"""清单解析、依赖图构建、最短路径与冲突分析。

支持的清单格式::

    {
      "project": {"name": "my-app", "version": "1.0.0"},
      "project_license": "MIT",                 // 可选，覆盖策略默认值
      "direct_dependencies": ["web框架"],        // 可选：显式直接依赖（name 或 name@version）
      "packages": [
        {
          "name": "web框架",
          "version": "2.0.0",
          "license": "MIT",
          "dependencies": ["工具@1.0", "解析器"]
        }
      ]
    }

说明：

* 依赖引用写作 ``name`` 或 ``name@version``；带版本时优先精确匹配，
  否则按名字匹配同名包；引用不存在的包会记入 ``unresolved_refs``，不中断分析。
* 未声明 ``direct_dependencies`` 时，入度为 0 的包视为根（直接依赖）。
* BFS 计算每个包到任意根的最短依赖路径；循环依赖不会导致死循环，
  不可达包会被标记（常见于孤立环）。
* 一个包多条许可证时可用 SPDX 表达式（``A OR B``、``(A AND B)``）描述。
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import licenses as lic
from . import policies as pol


class ManifestError(ValueError):
    """清单结构不合法。"""


@dataclass
class Pkg:
    name: str
    version: str
    license_raw: str
    deps: List[str] = field(default_factory=list)  # 原始引用字符串

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Graph:
    project: dict
    project_license: str
    packages: Dict[str, Pkg]  # key -> Pkg（保留插入顺序）
    edges: Dict[str, List[str]]  # from key -> [to key]
    roots: List[str]
    unresolved_refs: List[str]


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------


def _coerce_str(value, field_name: str) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    raise ManifestError(f"字段 {field_name} 必须是字符串，实际为 {type(value).__name__}")


def parse_manifest(data: dict) -> Tuple[List[Pkg], dict, Optional[str], Optional[List[str]]]:
    if not isinstance(data, dict):
        raise ManifestError("清单必须是 JSON 对象")
    raw_packages = data.get("packages")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise ManifestError("清单缺少非空的 packages 数组")

    project = data.get("project") or {}
    if not isinstance(project, dict):
        raise ManifestError("project 字段必须是对象")

    project_license_raw = data.get("project_license")
    project_license = (
        lic.canonicalize(project_license_raw)
        if isinstance(project_license_raw, str) and project_license_raw.strip()
        else None
    )
    if project_license == "NOASSERTION":
        raise ManifestError(
            f"项目许可证 {project_license_raw!r} 无法识别为已知 SPDX 标识"
        )

    direct_raw = data.get("direct_dependencies") or data.get("root_dependencies")
    if direct_raw is not None and not isinstance(direct_raw, list):
        raise ManifestError("direct_dependencies 必须是字符串数组")
    direct_deps = (
        [_coerce_str(r, "direct_dependencies[]") for r in direct_raw]
        if direct_raw is not None
        else None
    )

    packages: Dict[str, Pkg] = {}
    for idx, item in enumerate(raw_packages):
        if not isinstance(item, dict):
            raise ManifestError(f"packages[{idx}] 必须是对象")
        name = _coerce_str(item.get("name"), f"packages[{idx}].name")
        if not name:
            raise ManifestError(f"packages[{idx}] 缺少 name")
        version = _coerce_str(item.get("version"), f"packages[{idx}].version") or "0.0.0"
        license_raw = _coerce_str(item.get("license"), f"packages[{idx}].license")
        raw_deps = item.get("dependencies") or []
        if not isinstance(raw_deps, list):
            raise ManifestError(f"packages[{idx}].dependencies 必须是数组")
        deps = [_coerce_str(d, f"packages[{idx}].dependencies[]") for d in raw_deps if _coerce_str(d, "")]

        key = f"{name}@{version}"
        if key in packages:
            # 重复包：合并依赖边
            for d in deps:
                if d not in packages[key].deps:
                    packages[key].deps.append(d)
            if not packages[key].license_raw and license_raw:
                packages[key].license_raw = license_raw
        else:
            packages[key] = Pkg(name=name, version=version, license_raw=license_raw, deps=deps)

    return list(packages.values()), project, project_license, direct_deps


def _split_ref(ref: str) -> Tuple[str, str]:
    ref = ref.strip()
    if "@" in ref:
        name, version = ref.rsplit("@", 1)
        return name, version
    return ref, ""


def build_graph(data: dict, policy: pol.Policy, license_override: Optional[str] = None) -> Graph:
    pkgs, project, project_license, direct_deps = parse_manifest(data)
    index: Dict[str, Pkg] = {p.key: p for p in pkgs}
    by_name: Dict[str, List[str]] = {}
    for p in pkgs:
        by_name.setdefault(p.name, []).append(p.key)

    chosen_license = license_override or project_license or policy.default_project_license
    if chosen_license not in lic.KNOWN_LICENSES:
        raise ManifestError(f"项目许可证 {chosen_license!r} 不在内置矩阵中")
    if chosen_license not in policy.allowed_project_licenses:
        allowed = ", ".join(policy.allowed_project_licenses)
        raise ManifestError(
            f"项目许可证 {chosen_license} 与策略「{policy.name}」不匹配，"
            f"该策略允许的项目许可证：{allowed}"
        )

    edges: Dict[str, List[str]] = {p.key: [] for p in pkgs}
    unresolved: List[str] = []

    def resolve(ref: str) -> Optional[str]:
        name, version = _split_ref(ref)
        if version:
            exact = f"{name}@{version}"
            if exact in index:
                return exact
        candidates = by_name.get(name, [])
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            # 多版本且引用未指定/未命中：无法确定，作为未解析引用
            return None
        return None

    for p in pkgs:
        for ref in p.deps:
            target = resolve(ref)
            if target is None:
                if ref not in unresolved:
                    unresolved.append(ref)
                continue
            if target not in edges[p.key]:
                edges[p.key].append(target)

    # 根：显式声明 > 入度为 0
    roots: List[str] = []
    if direct_deps is not None:
        for ref in direct_deps:
            target = resolve(ref)
            if target is None:
                if ref not in unresolved:
                    unresolved.append(ref)
                continue
            if target not in roots:
                roots.append(target)
    else:
        depended: Set[str] = set()
        for targets in edges.values():
            depended.update(targets)
        roots = [p.key for p in pkgs if p.key not in depended]

    return Graph(
        project=project,
        project_license=chosen_license,
        packages=index,
        edges=edges,
        roots=roots,
        unresolved_refs=unresolved,
    )


# ---------------------------------------------------------------------------
# 最短路径（多源 BFS，记录前驱）
# ---------------------------------------------------------------------------


def shortest_paths(graph: Graph) -> Dict[str, Optional[List[str]]]:
    """返回每个包从任意根出发的最短路径（含首尾）。不可达为 None。"""
    prev: Dict[str, Optional[str]] = {}
    dist: Dict[str, int] = {}
    queue: deque[str] = deque()
    for root in graph.roots:
        if root in graph.packages and root not in dist:
            dist[root] = 0
            prev[root] = None
            queue.append(root)

    while queue:
        cur = queue.popleft()
        for nxt in graph.edges.get(cur, []):
            if nxt not in dist:
                dist[nxt] = dist[cur] + 1
                prev[nxt] = cur
                queue.append(nxt)

    paths: Dict[str, Optional[List[str]]] = {}
    for key in graph.packages:
        if key not in dist:
            paths[key] = None
            continue
        path: List[str] = []
        node: Optional[str] = key
        while node is not None:
            path.append(node)
            node = prev[node]
        path.reverse()
        paths[key] = path
    return paths


def detect_cycles(graph: Graph) -> List[List[str]]:
    """用 Tarjan 强连通分量找环（返回大小 >1 以及自环的分量）。"""
    index_counter = [0]
    stack: List[str] = []
    on_stack: Set[str] = set()
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    cycles: List[List[str]] = []

    def strongconnect(v: str) -> None:
        indices[v] = index_counter[0]
        lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in graph.edges.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            comp: List[str] = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1 or (len(comp) == 1 and comp[0] in graph.edges.get(comp[0], [])):
                cycles.append(list(reversed(comp)))

    for key in graph.packages:
        if key not in indices:
            strongconnect(key)
    return cycles


# ---------------------------------------------------------------------------
# 冲突分析
# ---------------------------------------------------------------------------


def _is_compound(raw: str) -> bool:
    upper = (raw or "").upper()
    return " OR " in upper or " AND " in upper or "(" in upper or ")" in upper


def analyze(
    data: dict,
    policy: pol.Policy,
    license_override: Optional[str] = None,
    exceptions: Optional[Dict[str, dict]] = None,
) -> dict:
    """执行完整分析，返回可序列化的结果字典。

    ``exceptions``: ``{package_key: {"note": str, "approved_at": iso8601}}``
    """
    graph = build_graph(data, policy, license_override)
    paths = shortest_paths(graph)
    cycles = detect_cycles(graph)
    exceptions = exceptions or {}

    root_set = set(graph.roots)
    package_results: List[dict] = []
    summary = {"total": 0, "allow": 0, "deny": 0, "review": 0, "exceptions": 0, "conflicts": 0}

    for key, pkg in graph.packages.items():
        path = paths[key]
        depth = (len(path) - 1) if path else None
        is_direct = key in root_set or depth == 0

        judgement = pol.judge(graph.project_license, pkg.license_raw, policy)

        if _is_compound(pkg.license_raw):
            canonical = judgement["trigger_license"]
            members = lic.expression_licenses(pkg.license_raw)
            family = "expression"
        else:
            canonical = lic.canonicalize(pkg.license_raw)
            members = [canonical]
            family = (
                lic.LICENSE_FAMILY.get(canonical, lic.UNKNOWN)
                if canonical != "NOASSERTION"
                else lic.UNKNOWN
            )

        exc = exceptions.get(key)
        effective_verdict = judgement["verdict"]
        exception_info = None
        if exc and judgement["verdict"] in (pol.DENY, pol.REVIEW):
            exception_info = {
                "approved": True,
                "note": exc.get("note", ""),
                "approved_at": exc.get("approved_at", ""),
                "original_verdict": judgement["verdict"],
            }
            effective_verdict = "exception"

        summary["total"] += 1
        if effective_verdict == "exception":
            summary["exceptions"] += 1
        else:
            summary[effective_verdict] = summary.get(effective_verdict, 0) + 1
        if judgement["verdict"] in (pol.DENY, pol.REVIEW) and not exc:
            summary["conflicts"] += 1

        package_results.append(
            {
                "id": key,
                "name": pkg.name,
                "version": pkg.version,
                "license_raw": pkg.license_raw,
                "license": canonical,
                "license_members": members,
                "family": family,
                "direct": is_direct,
                "depth": depth,
                "reachable": path is not None,
                "shortest_path": path or [],
                "dependencies": list(graph.edges.get(key, [])),
                "verdict": effective_verdict,  # allow / deny / review / exception
                "base_verdict": judgement["verdict"],
                "severity": judgement["severity"],
                "rule": judgement["rule"],
                "rule_kind": judgement["rule"].split(":", 1)[0],
                "message": judgement["message"],
                "exception": exception_info,
            }
        )

    # 排序：冲突在前（deny > review > 其他），其次按深度、名字
    order = {"deny": 0, "review": 1, "exception": 2, "allow": 3}
    package_results.sort(key=lambda p: (order.get(p["verdict"], 9), p["depth"] if p["depth"] is not None else 999, p["id"]))

    conflicts = [p for p in package_results if p["verdict"] in ("deny", "review")]

    return {
        "project": {
            "name": graph.project.get("name", "未命名项目"),
            "version": graph.project.get("version", ""),
        },
        "project_license": graph.project_license,
        "policy_key": policy.key,
        "policy": policy.to_dict(),
        "summary": summary,
        "packages": package_results,
        "conflicts": conflicts,
        "edges": [
            {"from": src, "to": dst}
            for src, targets in graph.edges.items()
            for dst in targets
        ],
        "roots": graph.roots,
        "cycles": cycles,
        "unresolved_refs": graph.unresolved_refs,
    }
