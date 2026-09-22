"""清单解析、依赖图构建、最短路径与冲突分析。

支持的清单格式（单制品）::

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

多制品清单可提供可选的 ``distributions`` 数组，每项包含唯一名称、
该制品的项目许可证与该制品的直接依赖（根）::

    {
      "project": {"name": "my-product"},
      "distributions": [
        {"name": "cli", "project_license": "MIT", "direct_dependencies": ["入口"]},
        {"name": "saas", "project_license": "AGPL-3.0", "direct_dependencies": ["服务"]}
      ],
      "packages": [ ... ]
    }

说明：

* 依赖引用写作 ``name`` 或 ``name@version``；带版本时优先精确匹配，
  否则按名字匹配同名包；引用不存在的包会记入 ``unresolved_refs``，不中断分析。
* 单制品模式下未声明 ``direct_dependencies`` 时，入度为 0 的包视为根（直接依赖）。
* 多制品模式下所有制品共享**同一张依赖图**，但分别从各自的根做 BFS：
  每个制品只统计自己可达的包，并按自己的项目许可证判定；公共包在不同
  制品下保留独立的最短路径、结论与触发规则。制品根引用了不存在的包时
  记为"悬空根"并定位到具体制品（``dangling_roots``）。
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

#: 多制品模式 / 单制品模式
MODE_SINGLE = "single"
MODE_MULTI = "multi"

#: 前端总览视图使用的虚拟作用域名
OVERVIEW_SCOPE = "__overview__"


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
class Distribution:
    """一个制品（分发物）：自带项目许可证与依赖根。"""

    name: str
    project_license: str
    direct_deps: List[str] = field(default_factory=list)  # 原始引用
    roots: List[str] = field(default_factory=list)  # 解析后的包 key
    dangling_roots: List[str] = field(default_factory=list)  # 未能解析的根引用


@dataclass
class Graph:
    project: dict
    project_license: str
    packages: Dict[str, Pkg]  # key -> Pkg（保留插入顺序）
    edges: Dict[str, List[str]]  # from key -> [to key]
    roots: List[str]
    unresolved_refs: List[str]
    mode: str = MODE_SINGLE
    distributions: List[Distribution] = field(default_factory=list)


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


def _parse_distributions(raw) -> List[dict]:
    """校验 distributions 的结构（不做许可证规范化，那一步在 build_graph）。"""
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw:
        raise ManifestError("distributions 必须是非空数组")
    parsed: List[dict] = []
    seen_names: Set[str] = set()
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ManifestError(f"distributions[{idx}] 必须是对象")
        name = _coerce_str(item.get("name"), f"distributions[{idx}].name")
        if not name:
            raise ManifestError(f"distributions[{idx}] 缺少 name")
        if name in seen_names:
            raise ManifestError(f"distributions 中制品名 {name!r} 重复，名称必须唯一")
        seen_names.add(name)

        license_raw = item.get("project_license")
        if not isinstance(license_raw, str) or not license_raw.strip():
            raise ManifestError(
                f"制品 {name!r} 缺少 project_license（每个制品需声明各自的项目许可证）"
            )

        deps_raw = item.get("direct_dependencies")
        if not isinstance(deps_raw, list):
            raise ManifestError(
                f"制品 {name!r} 的 direct_dependencies 必须是字符串数组"
            )
        deps = [
            _coerce_str(d, f"distributions[{idx}].direct_dependencies[]")
            for d in deps_raw
            if _coerce_str(d, "")
        ]
        parsed.append({"name": name, "project_license": license_raw.strip(),
                       "direct_dependencies": deps})
    return parsed


def parse_manifest(
    data: dict,
) -> Tuple[List[Pkg], dict, Optional[str], Optional[List[str]], List[dict]]:
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

    distributions_raw = data.get("distributions")
    distributions = _parse_distributions(distributions_raw)
    if distributions and direct_deps is not None:
        raise ManifestError(
            "多制品清单（含 distributions）不能再使用顶层 direct_dependencies，"
            "请在每个制品内声明 direct_dependencies"
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

    return list(packages.values()), project, project_license, direct_deps, distributions


def _split_ref(ref: str) -> Tuple[str, str]:
    ref = ref.strip()
    if "@" in ref:
        name, version = ref.rsplit("@", 1)
        return name, version
    return ref, ""


def build_graph(data: dict, policy: pol.Policy, license_override: Optional[str] = None) -> Graph:
    pkgs, project, project_license, direct_deps, dist_raw = parse_manifest(data)
    index: Dict[str, Pkg] = {p.key: p for p in pkgs}
    by_name: Dict[str, List[str]] = {}
    for p in pkgs:
        by_name.setdefault(p.name, []).append(p.key)

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

    def add_unresolved(ref: str, bucket: List[str]) -> None:
        if ref not in bucket and ref not in unresolved:
            bucket.append(ref)

    # 包之间的依赖边（全局共享）
    for p in pkgs:
        for ref in p.deps:
            target = resolve(ref)
            if target is None:
                add_unresolved(ref, unresolved)
                continue
            if target not in edges[p.key]:
                edges[p.key].append(target)

    # ------------------------------------------------------------------ #
    # 多制品模式：每个制品有独立的项目许可证与根集合
    # ------------------------------------------------------------------ #
    if dist_raw:
        distributions: List[Distribution] = []
        for d in dist_raw:
            name = d["name"]
            chosen = lic.canonicalize(d["project_license"])
            if chosen == "NOASSERTION":
                raise ManifestError(
                    f"制品 {name!r} 的项目许可证 {d['project_license']!r} "
                    "无法识别为已知 SPDX 标识"
                )
            if chosen not in lic.KNOWN_LICENSES:
                raise ManifestError(f"制品 {name!r} 的项目许可证 {chosen!r} 不在内置矩阵中")
            if chosen not in policy.allowed_project_licenses:
                allowed = ", ".join(policy.allowed_project_licenses)
                raise ManifestError(
                    f"制品 {name!r} 的项目许可证 {chosen} 与策略「{policy.name}」不匹配，"
                    f"该策略允许的项目许可证：{allowed}"
                )

            dist = Distribution(name=name, project_license=chosen,
                                direct_deps=list(d["direct_dependencies"]))
            for ref in d["direct_dependencies"]:
                target = resolve(ref)
                if target is None:
                    dist.dangling_roots.append(ref)
                    # 悬空根同样是无法解析的引用，计入全局清单
                    if ref not in unresolved:
                        unresolved.append(ref)
                    continue
                if target not in dist.roots:
                    dist.roots.append(target)
            distributions.append(dist)

        return Graph(
            project=project,
            # 顶层许可证仅作元数据；缺省取第一个制品的许可证
            project_license=project_license or distributions[0].project_license,
            packages=index,
            edges=edges,
            roots=[],
            unresolved_refs=unresolved,
            mode=MODE_MULTI,
            distributions=distributions,
        )

    # ------------------------------------------------------------------ #
    # 单制品模式（历史行为）
    # ------------------------------------------------------------------ #
    chosen_license = license_override or project_license or policy.default_project_license
    if chosen_license not in lic.KNOWN_LICENSES:
        raise ManifestError(f"项目许可证 {chosen_license!r} 不在内置矩阵中")
    if chosen_license not in policy.allowed_project_licenses:
        allowed = ", ".join(policy.allowed_project_licenses)
        raise ManifestError(
            f"项目许可证 {chosen_license} 与策略「{policy.name}」不匹配，"
            f"该策略允许的项目许可证：{allowed}"
        )

    roots: List[str] = []
    if direct_deps is not None:
        for ref in direct_deps:
            target = resolve(ref)
            if target is None:
                add_unresolved(ref, unresolved)
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
        mode=MODE_SINGLE,
    )


# ---------------------------------------------------------------------------
# 最短路径（多源 BFS，记录前驱）
# ---------------------------------------------------------------------------


def shortest_paths(
    graph: Graph, roots: Optional[List[str]] = None
) -> Dict[str, Optional[List[str]]]:
    """返回每个包从给定根集合出发的最短路径（含首尾）。不可达为 None。"""
    if roots is None:
        roots = graph.roots
    prev: Dict[str, Optional[str]] = {}
    dist: Dict[str, int] = {}
    queue: deque[str] = deque()
    for root in roots:
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

#: 有效结论的严重度排序（数字越小越严重），用于排序与总览聚合
#: 注意总览聚合时"例外"视为已平息的问题，比原生 allow 更轻：
#: 只要某包在任一制品下仍 deny/review，总览就按最严重的未处理冲突聚合；
#: 所有制品均已兼容或已例外时，未例外的 allow 优先于 exception。
VERDICT_ORDER = {"deny": 0, "review": 1, "allow": 2, "exception": 3}


def _is_compound(raw: str) -> bool:
    upper = (raw or "").upper()
    return " OR " in upper or " AND " in upper or "(" in upper or ")" in upper


def _empty_summary() -> dict:
    return {"total": 0, "allow": 0, "deny": 0, "review": 0,
            "exceptions": 0, "conflicts": 0}


def _license_parts(pkg: Pkg, judgement: dict) -> Tuple[str, List[str], str]:
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
    return canonical, members, family


def _exception_applies(exc: Optional[dict], judgement: dict, rule_scoped: bool) -> bool:
    if not exc or judgement["verdict"] not in (pol.DENY, pol.REVIEW):
        return False
    # 多制品模式：例外只覆盖同 package_id 且触发规则相同的制品结论
    if rule_scoped and exc.get("rule") != judgement["rule"]:
        return False
    return True


def _analyze_scope(
    graph: Graph,
    policy: pol.Policy,
    scope_name: Optional[str],
    scope_license: str,
    roots: List[str],
    exceptions: Dict[str, dict],
    *,
    rule_scoped: bool,
    include_unreachable: bool,
) -> dict:
    """在一张共享图上，以一组根、一个项目许可证执行一次完整判定。

    * 多制品模式 ``include_unreachable=False``：只输出该制品可达的包；
    * 单制品模式 ``include_unreachable=True``：不可达包也保留（历史行为）。
    """
    paths = shortest_paths(graph, roots)
    root_set = set(roots)
    package_results: List[dict] = []
    summary = _empty_summary()

    for key, pkg in graph.packages.items():
        path = paths[key]
        if path is None and not include_unreachable:
            continue
        depth = (len(path) - 1) if path else None
        is_direct = key in root_set or depth == 0

        judgement = pol.judge(scope_license, pkg.license_raw, policy)
        canonical, members, family = _license_parts(pkg, judgement)

        exc = exceptions.get(key)
        effective_verdict = judgement["verdict"]
        exception_info = None
        if _exception_applies(exc, judgement, rule_scoped):
            exception_info = {
                "approved": True,
                "note": exc.get("note", ""),
                "approved_at": exc.get("approved_at", ""),
                "original_verdict": judgement["verdict"],
                "rule": exc.get("rule"),
            }
            effective_verdict = "exception"

        summary["total"] += 1
        if effective_verdict == "exception":
            summary["exceptions"] += 1
        else:
            summary[effective_verdict] = summary.get(effective_verdict, 0) + 1
        if judgement["verdict"] in (pol.DENY, pol.REVIEW) and not exception_info:
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
                "distribution": scope_name,
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
    package_results.sort(
        key=lambda p: (
            VERDICT_ORDER.get(p["verdict"], 9),
            p["depth"] if p["depth"] is not None else 999,
            p["id"],
        )
    )
    conflicts = [p for p in package_results if p["verdict"] in ("deny", "review")]
    return {
        "name": scope_name,
        "project_license": scope_license,
        "roots": list(roots),
        "summary": summary,
        "packages": package_results,
        "conflicts": conflicts,
    }


def _build_overview(graph: Graph, scopes: List[dict]) -> dict:
    """跨制品总览：每个包按最严重结论聚合，并列出受影响制品。"""
    entries: Dict[str, List[Tuple[int, dict]]] = {}
    for idx, scope in enumerate(scopes):
        for p in scope["packages"]:
            entries.setdefault(p["id"], []).append((idx, p))

    rows: List[dict] = []
    summary = _empty_summary()
    summary["unreachable"] = 0
    for key, pkg in graph.packages.items():
        hits = entries.get(key)
        if not hits:
            continue  # 不可达包单独统计
        # 最严重有效结论；同级时取制品顺序靠前者，保证结果稳定
        worst_idx, worst = min(
            hits, key=lambda h: (VERDICT_ORDER.get(h[1]["verdict"], 9), h[0])
        )
        affected = [
            {
                "distribution": p["distribution"],
                "verdict": p["verdict"],
                "base_verdict": p["base_verdict"],
                "rule": p["rule"],
                "rule_kind": p["rule_kind"],
                "message": p["message"],
                "direct": p["direct"],
                "depth": p["depth"],
                "shortest_path": p["shortest_path"],
                "exception": p["exception"],
            }
            for _i, p in hits
        ]
        row = {
            "id": key,
            "name": pkg.name,
            "version": pkg.version,
            "license_raw": pkg.license_raw,
            "license": worst["license"],
            "license_members": worst["license_members"],
            "family": worst["family"],
            "verdict": worst["verdict"],
            "base_verdict": worst["base_verdict"],
            "severity": worst["severity"],
            "rule": worst["rule"],
            "rule_kind": worst["rule_kind"],
            "message": worst["message"],
            "reachable": True,
            "affected_count": len(hits),
            "affected": affected,
        }
        rows.append(row)
        summary["total"] += 1
        if worst["verdict"] == "exception":
            summary["exceptions"] += 1
        else:
            summary[worst["verdict"]] = summary.get(worst["verdict"], 0) + 1
        if worst["verdict"] in ("deny", "review"):
            summary["conflicts"] += 1

    rows.sort(key=lambda p: (VERDICT_ORDER.get(p["verdict"], 9), p["id"]))

    reached = set(entries)
    unreachable = [
        {
            "id": key,
            "name": pkg.name,
            "version": pkg.version,
            "license_raw": pkg.license_raw,
            "license": (
                lic.canonicalize(pkg.license_raw)
                if not _is_compound(pkg.license_raw)
                else "NOASSERTION"
            ),
            "family": (
                lic.LICENSE_FAMILY.get(lic.canonicalize(pkg.license_raw), lic.UNKNOWN)
                if not _is_compound(pkg.license_raw)
                else "expression"
            ),
        }
        for key, pkg in graph.packages.items()
        if key not in reached
    ]
    summary["unreachable"] = len(unreachable)

    conflicts = [r for r in rows if r["verdict"] in ("deny", "review")]
    return {"summary": summary, "packages": rows, "conflicts": conflicts,
            "unreachable_packages": unreachable}


def analyze(
    data: dict,
    policy: pol.Policy,
    license_override: Optional[str] = None,
    exceptions: Optional[Dict[str, dict]] = None,
) -> dict:
    """执行完整分析，返回可序列化的结果字典。

    ``exceptions``: ``{package_key: {"note": str, "approved_at": iso8601,
    "rule": 触发规则或 None}}``。单制品清单行为与历史一致（例外不区分规则）；
    多制品清单按每个制品的根分别遍历，例外仅覆盖同包同规则的制品结论。
    """
    graph = build_graph(data, policy, license_override)
    cycles = detect_cycles(graph)
    exceptions = exceptions or {}

    if graph.mode == MODE_MULTI:
        # 多制品模式：license_override 不适用（每个制品自带许可证）
        scopes = [
            _analyze_scope(
                graph, policy, d.name, d.project_license, d.roots, exceptions,
                rule_scoped=True, include_unreachable=False,
            )
            for d in graph.distributions
        ]
        for scope, d in zip(scopes, graph.distributions):
            scope["dangling_roots"] = list(d.dangling_roots)
        overview = _build_overview(graph, scopes)
        return {
            "project": {
                "name": graph.project.get("name", "未命名项目"),
                "version": graph.project.get("version", ""),
            },
            "project_license": graph.project_license,
            "mode": MODE_MULTI,
            "policy_key": policy.key,
            "policy": policy.to_dict(),
            "summary": overview["summary"],
            "distributions": scopes,
            "overview": overview,
            "edges": [
                {"from": src, "to": dst}
                for src, targets in graph.edges.items()
                for dst in targets
            ],
            "cycles": cycles,
            "unresolved_refs": graph.unresolved_refs,
            "dangling_roots": [
                {"distribution": d.name, "ref": ref}
                for d in graph.distributions
                for ref in d.dangling_roots
            ],
        }

    # 单制品模式（历史行为保持不变）
    scope = _analyze_scope(
        graph, policy, None, graph.project_license, graph.roots, exceptions,
        rule_scoped=False, include_unreachable=True,
    )
    return {
        "project": {
            "name": graph.project.get("name", "未命名项目"),
            "version": graph.project.get("version", ""),
        },
        "project_license": graph.project_license,
        "mode": MODE_SINGLE,
        "policy_key": policy.key,
        "policy": policy.to_dict(),
        "summary": scope["summary"],
        "packages": scope["packages"],
        "conflicts": scope["conflicts"],
        "edges": [
            {"from": src, "to": dst}
            for src, targets in graph.edges.items()
            for dst in targets
        ],
        "roots": graph.roots,
        "cycles": cycles,
        "unresolved_refs": graph.unresolved_refs,
    }
