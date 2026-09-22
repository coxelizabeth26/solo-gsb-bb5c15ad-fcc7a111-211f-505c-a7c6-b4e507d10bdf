"""FastAPI 入口：上传清单、查看分析结果、确认例外、导出 JSON。"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, analyzer, licenses, policies
from .db import Database, now_iso

DB_PATH = os.environ.get("LICENSEGATE_DB", "/data/licensegate.db")
db = Database(DB_PATH)

app = FastAPI(
    title="LicenseGate",
    description="开源依赖许可审查：解析传递依赖图，按策略与兼容矩阵标出许可证冲突，"
    "给出最短依赖路径与触发规则，支持例外确认与 JSON 导出。",
    version=__version__,
)


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    manifest: dict = Field(..., description="依赖清单 JSON")
    policy_key: str = Field(default=policies.DEFAULT_POLICY)
    project_license: Optional[str] = Field(
        default=None, description="项目许可证，覆盖策略默认值/清单内 project_license"
    )


class ReanalyzeRequest(BaseModel):
    policy_key: Optional[str] = None
    project_license: Optional[str] = None


class ExceptionRequest(BaseModel):
    note: str = Field(default="", max_length=2000, description="例外理由 / 审批备注")
    distribution: Optional[str] = Field(
        default=None,
        description="多制品清单：在哪个制品下确认例外（用于定位触发规则）",
    )


# ---------------------------------------------------------------------------
# 核心辅助
# ---------------------------------------------------------------------------


def _resolve_policy(key: Optional[str]) -> policies.Policy:
    if key is None or key == "":
        return policies.get_policy(policies.DEFAULT_POLICY)
    if key not in policies.POLICIES:
        raise HTTPException(status_code=400, detail=f"未知策略: {key}")
    return policies.POLICIES[key]


def _analyze_project(project_id: int, policy: policies.Policy,
                     project_license: Optional[str]) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    exceptions = db.list_exceptions(project_id)
    try:
        result = analyzer.analyze(
            project["manifest"], policy, project_license, exceptions
        )
    except analyzer.ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["project_id"] = project_id
    result["stored_license"] = project["project_license"]
    return result


def _parse_manifest_bytes(raw: bytes, filename: str) -> dict:
    if not raw.strip():
        raise HTTPException(status_code=400, detail="上传文件为空")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=400, detail=f"文件 {filename} 不是合法 JSON：{exc}"
        ) from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="清单根节点必须是 JSON 对象")
    return data


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/policies")
def get_policies() -> dict:
    return {"policies": policies.list_policies(), "default": policies.DEFAULT_POLICY}


@app.get("/api/licenses")
def get_licenses() -> dict:
    """返回许可证家族、项目许可证选项与完整兼容矩阵，便于前端展示规则来源。"""
    matrix: dict[str, dict[str, str]] = {}
    for proj, row in licenses.MATRIX.items():
        matrix[proj] = {dep: verdict for dep, (verdict, _note) in row.items()}
    return {
        "known_licenses": sorted(licenses.KNOWN_LICENSES),
        "families": licenses.LICENSE_FAMILY,
        "project_license_options": licenses.PROJECT_LICENSE_OPTIONS,
        "matrix": matrix,
    }


@app.post("/api/analyze")
def analyze_direct(req: AnalyzeRequest) -> dict:
    """不落库的即时分析（前端上传后预览用）。"""
    policy = _resolve_policy(req.policy_key)
    override = req.project_license or None
    try:
        return analyzer.analyze(req.manifest, policy, override, {})
    except analyzer.ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/projects")
async def create_project(
    file: UploadFile = File(..., description="依赖清单 JSON 文件"),
    policy_key: str = Form(default=policies.DEFAULT_POLICY),
    project_license: str = Form(default=""),
) -> dict:
    policy = _resolve_policy(policy_key)
    raw = await file.read()
    manifest = _parse_manifest_bytes(raw, file.filename or "manifest.json")

    override = project_license.strip() or None
    try:
        preview = analyzer.analyze(manifest, policy, override, {})
    except analyzer.ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    chosen_license = preview["project_license"]
    project_id = db.create_project(
        name=preview["project"]["name"],
        project_version=preview["project"].get("version", ""),
        project_license=chosen_license,
        policy_key=policy.key,
        manifest=manifest,
    )
    # 多制品清单的许可证由各制品自带，不再传顶层 override
    effective_override = None if preview.get("mode") == analyzer.MODE_MULTI else chosen_license
    return _analyze_project(project_id, policy, effective_override)


@app.get("/api/projects")
def list_projects() -> dict:
    return {"projects": db.list_projects()}


@app.get("/api/projects/{project_id}")
def get_project(project_id: int, policy_key: Optional[str] = None,
                project_license: Optional[str] = None) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    policy = _resolve_policy(policy_key or project["policy_key"])
    return _analyze_project(project_id, policy, project_license or None)


@app.post("/api/projects/{project_id}/reanalyze")
def reanalyze(project_id: int, req: ReanalyzeRequest) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    policy = _resolve_policy(req.policy_key or project["policy_key"])
    license_choice = req.project_license or None
    return _analyze_project(project_id, policy, license_choice)


@app.post("/api/projects/{project_id}/exceptions/{package_id:path}")
def add_exception(project_id: int, package_id: str, req: ExceptionRequest) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    pkg_keys = {
        f"{p.get('name','')}@{p.get('version') or '0.0.0'}"
        for p in project["manifest"].get("packages", [])
        if isinstance(p, dict)
    }
    if package_id not in pkg_keys:
        raise HTTPException(status_code=404, detail=f"包 {package_id} 不在清单中")

    policy = _resolve_policy(project["policy_key"])

    # 先在当前策略下计算一次，定位"所选制品下该包"的触发规则
    try:
        preview = analyzer.analyze(
            project["manifest"], policy, None, db.list_exceptions(project_id)
        )
    except analyzer.ManifestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    rule: Optional[str] = None
    if preview.get("mode") == analyzer.MODE_MULTI:
        dist_name = (req.distribution or "").strip()
        if not dist_name:
            raise HTTPException(
                status_code=400,
                detail="多制品清单确认例外时必须指定 distribution（制品名称）",
            )
        scope = next(
            (d for d in preview["distributions"] if d["name"] == dist_name), None
        )
        if scope is None:
            names = ", ".join(d["name"] for d in preview["distributions"])
            raise HTTPException(
                status_code=400,
                detail=f"制品 {dist_name!r} 不存在，可选制品：{names}",
            )
        hit = next((p for p in scope["packages"] if p["id"] == package_id), None)
        if hit is None:
            raise HTTPException(
                status_code=400,
                detail=f"包 {package_id} 从制品「{dist_name}」的根不可达，"
                "无法在该制品下确认例外",
            )
        if hit["base_verdict"] not in ("deny", "review") or hit["exception"]:
            raise HTTPException(
                status_code=400,
                detail=f"包 {package_id} 在制品「{dist_name}」下结论为 "
                f"{hit['base_verdict']}，不存在需要例外的冲突",
            )
        rule = hit["rule"]

    db.add_exception(project_id, package_id, req.note.strip(), rule)
    return _analyze_project(project_id, policy, None)


@app.delete("/api/projects/{project_id}/exceptions/{package_id:path}")
def revoke_exception(project_id: int, package_id: str) -> dict:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    removed = db.remove_exception(project_id, package_id)
    if not removed:
        raise HTTPException(status_code=404, detail="该包没有已确认的例外")
    policy = _resolve_policy(project["policy_key"])
    return _analyze_project(project_id, policy, None)


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: int) -> dict:
    if not db.delete_project(project_id):
        raise HTTPException(status_code=404, detail="项目不存在")
    return {"deleted": project_id}


@app.get("/api/projects/{project_id}/export")
def export_project(project_id: int) -> JSONResponse:
    project = db.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="项目不存在")
    policy = _resolve_policy(project["policy_key"])
    result = _analyze_project(project_id, policy, None)

    export_payload = {
        "report_format": "licensegate-report/v1",
        "exported_at": now_iso(),
        "mode": result.get("mode", "single"),
        "project": {
            "id": project["id"],
            "name": project["name"],
            "version": project["project_version"],
            "license": project["project_license"],
        },
        "policy": {
            "key": policy.key,
            "name": policy.name,
        },
        "summary": result["summary"],
        "exceptions": [
            {
                "package_id": pid,
                "note": info["note"],
                "rule": info.get("rule"),
                "approved_at": info["approved_at"],
            }
            for pid, info in db.list_exceptions(project_id).items()
        ],
        "cycles": result["cycles"],
        "unresolved_refs": result["unresolved_refs"],
        "manifest": project["manifest"],
    }

    def pkg_entry(p: dict) -> dict:
        return {
            "id": p["id"],
            "name": p["name"],
            "version": p["version"],
            "license": p["license_raw"],
            "license_canonical": p["license"],
            "family": p["family"],
            "direct": p.get("direct"),
            "depth": p.get("depth"),
            "verdict": p["verdict"],
            "base_verdict": p["base_verdict"],
            "rule": p["rule"],
            "message": p["message"],
            "shortest_path": p.get("shortest_path", []),
            "exception": p.get("exception"),
        }

    def conflict_entry(c: dict) -> dict:
        return {
            "package": c["id"],
            "license": c["license_raw"],
            "severity": c["severity"],
            "rule": c["rule"],
            "message": c["message"],
            "shortest_path": c["shortest_path"],
        }

    if result.get("mode") == analyzer.MODE_MULTI:
        # 分制品明细：每个制品保留各自可达包的独立路径 / 结论 / 触发规则
        export_payload["distributions"] = [
            {
                "name": d["name"],
                "project_license": d["project_license"],
                "roots": d["roots"],
                "dangling_roots": d.get("dangling_roots", []),
                "summary": d["summary"],
                "packages": [pkg_entry(p) for p in d["packages"]],
                "conflicts": [conflict_entry(c) for c in d["conflicts"]],
            }
            for d in result["distributions"]
        ]
        # 总览：按最严重结论聚合，列出受影响制品
        export_payload["overview"] = {
            "summary": result["overview"]["summary"],
            "packages": [
                {
                    **pkg_entry(p),
                    "affected_count": p["affected_count"],
                    "affected": p["affected"],
                }
                for p in result["overview"]["packages"]
            ],
            "conflicts": [
                {
                    "package": c["id"],
                    "license": c["license_raw"],
                    "severity": c["severity"],
                    "rule": c["rule"],
                    "verdict": c["verdict"],
                    "message": c["message"],
                    "affected": c["affected"],
                }
                for c in result["overview"]["conflicts"]
            ],
            "unreachable_packages": result["overview"]["unreachable_packages"],
        }
        export_payload["dangling_roots"] = result["dangling_roots"]
    else:
        export_payload["packages"] = [pkg_entry(p) for p in result["packages"]]
        export_payload["conflicts"] = [
            conflict_entry(c) for c in result["conflicts"]
        ]

    filename = f"license-report-{project_id}.json"
    return JSONResponse(
        content=export_payload,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


# ---------------------------------------------------------------------------
# 前端静态页（必须放在 API 路由之后挂载）
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
