"""FastAPI 端到端测试（使用内存 SQLite）。"""
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 必须在导入 app.main 之前指向内存库
os.environ["LICENSEGATE_DB"] = ":memory:"

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

client = TestClient(main.app)

MANIFEST = {
    "project": {"name": "api-demo", "version": "1.0"},
    "direct_dependencies": ["app"],
    "packages": [
        {"name": "app", "version": "1", "license": "MIT",
         "dependencies": ["gpl-lib", "apache-lib"]},
        {"name": "gpl-lib", "version": "2", "license": "GPL-3.0", "dependencies": []},
        {"name": "apache-lib", "version": "3", "license": "Apache-2.0",
         "dependencies": []},
    ],
}


def upload(manifest=MANIFEST, policy="permissive", project_license=""):
    return client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(manifest).encode(), "application/json")},
        data={"policy_key": policy, "project_license": project_license},
    )


def test_health_and_meta():
    assert client.get("/api/health").json()["status"] == "ok"
    policies = client.get("/api/policies").json()
    assert {p["key"] for p in policies["policies"]} == {
        "permissive", "copyleft", "strict", "proprietary"
    }
    licenses = client.get("/api/licenses").json()
    assert licenses["matrix"]["MIT"]["GPL-3.0"] == "deny"
    assert licenses["matrix"]["MIT"]["MIT"] == "allow"


def test_index_served():
    res = client.get("/")
    assert res.status_code == 200
    assert "LicenseGate" in res.text


def test_upload_and_conflicts():
    res = upload()
    assert res.status_code == 200, res.text
    data = res.json()
    pid = data["project_id"]
    assert data["summary"]["deny"] == 1
    gpl = next(p for p in data["conflicts"] if p["name"] == "gpl-lib")
    assert gpl["verdict"] == "deny"
    assert gpl["shortest_path"] == ["app@1", "gpl-lib@2"]
    assert gpl["message"]
    assert gpl["rule"]
    assert pid


def test_upload_bad_json():
    res = client.post(
        "/api/projects",
        files={"file": ("m.json", b"{not json", "application/json")},
        data={"policy_key": "permissive"},
    )
    assert res.status_code == 400


def test_direct_analyze_endpoint():
    res = client.post("/api/analyze", json={"manifest": MANIFEST, "policy_key": "strict"})
    assert res.status_code == 200
    # strict 下 Apache-2.0 仍允许，GPL deny
    verdicts = {p["id"]: p["verdict"] for p in res.json()["packages"]}
    assert verdicts["gpl-lib@2"] == "deny"
    assert verdicts["apache-lib@3"] == "allow"


def test_exception_workflow_and_recompute():
    pid = upload().json()["project_id"]

    # 确认例外
    res = client.post(
        f"/api/projects/{pid}/exceptions/gpl-lib@2",
        json={"note": "仅内部分发，法务批准"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["summary"]["conflicts"] == 0
    gpl = next(p for p in data["packages"] if p["id"] == "gpl-lib@2")
    assert gpl["verdict"] == "exception"
    assert gpl["exception"]["note"] == "仅内部分发，法务批准"
    assert gpl["exception"]["original_verdict"] == "deny"
    # 冲突列表里不再出现
    assert all(p["id"] != "gpl-lib@2" for p in data["conflicts"])

    # GET 结果持久化
    got = client.get(f"/api/projects/{pid}").json()
    assert next(p for p in got["packages"] if p["id"] == "gpl-lib@2")["verdict"] == "exception"

    # 撤销例外，冲突恢复
    res = client.delete(f"/api/projects/{pid}/exceptions/gpl-lib@2")
    assert res.status_code == 200
    assert res.json()["summary"]["conflicts"] == 1

    # 不存在的包
    res = client.post(f"/api/projects/{pid}/exceptions/nope@9", json={"note": "x"})
    assert res.status_code == 404


def test_reanalyze_with_policy_switch():
    pid = upload().json()["project_id"]
    # 切换到 copyleft + GPL-3.0 项目许可证：GPL-3.0 依赖兼容
    res = client.post(
        f"/api/projects/{pid}/reanalyze",
        json={"policy_key": "copyleft", "project_license": "GPL-3.0"},
    )
    assert res.status_code == 200
    verdicts = {p["id"]: p["verdict"] for p in res.json()["packages"]}
    assert verdicts["gpl-lib@2"] == "allow"


def test_policy_license_mismatch_rejected():
    # permissive 策略只允许 MIT/Apache 作为项目许可证
    res = upload(project_license="GPL-3.0")
    assert res.status_code == 400


def test_export_payload():
    pid = upload().json()["project_id"]
    client.post(f"/api/projects/{pid}/exceptions/gpl-lib@2", json={"note": "ok"})
    res = client.get(f"/api/projects/{pid}/export")
    assert res.status_code == 200
    assert "attachment" in res.headers["content-disposition"]
    payload = res.json()
    assert payload["report_format"] == "licensegate-report/v1"
    assert payload["project"]["license"] == "MIT"
    assert len(payload["conflicts"]) == 0  # 唯一冲突已例外
    assert payload["exceptions"][0]["package_id"] == "gpl-lib@2"
    conflict_ex = next(p for p in payload["packages"] if p["id"] == "gpl-lib@2")
    assert conflict_ex["verdict"] == "exception"
    assert conflict_ex["shortest_path"] == ["app@1", "gpl-lib@2"]
    assert payload["manifest"]["packages"][0]["name"] == "app"


def test_project_crud():
    pid = upload().json()["project_id"]
    assert client.get("/api/projects").status_code == 200
    assert client.get(f"/api/projects/{pid}").status_code == 200
    assert client.get("/api/projects/99999").status_code == 404
    assert client.delete(f"/api/projects/{pid}").status_code == 200
    assert client.get(f"/api/projects/{pid}").status_code == 404


# ---------------------------------------------------------------------------
# 多制品（distributions）端到端
# ---------------------------------------------------------------------------


MULTI_MANIFEST = {
    "project": {"name": "multi-api", "version": "2.0"},
    "distributions": [
        {"name": "gpl3-cli", "project_license": "GPL-3.0",
         "direct_dependencies": ["cli-main"]},
        {"name": "gpl2-daemon", "project_license": "GPL-2.0",
         "direct_dependencies": ["server", "ghost-artifact@3"]},
    ],
    "packages": [
        {"name": "cli-main", "version": "1", "license": "GPL-3.0",
         "dependencies": ["shared"]},
        {"name": "server", "version": "1", "license": "GPL-2.0",
         "dependencies": ["shared"]},
        {"name": "shared", "version": "1", "license": "Apache-2.0",
         "dependencies": []},
    ],
}


def upload_multi(policy="copyleft"):
    return client.post(
        "/api/projects",
        files={"file": ("m.json", json.dumps(MULTI_MANIFEST).encode(), "application/json")},
        data={"policy_key": policy},
    )


def test_multi_upload_and_overview():
    res = upload_multi()
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["mode"] == "multi"
    assert [d["name"] for d in data["distributions"]] == ["gpl3-cli", "gpl2-daemon"]
    # 悬空根定位到具体制品
    assert data["dangling_roots"] == [
        {"distribution": "gpl2-daemon", "ref": "ghost-artifact@3"}]
    daemon = next(d for d in data["distributions"] if d["name"] == "gpl2-daemon")
    assert daemon["dangling_roots"] == ["ghost-artifact@3"]
    # 公共包在两个制品下结论不同
    cli = next(d for d in data["distributions"] if d["name"] == "gpl3-cli")
    assert next(p for p in cli["packages"] if p["id"] == "shared@1")["verdict"] == "allow"
    assert next(p for p in daemon["packages"] if p["id"] == "shared@1")["verdict"] == "deny"
    # 总览按最严重聚合
    shared = next(p for p in data["overview"]["packages"] if p["id"] == "shared@1")
    assert shared["verdict"] == "deny"
    assert {a["distribution"] for a in shared["affected"]} == {
        "gpl3-cli", "gpl2-daemon"}


def test_multi_exception_requires_distribution():
    pid = upload_multi().json()["project_id"]
    # 缺少 distribution
    r = client.post(f"/api/projects/{pid}/exceptions/shared@1", json={"note": "x"})
    assert r.status_code == 400
    # 未知制品
    r = client.post(f"/api/projects/{pid}/exceptions/shared@1",
                    json={"note": "x", "distribution": "nope"})
    assert r.status_code == 400
    # cli 下 shared 是 allow，不能确认例外
    r = client.post(f"/api/projects/{pid}/exceptions/shared@1",
                    json={"note": "x", "distribution": "gpl3-cli"})
    assert r.status_code == 400


def test_multi_exception_saved_with_rule_and_scoped():
    pid = upload_multi().json()["project_id"]
    r = client.post(
        f"/api/projects/{pid}/exceptions/shared@1",
        json={"note": "专利授权已确认", "distribution": "gpl2-daemon"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    daemon = next(d for d in data["distributions"] if d["name"] == "gpl2-daemon")
    cli = next(d for d in data["distributions"] if d["name"] == "gpl3-cli")
    sd = next(p for p in daemon["packages"] if p["id"] == "shared@1")
    sc = next(p for p in cli["packages"] if p["id"] == "shared@1")
    assert sd["verdict"] == "exception"
    assert sd["exception"]["rule"] == "MATRIX:GPL-2.0!Apache-2.0"
    # 只覆盖同规则制品结论：cli 规则不同，仍为 allow
    assert sc["verdict"] == "allow"
    assert data["summary"]["conflicts"] == 0

    # 持久化：rule 已入库
    row = main.db._mem_conn.execute(
        "SELECT rule, note FROM exceptions WHERE package_id = ?", ("shared@1",)
    ).fetchone()
    assert row["rule"] == "MATRIX:GPL-2.0!Apache-2.0"
    assert row["note"] == "专利授权已确认"

    # 撤销恢复冲突
    r = client.delete(f"/api/projects/{pid}/exceptions/shared@1")
    assert r.json()["summary"]["conflicts"] == 1


def test_multi_policy_switch_recomputes_per_distribution():
    pid = upload_multi().json()["project_id"]
    # 切回 copyleft 无异常；验证 project_license 覆盖被忽略不报错（多制品各带许可证）
    r = client.post(f"/api/projects/{pid}/reanalyze",
                    json={"policy_key": "copyleft", "project_license": "MIT"})
    assert r.status_code == 200
    assert r.json()["mode"] == "multi"


def test_multi_policy_license_mismatch_rejected():
    # strict 策略不允许 GPL-2.0/GPL-3.0 作为制品许可证
    res = upload_multi(policy="strict")
    assert res.status_code == 400
    # 错误定位到具体制品（按声明顺序先遇到 gpl3-cli）
    assert "gpl3-cli" in res.json()["detail"]


def test_multi_export_contains_distribution_details():
    pid = upload_multi().json()["project_id"]
    client.post(
        f"/api/projects/{pid}/exceptions/shared@1",
        json={"note": "ok", "distribution": "gpl2-daemon"},
    )
    payload = client.get(f"/api/projects/{pid}/export").json()
    assert payload["mode"] == "multi"
    assert payload["report_format"] == "licensegate-report/v1"
    assert {d["name"] for d in payload["distributions"]} == {
        "gpl3-cli", "gpl2-daemon"}
    daemon = next(d for d in payload["distributions"] if d["name"] == "gpl2-daemon")
    assert daemon["dangling_roots"] == ["ghost-artifact@3"]
    shared_d = next(p for p in daemon["packages"] if p["id"] == "shared@1")
    assert shared_d["verdict"] == "exception"
    assert shared_d["shortest_path"] == ["server@1", "shared@1"]
    ov = next(p for p in payload["overview"]["packages"] if p["id"] == "shared@1")
    assert len(ov["affected"]) == 2
    assert payload["exceptions"][0]["rule"] == "MATRIX:GPL-2.0!Apache-2.0"
    assert payload["dangling_roots"][0]["distribution"] == "gpl2-daemon"


def test_multi_direct_analyze_preview():
    r = client.post("/api/analyze",
                    json={"manifest": MULTI_MANIFEST, "policy_key": "copyleft"})
    assert r.status_code == 200
    data = r.json()
    assert data["mode"] == "multi"
    assert data["summary"]["deny"] == 1
