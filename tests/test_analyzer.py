"""分析引擎单元测试（不依赖网络/框架）。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyzer, licenses, policies  # noqa: E402


def test_canonicalize_aliases():
    assert licenses.canonicalize("apache2") == "Apache-2.0"
    assert licenses.canonicalize("GPLv3") == "NOASSERTION"
    assert licenses.canonicalize("mit") == "MIT"
    assert licenses.canonicalize("") == "NOASSERTION"
    assert licenses.canonicalize(None) == "NOASSERTION"


def test_matrix_basic_compatibility():
    assert licenses.compatibility("MIT", "MIT") == "allow"
    assert licenses.compatibility("MIT", "GPL-3.0") == "deny"
    assert licenses.compatibility("Apache-2.0", "GPL-2.0") == "deny"
    assert licenses.compatibility("Apache-2.0", "GPL-3.0") == "allow"
    assert licenses.compatibility("GPL-3.0", "Apache-2.0") == "allow"
    assert licenses.compatibility("Proprietary", "AGPL-3.0") == "deny"
    assert licenses.compatibility("Proprietary", "MPL-2.0") == "review"
    assert licenses.compatibility("MIT", "Proprietary") == "review"


def test_spdx_expression_or_takes_best():
    verdict, hit, members = licenses.evaluate_expression("MIT OR GPL-3.0", "MIT")
    assert verdict == "allow"
    assert hit == "MIT"
    assert set(members) == {"MIT", "GPL-3.0"}


def test_spdx_expression_and_takes_worst():
    verdict, hit, _ = licenses.evaluate_expression("MIT AND GPL-3.0", "MIT")
    assert verdict == "deny"
    assert hit == "GPL-3.0"


def test_spdx_expression_nested_and_with():
    verdict, hit, _ = licenses.evaluate_expression(
        "Apache-2.0 AND (MIT OR BSD-3-Clause)", "Apache-2.0"
    )
    assert verdict == "allow"


def test_or_expression_with_copyleft_branch_selectable_permissive():
    # OR 表示被许可方可择一：MIT OR GPL-3.0 选 MIT，策略不应被 GPL 分支误伤
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "MIT OR GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    dual = next(p for p in res["packages"] if p["id"] == "dual@1")
    assert dual["verdict"] == "allow"
    assert dual["license_members"] == ["MIT", "GPL-3.0"]


def test_or_expression_no_compatible_branch_denied():
    # 两个分支都不兼容时仍判冲突
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "GPL-2.0 OR AGPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    dual = next(p for p in res["packages"] if p["id"] == "dual@1")
    assert dual["verdict"] == "deny"


def test_and_expression_with_copyleft_branch_strict():
    # AND 条款同时适用，含 GPL 分支即按 GPL 处理
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["dual"]},
            {"name": "dual", "version": "1", "license": "MIT AND GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["strict"])
    dual = next(p for p in res["packages"] if p["id"] == "dual@1")
    assert dual["verdict"] == "deny"
    assert dual["rule_kind"] == "POLICY_DENY"


def test_policy_deny_overrides_matrix_allow():
    # GPL-3.0 项目 + Apache-2.0 矩阵 allow，但专有策略下改选项目许可证？
    # 这里直接验证：严格白名单策略把 MPL 判 deny（矩阵 MIT+MPL 是 allow）
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["m"]},
            {"name": "m", "version": "1", "license": "MPL-2.0", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["strict"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["m@1"]["verdict"] == "deny"
    assert pkgs["m@1"]["rule_kind"] == "POLICY_DENY"


def test_policy_allow_family_overrides_review():
    # 宽松策略：MIT + LGPL 矩阵 review，allow_families 含 weak_copyleft → allow
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["l"]},
            {"name": "l", "version": "1", "license": "LGPL-2.1", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["l@1"]["verdict"] == "allow"
    assert pkgs["l@1"]["rule_kind"] == "POLICY_ALLOW"


def test_strict_unknown_denied():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["x"]},
            {"name": "x", "version": "1", "license": "Custom-Weird", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["strict"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["x@1"]["verdict"] == "deny"


def test_permissive_unknown_review():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["x"]},
            {"name": "x", "version": "1", "license": "Custom-Weird", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    pkgs = {p["id"]: p for p in res["packages"]}
    assert pkgs["x@1"]["verdict"] == "review"
    assert pkgs["x@1"]["severity"] == "warning"


def test_shortest_path_transitive_conflict():
    data = {
        "project": {"name": "demo"},
        "packages": [
            {"name": "root", "version": "1", "license": "MIT",
             "dependencies": ["a", "b"]},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["gpl-deep"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "gpl-deep", "version": "9", "license": "GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    gpl = next(p for p in res["packages"] if p["name"] == "gpl-deep")
    assert gpl["verdict"] == "deny"
    assert gpl["shortest_path"] == ["root@1", "a@1", "gpl-deep@9"]
    assert gpl["depth"] == 2
    assert gpl["direct"] is False
    assert "GPL-3.0" in gpl["message"]
    # root/b/a 兼容
    allowed = {p["id"]: p["verdict"] for p in res["packages"]}
    assert allowed["root@1"] == "allow"


def test_explicit_direct_dependencies_and_version_resolution():
    data = {
        "direct_dependencies": ["app"],
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["lib@2.0.0"]},
            {"name": "lib", "version": "1.0.0", "license": "MIT", "dependencies": []},
            {"name": "lib", "version": "2.0.0", "license": "GPL-3.0",
             "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert res["roots"] == ["app@1"]
    gpl = next(p for p in res["packages"] if p["id"] == "lib@2.0.0")
    assert gpl["shortest_path"] == ["app@1", "lib@2.0.0"]


def test_unresolved_ref_recorded():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["ghost@9.9.9"]},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert "ghost@9.9.9" in res["unresolved_refs"]


def test_cycle_does_not_hang():
    data = {
        "direct_dependencies": ["a"],
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["b"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["a"]},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert len(res["cycles"]) == 1
    assert set(res["cycles"][0]) == {"a@1", "b@1"}
    # 二者均可达（a 是根），路径长度有限
    for p in res["packages"]:
        assert p["shortest_path"]


def test_isolated_cycle_unreachable():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "x", "version": "1", "license": "MIT", "dependencies": ["y"]},
            {"name": "y", "version": "1", "license": "MIT", "dependencies": ["x"]},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    assert res["roots"] == ["app@1"]
    unreachable = [p for p in res["packages"] if not p["reachable"]]
    assert {p["id"] for p in unreachable} == {"x@1", "y@1"}


def test_exception_removes_conflict_and_recompute():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["g"]},
            {"name": "g", "version": "1", "license": "GPL-3.0", "dependencies": []},
        ]
    }
    policy = policies.POLICIES["permissive"]
    before = analyzer.analyze(data, policy)
    assert before["summary"]["conflicts"] == 1

    after = analyzer.analyze(
        data, policy, exceptions={"g@1": {"note": "法务已批", "approved_at": "t"}}
    )
    g = next(p for p in after["packages"] if p["id"] == "g@1")
    assert g["verdict"] == "exception"
    assert g["exception"]["original_verdict"] == "deny"
    assert after["summary"]["conflicts"] == 0
    assert after["summary"]["exceptions"] == 1
    assert len(after["conflicts"]) == 0


def test_invalid_manifest_raises():
    import pytest

    with pytest.raises(analyzer.ManifestError):
        analyzer.analyze({"packages": []}, policies.POLICIES["permissive"])
    with pytest.raises(analyzer.ManifestError):
        analyzer.analyze({"packages": [{"version": "1", "license": "MIT"}]},
                         policies.POLICIES["permissive"])


def test_project_license_policy_mismatch():
    import pytest

    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": []},
        ]
    }
    with pytest.raises(analyzer.ManifestError):
        analyzer.analyze(data, policies.POLICIES["strict"], "GPL-3.0")


def test_agpl_network_copyleft_policy():
    data = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["a"]},
            {"name": "a", "version": "1", "license": "AGPL-3.0", "dependencies": []},
        ]
    }
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    a = next(p for p in res["packages"] if p["id"] == "a@1")
    assert a["verdict"] == "deny"


def test_example_manifest(tmp_path):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "examples", "manifest.example.json",
    )
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    res = analyzer.analyze(data, policies.POLICIES["permissive"])
    by_id = {p["id"]: p for p in res["packages"]}
    # 加密原语 GPL-3.0 经 network内核 传递引入 → 冲突 + 最短路径
    gpl = by_id["加密原语@2.0.0"]
    assert gpl["verdict"] == "deny"
    assert gpl["shortest_path"][0] == "rpc工具包@5.0.0"
    assert gpl["shortest_path"][-1] == "加密原语@2.0.0"
    # json 工具 SPDX 表达式 (MIT OR Apache-2.0) → 选 MIT 兼容
    assert by_id["json工具@1.0.0"]["verdict"] == "allow"
    # 自定义许可证 → review
    assert by_id["内部工具@0.1.0"]["verdict"] == "review"
    # 未被任何包引用且无 direct_dependencies 指向 → 不可达，仍是 review
    assert by_id["内部工具@0.1.0"]["reachable"] is False


# ---------------------------------------------------------------------------
# 多制品（distributions）审查
# ---------------------------------------------------------------------------


MULTI_MANIFEST = {
    "project": {"name": "multi-demo", "version": "1.0"},
    "distributions": [
        {"name": "gpl3-cli", "project_license": "GPL-3.0",
         "direct_dependencies": ["cli-main"]},
        {"name": "gpl2-daemon", "project_license": "GPL-2.0",
         "direct_dependencies": ["server", "ghost-artifact@3"]},
    ],
    "packages": [
        {"name": "cli-main", "version": "1", "license": "GPL-3.0",
         "dependencies": ["shared", "vendored-blob"]},
        {"name": "server", "version": "1", "license": "GPL-2.0",
         "dependencies": ["shared"]},
        {"name": "shared", "version": "1", "license": "Apache-2.0",
         "dependencies": []},
        {"name": "vendored-blob", "version": "1", "license": "Proprietary",
         "dependencies": []},
        {"name": "orphan", "version": "1", "license": "MIT", "dependencies": []},
    ],
}


def test_multi_mode_flag_and_scope_shape():
    res = analyzer.analyze(MULTI_MANIFEST, policies.POLICIES["copyleft"])
    assert res["mode"] == "multi"
    assert [d["name"] for d in res["distributions"]] == ["gpl3-cli", "gpl2-daemon"]
    assert res["project_license"] == "GPL-3.0"  # 元数据缺省取首个制品
    licenses = {d["name"]: d["project_license"] for d in res["distributions"]}
    assert licenses == {"gpl3-cli": "GPL-3.0", "gpl2-daemon": "GPL-2.0"}


def test_multi_common_package_independent_verdicts_and_paths():
    res = analyzer.analyze(MULTI_MANIFEST, policies.POLICIES["copyleft"])
    cli = next(d for d in res["distributions"] if d["name"] == "gpl3-cli")
    daemon = next(d for d in res["distributions"] if d["name"] == "gpl2-daemon")

    s_cli = next(p for p in cli["packages"] if p["id"] == "shared@1")
    s_d = next(p for p in daemon["packages"] if p["id"] == "shared@1")
    # GPL-3.0 与 Apache-2.0 矩阵兼容；GPL-2.0 与 Apache-2.0 专利冲突
    assert s_cli["verdict"] == "allow"
    assert s_cli["rule"] == "MATRIX:GPL-3.0=Apache-2.0"
    assert s_cli["shortest_path"] == ["cli-main@1", "shared@1"]
    assert s_cli["depth"] == 1
    assert s_d["verdict"] == "deny"
    assert s_d["rule"] == "MATRIX:GPL-2.0!Apache-2.0"
    assert s_d["shortest_path"] == ["server@1", "shared@1"]
    assert s_d["distribution"] == "gpl2-daemon"


def test_multi_scope_only_counts_reachable_packages():
    res = analyzer.analyze(MULTI_MANIFEST, policies.POLICIES["copyleft"])
    cli = next(d for d in res["distributions"] if d["name"] == "gpl3-cli")
    daemon = next(d for d in res["distributions"] if d["name"] == "gpl2-daemon")
    assert {p["id"] for p in cli["packages"]} == {
        "cli-main@1", "shared@1", "vendored-blob@1"}
    assert {p["id"] for p in daemon["packages"]} == {"server@1", "shared@1"}
    assert cli["summary"]["total"] == 3
    assert daemon["summary"]["total"] == 2


def test_multi_dangling_root_localized_to_distribution():
    res = analyzer.analyze(MULTI_MANIFEST, policies.POLICIES["copyleft"])
    daemon = next(d for d in res["distributions"] if d["name"] == "gpl2-daemon")
    assert daemon["dangling_roots"] == ["ghost-artifact@3"]
    assert res["dangling_roots"] == [
        {"distribution": "gpl2-daemon", "ref": "ghost-artifact@3"}]
    assert "ghost-artifact@3" in res["unresolved_refs"]
    cli = next(d for d in res["distributions"] if d["name"] == "gpl3-cli")
    assert cli["dangling_roots"] == []


def test_multi_overview_aggregates_worst_and_lists_affected():
    res = analyzer.analyze(MULTI_MANIFEST, policies.POLICIES["copyleft"])
    ov = res["overview"]
    shared = next(p for p in ov["packages"] if p["id"] == "shared@1")
    assert shared["verdict"] == "deny"
    assert shared["affected_count"] == 2
    assert {a["distribution"] for a in shared["affected"]} == {
        "gpl3-cli", "gpl2-daemon"}
    by_dist = {a["distribution"]: a["verdict"] for a in shared["affected"]}
    assert by_dist == {"gpl3-cli": "allow", "gpl2-daemon": "deny"}
    # 总览统计按去重后的包
    assert res["summary"]["total"] == 4
    assert res["summary"]["deny"] == 2  # shared + vendored-blob
    assert res["summary"]["conflicts"] == 2
    # 从所有制品根都不可达的包单独列出
    assert [p["id"] for p in ov["unreachable_packages"]] == ["orphan@1"]
    assert res["summary"]["unreachable"] == 1


def test_multi_exception_rule_scoped_only_matching_rule():
    policy = policies.POLICIES["copyleft"]
    before = analyzer.analyze(MULTI_MANIFEST, policy)
    daemon = next(d for d in before["distributions"] if d["name"] == "gpl2-daemon")
    shared_rule = next(
        p for p in daemon["packages"] if p["id"] == "shared@1")["rule"]

    # 按 daemon 下的 MATRIX 规则确认例外：只覆盖 daemon，cli 规则不同不受影响
    res = analyzer.analyze(
        MULTI_MANIFEST, policy,
        exceptions={"shared@1": {"note": "n", "approved_at": "t",
                                 "rule": shared_rule}},
    )
    cli = next(d for d in res["distributions"] if d["name"] == "gpl3-cli")
    d2 = next(d for d in res["distributions"] if d["name"] == "gpl2-daemon")
    assert next(p for p in d2["packages"] if p["id"] == "shared@1")["verdict"] == "exception"
    assert next(p for p in cli["packages"] if p["id"] == "shared@1")["verdict"] == "allow"
    # 总览：daemon 已例外、cli allow → 最严重为 allow
    ov_shared = next(p for p in res["overview"]["packages"] if p["id"] == "shared@1")
    assert ov_shared["verdict"] == "allow"
    assert res["summary"]["conflicts"] == 1  # vendored-blob 仍是冲突


def test_multi_exception_same_rule_covers_both_distributions():
    policy = policies.POLICIES["copyleft"]
    res = analyzer.analyze(
        MULTI_MANIFEST, policy,
        exceptions={"vendored-blob@1": {
            "note": "n", "approved_at": "t", "rule": "POLICY_DENY:proprietary"}},
    )
    cli = next(d for d in res["distributions"] if d["name"] == "gpl3-cli")
    v = next(p for p in cli["packages"] if p["id"] == "vendored-blob@1")
    assert v["verdict"] == "exception"
    assert v["exception"]["original_verdict"] == "deny"
    assert v["exception"]["rule"] == "POLICY_DENY:proprietary"


def test_multi_exception_with_wrong_rule_does_not_apply():
    policy = policies.POLICIES["copyleft"]
    res = analyzer.analyze(
        MULTI_MANIFEST, policy,
        exceptions={"shared@1": {"note": "n", "approved_at": "t",
                                 "rule": "MATRIX:GPL-3.0=Apache-2.0"}},
    )
    # cli 下规则匹配，但 cli 本来就是 allow（例外只对 deny/review 生效）；
    # daemon 的 deny 规则不同，不得被覆盖
    daemon = next(d for d in res["distributions"] if d["name"] == "gpl2-daemon")
    assert next(p for p in daemon["packages"] if p["id"] == "shared@1")["verdict"] == "deny"


def test_multi_validation_errors():
    import pytest

    def analyze(manifest):
        return analyzer.analyze(manifest, policies.POLICIES["permissive"])

    base_pkgs = [{"name": "x", "version": "1", "license": "MIT", "dependencies": []}]
    with pytest.raises(analyzer.ManifestError):
        analyze({"distributions": [], "packages": base_pkgs})
    with pytest.raises(analyzer.ManifestError):
        analyze({"distributions": [{"name": "a"}], "packages": base_pkgs})
    with pytest.raises(analyzer.ManifestError):
        analyze({"distributions": [
            {"name": "a", "project_license": "MIT", "direct_dependencies": []},
            {"name": "a", "project_license": "MIT", "direct_dependencies": []},
        ], "packages": base_pkgs})
    with pytest.raises(analyzer.ManifestError):
        analyze({"direct_dependencies": ["x"], "distributions": [
            {"name": "a", "project_license": "MIT", "direct_dependencies": []},
        ], "packages": base_pkgs})
    # 策略不允许该制品许可证
    with pytest.raises(analyzer.ManifestError):
        analyze({"distributions": [
            {"name": "a", "project_license": "GPL-3.0", "direct_dependencies": []},
        ], "packages": base_pkgs})
    # 无法识别的制品许可证
    with pytest.raises(analyzer.ManifestError):
        analyze({"distributions": [
            {"name": "a", "project_license": "Custom-Blah", "direct_dependencies": []},
        ], "packages": base_pkgs})


def test_multi_roots_and_cycles_shared_graph():
    manifest = {
        "distributions": [
            {"name": "a", "project_license": "MIT", "direct_dependencies": ["r1"]},
            {"name": "b", "project_license": "MIT", "direct_dependencies": ["r2"]},
        ],
        "packages": [
            {"name": "r1", "version": "1", "license": "MIT", "dependencies": ["c"]},
            {"name": "r2", "version": "1", "license": "MIT", "dependencies": []},
            {"name": "c", "version": "1", "license": "MIT", "dependencies": ["x"]},
            {"name": "x", "version": "1", "license": "MIT", "dependencies": ["y"]},
            {"name": "y", "version": "1", "license": "MIT", "dependencies": ["x"]},
        ],
    }
    res = analyzer.analyze(manifest, policies.POLICIES["permissive"])
    a, b = res["distributions"]
    assert a["roots"] == ["r1@1"] and b["roots"] == ["r2@1"]
    # 环检测在共享图上做一次
    assert len(res["cycles"]) == 1
    # b 的根就是 r2@1；x/y 位于从 r1 可达的环中，b 不可达 c/x/y
    assert {p["id"] for p in b["packages"]} == {"r2@1"}
    assert {p["id"] for p in a["packages"]} == {"r1@1", "c@1", "x@1", "y@1"}
    assert next(p for p in a["packages"] if p["id"] == "x@1")["depth"] == 2
    assert next(p for p in a["packages"] if p["id"] == "r1@1")["direct"] is True


def test_multi_example_manifest():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "examples", "manifest.multi-distribution.example.json",
    )
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    res = analyzer.analyze(data, policies.POLICIES["copyleft"])
    cli = next(d for d in res["distributions"] if d["name"] == "gpl3-cli")
    daemon = next(d for d in res["distributions"] if d["name"] == "gpl2-daemon")
    shared_cli = next(p for p in cli["packages"] if p["id"] == "共享核心@0.5.0")
    shared_d = next(p for p in daemon["packages"] if p["id"] == "共享核心@0.5.0")
    assert shared_cli["verdict"] == "allow"
    assert shared_d["verdict"] == "deny"
    assert daemon["dangling_roots"] == ["不存在的内部SDK@9.9.9"]
    unreachable = [p["id"] for p in res["overview"]["unreachable_packages"]]
    assert "日志库@0.9.2" in unreachable and "专有组件@1.0.0" in unreachable
