# LicenseGate — 开源依赖许可审查 Web 应用

基于 **FastAPI + SQLite** 的自托管工具：上传包含包名、版本、许可证与依赖关系的
JSON 清单，选择项目许可策略后，系统解析完整**传递依赖图**，按内置许可证
**兼容矩阵**标出冲突，为每个冲突给出：

* **结论**：`冲突(deny)` / `待审查(review)` / `兼容(allow)`；
* **触发规则**：矩阵规则（`MATRIX`）或策略规则（`POLICY_DENY` / `POLICY_ALLOW` / `UNKNOWN_LICENSE`）及触发的许可证；
* **最短依赖路径**：从直接依赖（根）到冲突包的最短路径（BFS）与引入深度；
* **例外确认**：在页面上对任意冲突包填写理由并"确认例外"，结果实时重新计算，可随时撤销；
* **JSON 报告导出**：一键下载完整审查报告。

> ⚠️ 内置矩阵覆盖 MIT / Apache-2.0 / BSD / ISC / MPL-2.0 / LGPL-2.1 / LGPL-3.0 /
> GPL-2.0 / GPL-3.0 / AGPL-3.0 / Proprietary 等常见许可证（含 GPL 单向兼容、
> Apache↔GPL2 专利冲突、AGPL 网络条款等），仅作工程辅助，**不构成法律意见**。

---

## 一键启动（Docker Compose）

```bash
# 在项目根目录执行
docker compose up -d --build
```

启动后访问：

| 项目 | 地址 |
| --- | --- |
| Web 页面 | <http://localhost:8000/> |
| 健康检查 | <http://localhost:8000/api/health> |
| 策略列表 | <http://localhost:8000/api/policies> |
| 许可证矩阵 | <http://localhost:8000/api/licenses> |
| OpenAPI 文档 | <http://localhost:8000/docs> |

**端口**：容器内固定监听 `8000`；宿主机端口默认 `8000`，可通过环境变量修改：

```bash
LICENSEGATE_PORT=9000 docker compose up -d --build
# 然后访问 http://localhost:9000/
```

停止 / 清理：

```bash
docker compose down          # 停止（数据保留在命名卷 licensegate-data 中）
docker compose down -v       # 停止并删除数据库卷
```

---

## 本地开发运行（不用 Docker）

需要 Python 3.11+：

```bash
pip install -r requirements.txt
export LICENSEGATE_DB=./data/licensegate.db   # SQLite 文件路径，默认 /data/licensegate.db
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

运行测试：

```bash
pip install pytest
pytest -q
```

---

## 配置项

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LICENSEGATE_DB` | `/data/licensegate.db`（容器内） | SQLite 数据库文件路径；设为 `:memory:` 使用内存库（测试用） |
| `LICENSEGATE_PORT` | `8000` | **宿主机**映射端口（docker-compose 变量，仅影响 `-p` 映射） |

容器内数据目录 `/data` 挂载到 Docker 命名卷 `licensegate-data`，容器重建后项目与
例外记录不会丢失。

---

## 清单文件格式

上传一个 UTF-8 编码的 JSON 文件（参考 [`examples/manifest.example.json`](examples/manifest.example.json)）：

```json
{
  "project": { "name": "my-app", "version": "1.4.0" },
  "project_license": "MIT",
  "direct_dependencies": ["web框架"],
  "packages": [
    {
      "name": "web框架",
      "version": "2.3.1",
      "license": "MIT",
      "dependencies": ["json工具@1.0.0", "日志库@0.9.2"]
    },
    {
      "name": "json工具",
      "version": "1.0.0",
      "license": "(MIT OR Apache-2.0)",
      "dependencies": []
    }
  ]
}
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `packages[].name` | 是 | 包名 |
| `packages[].version` | 否 | 版本，缺省记为 `0.0.0` |
| `packages[].license` | 是 | 许可证；支持 SPDX 标识与 SPDX 复合表达式 `AND` / `OR` / `WITH` / 括号 |
| `packages[].dependencies` | 否 | 依赖引用：`名字` 或 `名字@版本`；同名包仅一个版本时可省略版本 |
| `project.name` / `project.version` | 否 | 项目元信息 |
| `project_license` | 否 | 项目许可证（派生作品分发许可证），缺省取策略默认值 |
| `direct_dependencies` | 否 | 显式直接依赖（图的根）；缺省时以"入度为 0 的包"为根 |

解析特性：

* 同一 `name@version` 重复出现会自动合并依赖边；
* 引用了不存在的包 → 记为"悬空引用"在页面提示，不中断分析；
* 循环依赖通过 Tarjan 算法检出并提示，BFS 不会死循环；孤立环中的包标记为"不可达"；
* 许可证别名自动规范化（`apache2` → `Apache-2.0`、`agpl` → `AGPL-3.0` 等），无法识别
  时按策略判为"待审查"或"冲突"。

### SPDX 复合表达式语义

* `A OR B`：被许可方可二选一，按**最兼容**分支判定；
* `A AND B`：条款同时适用，按**最严格**分支判定。

---

## 许可策略

策略在兼容矩阵之上叠加两层规则：

1. **策略禁止家族**（`POLICY_DENY`，最高优先级）——即使矩阵判兼容也按冲突处理；
2. **策略预放行家族**（`POLICY_ALLOW`）——矩阵建议"待审查"时可自动放行；
   矩阵明确"冲突"的组合**永远不会被降级**。

| 策略 | 默认项目许可证 | 行为摘要 |
| --- | --- | --- |
| `permissive` 宽松商业友好 | MIT | 允许宽松/MPL；LGPL 预放行（仍建议确认链接方式）；GPL/AGPL/专有拒绝 |
| `copyleft` Copyleft 开放专享 | GPL-3.0 | 允许开源/ copyleft 许可证；专有拒绝；矩阵不兼容组合拒绝 |
| `strict` 严格白名单 | MIT | 仅允许公共领域与宽松许可证；MPL/LGPL/GPL/专有及**无法识别的许可证**全部拒绝 |
| `proprietary` 专有闭源商业 | Proprietary | 仅允许宽松/Apache；MPL 待审查；LGPL/GPL/AGPL 拒绝 |

每个策略限定了可选的"项目许可证"范围；上传时也可以在页面上覆盖项目许可证并重新计算。

---

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/analyze` | 即时分析（JSON body，不落库） |
| `POST` | `/api/projects` | 上传清单（`multipart/form-data`：`file`、`policy_key`、`project_license`），创建项目并返回分析结果 |
| `GET` | `/api/projects` | 项目列表 |
| `GET` | `/api/projects/{id}` | 获取项目最新分析结果（可带 `?policy_key=&project_license=`） |
| `POST` | `/api/projects/{id}/reanalyze` | 切换策略/项目许可证后重新计算 |
| `POST` | `/api/projects/{id}/exceptions/{package_id}` | 确认例外（body：`{"note": "理由"}`），自动重新计算 |
| `DELETE` | `/api/projects/{id}/exceptions/{package_id}` | 撤销例外，自动重新计算 |
| `DELETE` | `/api/projects/{id}` | 删除项目 |
| `GET` | `/api/projects/{id}/export` | 下载 JSON 报告（`license-report-{id}.json`） |
| `GET` | `/api/policies` · `/api/licenses` · `/api/health` | 元数据 |

`package_id` 即 `name@version`（URL 中需编码，前端已处理）。

导出报告（`licensegate-report/v1`）包含：项目与策略信息、统计摘要、每个包的结论 /
触发规则 / 最短路径 / 例外信息、冲突列表、循环依赖、悬空引用以及原始清单。

---

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 路由与静态页
│   ├── analyzer.py    # 清单解析、依赖图、BFS 最短路径、环检测、冲突分析
│   ├── licenses.py    # SPDX 规范化、表达式解析、兼容性矩阵
│   ├── policies.py    # 四种许可策略与判定叠加规则
│   └── db.py          # SQLite 持久化（项目 + 例外）
├── static/index.html  # 单页前端（原生 JS，无构建步骤）
├── examples/          # 示例清单
├── tests/             # 29 个单元/接口测试
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
