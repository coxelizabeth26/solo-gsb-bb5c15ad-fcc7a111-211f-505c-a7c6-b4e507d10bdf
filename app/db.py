"""SQLite 持久化层（标准库 sqlite3）。"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    project_version TEXT DEFAULT '',
    project_license TEXT NOT NULL,
    policy_key TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    package_id TEXT NOT NULL,
    note TEXT DEFAULT '',
    rule TEXT,
    approved_at TEXT NOT NULL,
    UNIQUE(project_id, package_id)
);

CREATE INDEX IF NOT EXISTS idx_exceptions_project ON exceptions(project_id);
"""

#: 旧库（建表时没有 rule 列）平滑升级
_MIGRATIONS = (
    "ALTER TABLE exceptions ADD COLUMN rule TEXT",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        if self.path == ":memory:":
            # 测试模式：复用同一内存连接，避免每个连接拿到独立空库
            assert self._mem_conn is not None
            try:
                yield self._mem_conn
                self._mem_conn.commit()
            except Exception:
                self._mem_conn.rollback()
                raise
            return
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self) -> None:
        if self.path == ":memory:":
            self._mem_conn = sqlite3.connect(
                ":memory:", check_same_thread=False
            )
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON")
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            for stmt in _MIGRATIONS:
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    pass  # 列已存在（全新库按 SCHEMA 直接建好）
            if self.path != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL")

    # ------------------------------------------------------------------ #

    def create_project(self, name: str, project_version: str, project_license: str,
                       policy_key: str, manifest: dict) -> int:
        ts = now_iso()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO projects(name, project_version, project_license, policy_key, "
                "manifest_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (name, project_version, project_license, policy_key,
                 json.dumps(manifest, ensure_ascii=False), ts, ts),
            )
            return int(cur.lastrowid)

    def list_projects(self, limit: int = 50) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, name, project_version, project_license, policy_key, "
                "created_at, updated_at FROM projects ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_project(self, project_id: int) -> Optional[dict]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["manifest"] = json.loads(data.pop("manifest_json"))
        return data

    def delete_project(self, project_id: int) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            return cur.rowcount > 0

    def touch_project(self, project_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE projects SET updated_at = ? WHERE id = ?",
                (now_iso(), project_id),
            )

    # ------------------------------------------------------------------ #

    def list_exceptions(self, project_id: int) -> dict[str, dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT package_id, note, rule, approved_at FROM exceptions "
                "WHERE project_id = ? ORDER BY approved_at",
                (project_id,),
            ).fetchall()
        return {
            r["package_id"]: {
                "note": r["note"],
                "rule": r["rule"],
                "approved_at": r["approved_at"],
            }
            for r in rows
        }

    def add_exception(self, project_id: int, package_id: str, note: str,
                      rule: Optional[str] = None) -> dict:
        ts = now_iso()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO exceptions(project_id, package_id, note, rule, approved_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(project_id, package_id) "
                "DO UPDATE SET note=excluded.note, rule=excluded.rule, "
                "approved_at=excluded.approved_at",
                (project_id, package_id, note, rule, ts),
            )
            conn.execute(
                "UPDATE projects SET updated_at = ? WHERE id = ?", (ts, project_id)
            )
        return {"note": note, "approved_at": ts}

    def remove_exception(self, project_id: int, package_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute(
                "DELETE FROM exceptions WHERE project_id = ? AND package_id = ?",
                (project_id, package_id),
            )
            if cur.rowcount:
                conn.execute(
                    "UPDATE projects SET updated_at = ? WHERE id = ?",
                    (now_iso(), project_id),
                )
            return cur.rowcount > 0
