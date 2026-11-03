"""SQLite/MariaDB persistence for named project scopes and approved assets (PX-101).

One explicit read/write contract for the project registry. Rows are stored in
backend-neutral %s form; the SQLite backend adapts the placeholders. Duplicate
(canonical, kind) pairs inside a project are rejected by the unique index.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from typing import Any, NamedTuple


class Project(NamedTuple):
    id: int
    name: str
    created_at: str


class AssetRow(NamedTuple):
    id: int
    project_id: int
    raw: str
    canonical: str
    kind: str
    status: str
    approved_at: str
    expires_at: str | None
    max_rate: float | None
    max_budget: int | None
    tags: str


ASSET_COLUMNS = ("id, project_id, raw, canonical, kind, status, approved_at, "
                 "expires_at, max_rate, max_budget, tags")


@dataclass(frozen=True)
class ProjectRepository:
    connection_factory: Callable[[], Any]

    def create_project(self, name: str, created_at: str) -> int:
        with closing(self.connection_factory()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO projects (name, created_at) VALUES (%s, %s)",
                (name, created_at))
            conn.commit()
            return cursor.lastrowid

    def get_project(self, name: str) -> Project | None:
        with closing(self.connection_factory()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, created_at FROM projects WHERE name = %s", (name,))
            row = cursor.fetchone()
            return Project(*row) if row else None

    def list_projects(self) -> list[Project]:
        with closing(self.connection_factory()) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, created_at FROM projects ORDER BY id")
            return [Project(*row) for row in cursor.fetchall()]

    def asset_count(self, project_id: int) -> int:
        with closing(self.connection_factory()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM project_assets WHERE project_id = %s",
                (project_id,))
            return cursor.fetchone()[0]

    def add_asset(self, row: AssetRow) -> int:
        with closing(self.connection_factory()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO project_assets "
                "(project_id, raw, canonical, kind, status, approved_at, "
                "expires_at, max_rate, max_budget, tags) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (row.project_id, row.raw, row.canonical, row.kind, row.status,
                 row.approved_at, row.expires_at, row.max_rate, row.max_budget,
                 row.tags))
            conn.commit()
            return cursor.lastrowid

    def list_assets(self, project_id: int) -> list[AssetRow]:
        with closing(self.connection_factory()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT {ASSET_COLUMNS} FROM project_assets "
                "WHERE project_id = %s ORDER BY id", (project_id,))
            return [AssetRow(*row) for row in cursor.fetchall()]

    def delete_asset(self, project_id: int, canonical: str, kind: str) -> bool:
        with closing(self.connection_factory()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM project_assets "
                "WHERE project_id = %s AND canonical = %s AND kind = %s",
                (project_id, canonical, kind))
            conn.commit()
            return cursor.rowcount > 0
