"""Application service and headless CLI for named project scopes (PX-101).

Validate, preview, store, and list exact user-approved scopes. No batch
scanning is dispatched here; approval enforcement across a project's assets is
deferred until it is proven. Reuses the pure domain contract and the project
registry, so the CLI never issues SQL itself.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone

from penx_app.domain.project_scope import (
    MAX_ASSETS,
    Asset,
    AssetStatus,
    ProjectScope,
    TargetKind,
    authorize,
    canonicalize,
    expand_cidr_preview,
    is_expired,
)
from penx_app.storage.db_backend import get_connection
from penx_app.storage.project_repository import (
    AssetRow,
    ProjectRepository,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _split_tags(value: str) -> tuple[str, ...]:
    tags = tuple(tag.strip() for tag in value.split(',') if tag.strip())
    if len(set(tags)) != len(tags):
        raise ValueError('Duplicate asset tag.')
    return tags


class ProjectService:
    def __init__(self, repository: ProjectRepository):
        self.repository = repository

    def create(self, name: str) -> int:
        name = name.strip()
        if not 1 <= len(name) <= 128:
            raise ValueError('Project name must be 1..128 characters.')
        if self.repository.get_project(name) is not None:
            raise ValueError('Project name already exists.')
        return self.repository.create_project(name, _utc_now().isoformat())

    def scope(self, name: str) -> ProjectScope:
        project = self.repository.get_project(name)
        if project is None:
            raise KeyError(f'Unknown project: {name}')
        created = _aware(project.created_at, 'created_at')
        if created is None:
            raise ValueError('Missing project created_at.')
        rows = self.repository.list_assets(project.id)
        assets = tuple(self._to_asset(row) for row in rows)
        return ProjectScope(name, created, assets)

    def add(self, name: str, raw: str, *, now: datetime | None = None,
            expires_at: str | None = None, max_rate: float | None = None,
            max_budget: int | None = None, tags: str = '',
            as_candidate: bool = False) -> int:
        project = self.repository.get_project(name)
        if project is None:
            raise KeyError(f'Unknown project: {name}')
        kind, canonical = canonicalize(raw)
        now = now or _utc_now()
        expiry = _aware(expires_at, 'expires_at')
        parsed_tags = _split_tags(tags)
        status = AssetStatus.CANDIDATE if as_candidate else AssetStatus.APPROVED
        asset = Asset(raw=raw, canonical=canonical, kind=kind, approved_at=now,
                      expires_at=expiry, max_rate=max_rate, max_budget=max_budget,
                      tags=parsed_tags, status=status)
        existing = [row for row in self.repository.list_assets(project.id)
                   if row.canonical == asset.canonical and row.kind == asset.kind.value]
        if existing:
            raise ValueError(f'Asset already recorded for {name}: {asset.canonical}')
        if self.repository.asset_count(project.id) + 1 > MAX_ASSETS:
            raise ValueError('Too many project assets.')
        row = AssetRow(0, project.id, asset.raw, asset.canonical,
                       asset.kind.value, asset.status.value,
                       asset.approved_at.isoformat(),
                       asset.expires_at.isoformat() if asset.expires_at else None,
                       asset.max_rate, asset.max_budget,
                       ','.join(asset.tags))
        try:
            return self.repository.add_asset(row)
        except Exception as exc:
            raise ValueError(f'Could not record asset for {name}: {exc}') from exc

    def approve_candidate(self, name: str, raw: str, *,
                          confirmed: bool = False,
                          now: datetime | None = None) -> str:
        """Require an explicit action to approve an already-recorded candidate.

        No discovered target or missing asset is ever auto-added. Existing
        expiry/rate/budget/tags survive, and expired grants cannot be revived.
        """
        if confirmed is not True:
            raise ValueError('Candidate approval requires explicit --confirm.')
        project = self.repository.get_project(name)
        if project is None:
            raise KeyError(f'Unknown project: {name}')
        kind, canonical = canonicalize(raw)
        rows = [row for row in self.repository.list_assets(project.id)
                if row.canonical == canonical and row.kind == kind.value]
        if len(rows) != 1 or rows[0].status != AssetStatus.CANDIDATE.value:
            raise ValueError('Only one existing candidate may be approved.')
        candidate = self._to_asset(rows[0])
        approval_time = now if now is not None else _utc_now()
        # Validates timezone, expiry and retained per-asset constraints before
        # any write. A stale expiry cannot be cleared by promotion.
        Asset(raw=candidate.raw, canonical=candidate.canonical,
              kind=candidate.kind, approved_at=approval_time,
              expires_at=candidate.expires_at, max_rate=candidate.max_rate,
              max_budget=candidate.max_budget, tags=candidate.tags,
              status=AssetStatus.APPROVED)
        if not self.repository.approve_candidate(
                project.id, canonical, kind.value,
                approved_at=approval_time.isoformat(),
                expected_candidate_at=rows[0].approved_at):
            raise ValueError('Candidate was changed or already approved.')
        return canonical

    def revoke_approval(self, name: str, raw: str, *,
                        confirmed: bool = False) -> str:
        """Explicitly demote an exact approval without deleting its record."""
        if confirmed is not True:
            raise ValueError('Approval revocation requires explicit --confirm.')
        project = self.repository.get_project(name)
        if project is None:
            raise KeyError(f'Unknown project: {name}')
        kind, canonical = canonicalize(raw)
        if not self.repository.revoke_approval(project.id, canonical, kind.value):
            raise ValueError('No currently approved exact asset to revoke.')
        return canonical

    def check(self, name: str, target: str, *, now: datetime | None = None) -> bool:
        return authorize(self.scope(name), target, now=now)

    def preview(self, name: str) -> ProjectScope:
        return self.scope(name)

    @staticmethod
    def _to_asset(row: AssetRow) -> Asset:
        tags = tuple(row.tags.split(',')) if row.tags else ()
        approved = _aware(row.approved_at, 'approved_at')
        if approved is None:
            raise ValueError('Missing asset approved_at.')
        return Asset(
            raw=row.raw,
            canonical=row.canonical,
            kind=TargetKind(row.kind),
            approved_at=approved,
            expires_at=_aware(row.expires_at, 'expires_at'),
            max_rate=row.max_rate,
            max_budget=row.max_budget,
            tags=tags,
            status=AssetStatus(row.status),
        )


def _print_list_projects(service: ProjectService) -> None:
    projects = service.repository.list_projects()
    if not projects:
        print('No projects.')
        return
    print(f'{len(projects)} project(s):')
    for project in projects:
        count = service.repository.asset_count(project.id)
        print(f'  [{project.id}] {project.name}  ({count} asset(s))')


def _print_assets(service: ProjectService, name: str, now: datetime) -> None:
    scope = service.scope(name)
    if not scope.assets:
        print(f'Project {name} has no assets.')
        return
    print(f'Project {name}: {len(scope.assets)} asset(s)')
    for asset in scope.assets:
        state = asset.status.value
        if asset.status is AssetStatus.APPROVED and is_expired(asset, now):
            state = 'expired'
        expiry = asset.expires_at.isoformat() if asset.expires_at else '-'
        print(f'  {state:<10} {asset.kind.value:<9} {asset.canonical}  '
              f'approved={asset.approved_at.isoformat()}  expiry={expiry}')


def _print_check(service: ProjectService, name: str, target: str) -> int:
    authorized = service.check(name, target)
    print('authorized' if authorized else 'not authorized')
    return 0 if authorized else 1


def _print_preview(service: ProjectService, name: str) -> None:
    scope = service.preview(name)
    print(f'Project {name}: {len(scope.assets)} asset(s)')
    for asset in scope.assets:
        if asset.kind is TargetKind.CIDR:
            preview = expand_cidr_preview(asset.canonical)
            sample = ', '.join(preview['sample'])
            note = f' (truncated)' if preview['truncated'] else ''
            print(f'  CIDR {asset.canonical}: {preview["total"]} address(es){note}')
            print(f'    sample: {sample}')
        else:
            print(f'  {asset.kind.value} {asset.canonical}')


def main(argv: list[str], *, connection_factory=None) -> int:
    """Headless entry point for `penx project ...`.

    Exit codes: 0 = success (or target authorized); 1 = target not authorized;
    2 = usage, scope, or storage error (no scan dispatched).
    """
    parser = argparse.ArgumentParser(
        prog='penx project',
        description='Validate, preview, store, and list exact user-approved '
                    'scopes. No batch scanning is dispatched.')
    sub = parser.add_subparsers(dest='action', required=True)
    p_create = sub.add_parser('create', help='Create a named project scope')
    p_create.add_argument('name')
    p_add = sub.add_parser('add', help='Record an exactly approved (or candidate) asset')
    p_add.add_argument('name')
    p_add.add_argument('--target', required=True)
    p_add.add_argument('--expiry', default=None, help='ISO-8601 UTC expiry (optional)')
    p_add.add_argument('--rate', type=float, default=None, help='Optional per-asset max rate')
    p_add.add_argument('--budget', type=int, default=None, help='Optional per-asset budget')
    p_add.add_argument('--tags', default='', help='Comma-separated tags')
    p_add.add_argument('--as-candidate', action='store_true',
                      help='Record as a candidate (never authorized until approved)')
    p_list = sub.add_parser('list', help='List projects, or a project\'s assets')
    p_list.add_argument('name', nargs='?')
    p_check = sub.add_parser('check', help='Check whether a target is authorized')
    p_check.add_argument('name')
    p_check.add_argument('--target', required=True)
    p_preview = sub.add_parser('preview', help='Preview a project scope (bounded CIDR)')
    p_preview.add_argument('name')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    factory = connection_factory if connection_factory is not None else get_connection
    service = ProjectService(ProjectRepository(factory))
    now = _utc_now()
    try:
        if args.action == 'create':
            project_id = service.create(args.name)
            print(f'Created project: {args.name} (id={project_id})')
            return 0
        if args.action == 'add':
            asset_id = service.add(
                args.name, args.target, expires_at=args.expiry, max_rate=args.rate,
                max_budget=args.budget, tags=args.tags, as_candidate=args.as_candidate)
            label = 'candidate' if args.as_candidate else 'approved asset'
            print(f'Recorded {label} for {args.name}: id={asset_id}')
            return 0
        if args.action == 'list':
            if args.name:
                _print_assets(service, args.name, now)
            else:
                _print_list_projects(service)
            return 0
        if args.action == 'check':
            return _print_check(service, args.name, args.target)
        if args.action == 'preview':
            _print_preview(service, args.name)
            return 0
        raise ValueError('Unknown project action.')
    except KeyError as exc:
        print('[!] Project scope: ' + str(exc).strip("'\""))
        return 2
    except (ValueError, TypeError) as exc:
        print('[!] Project scope: ' + str(exc))
        return 2
    except Exception as exc:
        print('[!] Project scope: ' + type(exc).__name__ + ': ' + str(exc))
        return 2
