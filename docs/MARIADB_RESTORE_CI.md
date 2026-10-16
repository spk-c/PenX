# Isolated MariaDB backup/restore on GitHub Actions

The `MariaDB integration` CI job first exercises real schema migrations,
CRUD, duplicate detection and transactional rollback. It then writes a
**synthetic**, disposable history/summary record into its temporary
`penx_ci_test` service database, creates a transactional `mariadb-dump`,
and restores it into an entirely separate `penx_ci_restore_test` database
inside the same ephemeral service container.

The job validates the restored history, assessment summary, uniqueness
index and rejection of duplicate assessments. The script refuses to run
outside the exact CI test environment and writes no production data.
The temporary SQL dump is removed from the runner after validation.

**Scope:** This is a genuine MariaDB logical dump/restore with synthetic
fixture rows, NOT proof of restoring a sanitized historical production-shaped
backup, migration of a real older customer database, or field rollback.
Pk07 still requires independent real-backup evidence and sign-off.
