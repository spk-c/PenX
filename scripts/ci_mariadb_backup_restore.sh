#!/usr/bin/env bash
# Disposable service DB only; no live scanner, production database, or PII.
set -euo pipefail
if [[ "$PENX_MARIADB_TEST" != "1" || "$PENX_DB_ENGINE" != "mariadb" ||
      "$PENX_DB_HOST" != "127.0.0.1" || "$PENX_DB_NAME" != "penx_ci_test" ]]; then
  echo "REFUSED: isolated MariaDB test DB required." >&2
  exit 2
fi
cid="$PENX_MARIADB_CONTAINER"
if [[ ! "$cid" =~ ^[a-f0-9]{12,64}$ ]]; then
  echo "REFUSED: expected current MariaDB CI service container ID." >&2
  exit 2
fi
sql() {
  docker exec "$cid" mariadb --host=127.0.0.1 --user=penx_ci \
    --password=integration-only penx_ci_test "$@"
}
root_sql() {
  docker exec "$cid" mariadb --host=127.0.0.1 --user=root \
    --password=integration-root-only "$@"
}
sql -e "INSERT INTO history (sl_no, target, scan_date, status)
        VALUES (987654, 'restore-fixture.invalid', '2026-10-16', 'active')"
sql -e "INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level)
        VALUES (987654, 'synthetic scanner fixture', 'synthetic review fixture', 'LOW')"

backup="$RUNNER_TEMP/penx-ci-mariadb-$GITHUB_RUN_ID.sql"
trap 'rm -f "$backup"' EXIT
docker exec "$cid" mariadb-dump --host=127.0.0.1 --user=penx_ci \
  --password=integration-only --single-transaction --skip-comments \
  --skip-lock-tables penx_ci_test > "$backup"
if [[ ! -s "$backup" ]]; then
  echo "MariaDB logical backup was empty." >&2
  exit 1
fi

# A separate restored DB, limited to an ephemeral GitHub-hosted service.
root_sql -e "CREATE DATABASE penx_ci_restore_test CHARACTER SET utf8mb4"
docker exec -i "$cid" mariadb --host=127.0.0.1 --user=root \
  --password=integration-root-only penx_ci_restore_test < "$backup"

restored=$(root_sql -N -B -e \
  "SELECT COUNT(*) FROM penx_ci_restore_test.history
   WHERE sl_no=987654 AND target='restore-fixture.invalid' AND status='active'")
summary=$(root_sql -N -B -e \
  "SELECT COUNT(*) FROM penx_ci_restore_test.summary
   WHERE sl_no=987654 AND raw_scan='synthetic scanner fixture' AND risk_level='LOW'")
index=$(root_sql -N -B -e \
  "SELECT COUNT(*) FROM information_schema.STATISTICS
   WHERE TABLE_SCHEMA='penx_ci_restore_test' AND TABLE_NAME='summary'
   AND INDEX_NAME='uq_summary_sl_no' AND NON_UNIQUE=0")
if [[ "$restored" != "1" || "$summary" != "1" || "$index" -lt 1 ]]; then
  echo "FAIL: MariaDB restored row integrity or unique index." >&2
  exit 1
fi
if root_sql -e \
  "INSERT INTO penx_ci_restore_test.summary
   (sl_no, raw_scan, ai_analysis, risk_level)
   VALUES (987654, 'duplicate', 'invalid', 'HIGH')" >/dev/null 2>&1; then
  echo "FAIL: Restored DB accepted duplicate assessment." >&2
  exit 1
fi
after=$(root_sql -N -B -e \
  "SELECT COUNT(*) FROM penx_ci_restore_test.summary WHERE sl_no=987654")
if [[ "$after" != "1" ]]; then
  echo "FAIL: Rejected insert damaged restored data." >&2
  exit 1
fi
echo "Disposable MariaDB logical backup SHA256: $(sha256sum "$backup" | cut -d ' ' -f 1)"
echo "PASS: synthetic MariaDB dump/restore preserves history, summary and uniqueness."
