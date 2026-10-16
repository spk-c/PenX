-- Issue #147: one assessment summary per session (MariaDB).
-- IMPORTANT: back up the database and run the read-only preflight queries
-- in migrations/README.md first. Existing duplicates/NULLs cause this DDL
-- to fail; NEVER use ALTER IGNORE (which can discard customer records).
-- One ALTER keeps the NOT NULL change and UNIQUE index in the same statement.
-- IF NOT EXISTS makes re-running the index addition safe on a clean DB.
ALTER TABLE summary
    MODIFY COLUMN sl_no INT NOT NULL,
    ADD UNIQUE INDEX IF NOT EXISTS uq_summary_sl_no (sl_no);
