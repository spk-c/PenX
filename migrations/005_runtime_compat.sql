-- PenX MariaDB compatibility migration for older installations.
-- Add columns introduced by the active/pending assessment lifecycle.
-- Repeatable: existing values are preserved.
ALTER TABLE history ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';
ALTER TABLE summary ADD COLUMN IF NOT EXISTS model_name VARCHAR(200) DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS confidence VARCHAR(20) DEFAULT 'possible';
