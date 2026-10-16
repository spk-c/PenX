-- PenX Migration 003: Add confidence column to vulnerabilities
-- Run with: mysql -u penx -p penx < migrations/003_confidence.sql

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS confidence VARCHAR(20) DEFAULT 'possible' AFTER severity;

-- Backfill existing data: mark all existing vulns as 'possible' (unknown confidence)
UPDATE vulnerabilities SET confidence = 'possible' WHERE confidence IS NULL;

-- Verify
SELECT 'confidence column added' AS status;
SHOW COLUMNS FROM vulnerabilities WHERE Field = 'confidence';
