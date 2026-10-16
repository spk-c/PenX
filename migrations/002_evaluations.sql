-- PenX Migration 002: Evaluations table + model_name tracking
-- Run with: mysql -u penx -p penx < migrations/002_evaluations.sql

-- 1. Create evaluations table for external LLM review storage
CREATE TABLE IF NOT EXISTS evaluations (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  sl_no            INT NOT NULL,
  vuln_id          INT NOT NULL,
  evaluator        VARCHAR(100) NOT NULL COMMENT 'e.g., claude-opus-4-6, gpt-5-4, human',
  evidence_cited   TEXT COMMENT 'Evidence quoted from raw scan data',
  verdict          VARCHAR(50) NOT NULL COMMENT 'valid, hallucination, corrected, downgraded, reclassified',
  confidence       VARCHAR(20) DEFAULT 'medium' COMMENT 'high, medium, low',
  severity_correct BOOLEAN DEFAULT FALSE,
  cve_correct      BOOLEAN DEFAULT FALSE,
  software_correct BOOLEAN DEFAULT FALSE,
  fix_correct      BOOLEAN DEFAULT FALSE,
  notes            TEXT COMMENT 'Evaluator reasoning and explanation',
  evaluated_at     DATETIME NOT NULL,
  FOREIGN KEY (sl_no)   REFERENCES history(sl_no),
  FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);

-- 2. Add model_name to summary table to track which model produced the analysis
ALTER TABLE summary ADD COLUMN IF NOT EXISTS model_name VARCHAR(200) DEFAULT '' AFTER risk_level;

-- Verify
SELECT 'evaluations table created' AS status;
DESCRIBE evaluations;
SELECT 'model_name column added to summary' AS status;
SHOW COLUMNS FROM summary WHERE Field = 'model_name';
