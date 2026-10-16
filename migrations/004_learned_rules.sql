-- PenX Migration 004: Learned rules table for distilled corrections
-- Run with: mysql -u penx -p penx < migrations/004_learned_rules.sql

CREATE TABLE IF NOT EXISTS learned_rules (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  rule_text  TEXT NOT NULL COMMENT 'Short imperative rule, under 120 chars',
  source     VARCHAR(100) NOT NULL COMMENT 'e.g., claude-opus-4-6, human',
  created_at DATETIME NOT NULL
);

SELECT 'learned_rules table created' AS status;
DESCRIBE learned_rules;
