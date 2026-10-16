-- PenX MariaDB schema baseline for a new database (must exist already).
-- Run before 002_evaluations.sql, 003_confidence.sql, 004_learned_rules.sql,
-- and 005_runtime_compat.sql. Safe to re-run; no data is dropped.
CREATE TABLE IF NOT EXISTS history (
    sl_no INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_date DATETIME NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sl_no INT,
    vuln_name TEXT,
    severity VARCHAR(30),
    port VARCHAR(100),
    service TEXT,
    description LONGTEXT,
    INDEX idx_vulnerabilities_session (sl_no),
    CONSTRAINT fk_penx_vuln_session FOREIGN KEY (sl_no) REFERENCES history(sl_no)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS fixes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sl_no INT,
    vuln_id INT,
    fix_text LONGTEXT,
    source VARCHAR(120),
    INDEX idx_fixes_session (sl_no),
    INDEX idx_fixes_vuln (vuln_id),
    CONSTRAINT fk_penx_fixes_session FOREIGN KEY (sl_no) REFERENCES history(sl_no),
    CONSTRAINT fk_penx_fixes_vuln FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS exploits_attempted (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sl_no INT,
    exploit_name TEXT,
    tool_used TEXT,
    payload LONGTEXT,
    result TEXT,
    notes LONGTEXT,
    INDEX idx_exploits_session (sl_no),
    CONSTRAINT fk_penx_exploits_session FOREIGN KEY (sl_no) REFERENCES history(sl_no)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS summary (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sl_no INT,
    raw_scan LONGTEXT,
    ai_analysis LONGTEXT,
    risk_level VARCHAR(30),
    generated_at DATETIME,
    INDEX idx_summary_session (sl_no),
    CONSTRAINT fk_penx_summary_session FOREIGN KEY (sl_no) REFERENCES history(sl_no)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS corrections (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sl_no INT NOT NULL,
    vuln_id INT NOT NULL,
    status VARCHAR(40) NOT NULL,
    original_text LONGTEXT,
    corrected_text LONGTEXT,
    reason LONGTEXT,
    corrected_at DATETIME NOT NULL,
    INDEX idx_corrections_session (sl_no),
    INDEX idx_corrections_vuln (vuln_id),
    CONSTRAINT fk_penx_corrections_session FOREIGN KEY (sl_no) REFERENCES history(sl_no),
    CONSTRAINT fk_penx_corrections_vuln FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
