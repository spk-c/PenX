-- PX-101: project registry for MariaDB (manual/idempotent migration).
-- Apply after 007_summary_unique.sql. No existing data is altered or dropped.
CREATE TABLE IF NOT EXISTS projects (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    created_at VARCHAR(48) NOT NULL,
    UNIQUE KEY uq_projects_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS project_assets (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    raw TEXT NOT NULL,
    canonical VARCHAR(320) NOT NULL,
    kind VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    approved_at VARCHAR(48) NOT NULL,
    expires_at VARCHAR(48) NULL,
    max_rate DOUBLE NULL,
    max_budget INT NULL,
    tags TEXT NOT NULL,
    UNIQUE KEY uq_project_asset (project_id, canonical, kind),
    CONSTRAINT fk_penx_project_asset_project
        FOREIGN KEY (project_id) REFERENCES projects(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
