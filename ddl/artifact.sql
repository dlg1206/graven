# Table for storing syft sbom archives
CREATE TABLE IF NOT EXISTS artifact
(
    purl    VARCHAR(255) PRIMARY KEY,
    name    VARCHAR(100),
    version VARCHAR(100),
    run_id  INTEGER,
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);