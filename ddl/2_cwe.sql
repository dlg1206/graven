# Table for tracking CWE information
CREATE TABLE IF NOT EXISTS cwe
(
    cwe_id       VARCHAR(10) PRIMARY KEY,
    name         VARCHAR(100) UNIQUE,
    description  TEXT,
    source       VARCHAR(255),
    last_queried TIMESTAMP,
    status_code  INTEGER,
    run_id       INTEGER,
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);