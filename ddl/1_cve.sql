# Table for tracking CVE information
CREATE TABLE IF NOT EXISTS cve
(
    cve_id       VARCHAR(20) PRIMARY KEY,
    severity     VARCHAR(10),
    cvss         DOUBLE,
    publish_date TIMESTAMP,
    description  TEXT,
    source       VARCHAR(255),
    last_queried TIMESTAMP,
    status_code  INTEGER, # 0 ok, 1 err, 2 in prog
    run_id       INTEGER,
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);