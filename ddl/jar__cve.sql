# Join table for mapping cves to jars
CREATE TABLE IF NOT EXISTS jar__cve
(
    jar_id VARCHAR(255),
    cve_id VARCHAR(20),
    run_id INTEGER,
    PRIMARY KEY (jar_id, cve_id),
    FOREIGN KEY (jar_id) REFERENCES jar (jar_id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);