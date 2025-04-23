# Join table for CVEs and CWEs
CREATE TABLE IF NOT EXISTS cve__cwe
(
    cve_id VARCHAR(20),
    cwe_id VARCHAR(10),
    PRIMARY KEY (cve_id, cwe_id),
    FOREIGN KEY (cve_id) REFERENCES cve (cve_id) ON DELETE CASCADE,
    FOREIGN KEY (cwe_id) REFERENCES cwe (cwe_id) ON DELETE CASCADE
);