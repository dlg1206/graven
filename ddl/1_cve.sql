# Table for tracking CVE information
CREATE TABLE IF NOT EXISTS cve
(
    cve_id       VARCHAR(20) PRIMARY KEY,
    cvss         DOUBLE,
    publish_date TIMESTAMP,
    description  TEXT
);