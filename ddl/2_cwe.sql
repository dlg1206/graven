# Table for tracking CWE information
CREATE TABLE IF NOT EXISTS cwe
(
    cwe_id      VARCHAR(10) PRIMARY KEY,
    name        VARCHAR(100) UNIQUE,
    description TEXT
);