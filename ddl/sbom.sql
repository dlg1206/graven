# Table for storing syft sbom archives
CREATE TABLE IF NOT EXISTS sbom
(
    jar_id   VARCHAR(255) PRIMARY KEY,
    uploaded TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sbom     MEDIUMBLOB, # compressed archive of
    run_id   INTEGER,
    FOREIGN KEY (jar_id) REFERENCES jar (jar_id),
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);