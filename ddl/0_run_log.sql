# metadata about each run
CREATE TABLE IF NOT EXISTS run_log
(
    run_id          INTEGER AUTO_INCREMENT PRIMARY KEY,
    start           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end             TIMESTAMP,
    syft_version    VARCHAR(10),
    grype_version   VARCHAR(10),
    grype_db_source VARCHAR(255) # url of source
);