# Table for tracking jar details
CREATE TABLE IF NOT EXISTS jar
(
    jar_id          VARCHAR(255) PRIMARY KEY,
    uri             VARCHAR(512) UNIQUE,
    group_id        VARCHAR(255),
    artifact_id     VARCHAR(255),
    version         VARCHAR(100),
    publish_date    TIMESTAMP,
    last_grype_scan TIMESTAMP,
    # metadata
    last_processed  TIMESTAMP,
    status          VARCHAR(32), # track stage
    run_id          INTEGER,
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);