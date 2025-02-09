# Table for tracking jar details
CREATE TABLE IF NOT EXISTS jar
(
    jar_id       VARCHAR(255) PRIMARY KEY,
    uri          VARCHAR(255) UNIQUE,
    group_id     VARCHAR(255),
    artifact_id  VARCHAR(255),
    version      VARCHAR(100),
    publish_date TIMESTAMP,
    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);