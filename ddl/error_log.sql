# Util error log table during data generation
CREATE TABLE IF NOT EXISTS error_log
(
    error_id      INTEGER AUTO_INCREMENT PRIMARY KEY,
    run_id        INTEGER,
    timestamp     TIMESTAMP,
    stage         VARCHAR(32),
    jar_id        VARCHAR(255),
    error_type    VARCHAR(255),
    error_message TEXT,
    details       JSON,
    FOREIGN KEY (jar_id) REFERENCES jar (jar_id),
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);