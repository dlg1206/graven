# Util error log table during data generation
CREATE TABLE IF NOT EXISTS error_log
(
    error_id  INTEGER AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stage     CHAR(5),
    uri       VARCHAR(255),
    message   VARCHAR(255)
);