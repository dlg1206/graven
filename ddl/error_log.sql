# Util error log table during data generation
CREATE TABLE IF NOT EXISTS error_log
(
    error_id      INTEGER AUTO_INCREMENT PRIMARY KEY,
    timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stage         CHAR(5),
    url           VARCHAR(255),
    error_type    VARCHAR(255),
    error_message VARCHAR(255),
    comment       VARCHAR(255),
    details       JSON
);