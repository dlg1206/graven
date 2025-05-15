# table for tracking events for debugging
# enqueue: job submitted to thread pool
# dequeue: job was pulled from thread pool
CREATE TABLE IF NOT EXISTS event_log
(
    jar_id            VARCHAR(255) PRIMARY KEY,
    # download
    download_enqueue  DATETIME,
    download_dequeue  DATETIME,
    download_start    DATETIME,
    download_end      DATETIME,
    # generator
    generator_enqueue DATETIME,
    generator_dequeue DATETIME,
    generator_start   DATETIME,
    generator_end     DATETIME,
    # scanner
    scanner_enqueue   DATETIME,
    scanner_dequeue   DATETIME,
    scanner_start     DATETIME,
    scanner_end       DATETIME,
    # analyzer
    analyzer_enqueue  DATETIME,
    analyzer_dequeue  DATETIME,
    analyzer_start    DATETIME,
    analyzer_end      DATETIME,
    FOREIGN KEY (jar_id) REFERENCES jar (jar_id) ON DELETE CASCADE
);