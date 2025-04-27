# Table for tracking domains that have been seen
CREATE TABLE IF NOT EXISTS domain
(
    url         VARCHAR(255) PRIMARY KEY,
    crawl_start TIMESTAMP,
    crawl_end   TIMESTAMP,
    run_id      INTEGER,
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);