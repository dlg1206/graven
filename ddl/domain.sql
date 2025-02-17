# Table for tracking domains that have been seen
CREATE TABLE IF NOT EXISTS domain
(
    url          VARCHAR(255) PRIMARY KEY,
    last_crawled TIMESTAMP
);