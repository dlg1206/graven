# Join table for mapping sboms to artifact contents
# these are of type 'dependency-of' where the child is the jar_id
# ie. parent is 'dependency-of' child / jar_id
CREATE TABLE IF NOT EXISTS sbom__artifact
(
    jar_id  VARCHAR(255), # parent
    purl    VARCHAR(255), # child
    has_pom INTEGER,      # if artifact has a pom in this jar
    run_id  INTEGER,
    PRIMARY KEY (jar_id, purl),
    FOREIGN KEY (jar_id) REFERENCES sbom (jar_id) ON DELETE CASCADE,
    FOREIGN KEY (purl) REFERENCES artifact (purl) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES run_log (run_id)
);