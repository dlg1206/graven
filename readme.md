# Graven

> Graven (grype + maven) is a recursive and optimized crawler for scraping
> the [Maven Central Repository](https://repo1.maven.org/maven2).

Graven 2.0 introduces three additional workers into the pipeline, while existing workers have been specialized:

- Crawler: Recursive Maven Central crawler that parses file trees looking for jars to download

- Downloader: Mass downloader for jars from Maven Central

- Generator: Use `syft` to scan the downloaded jars to generate SBOMs

- Scanner: Use `grype` to scan the generated SBOMs for CVEs

- Analyzer: Parse the `syft` and `grype` reports and save vulnerability information into the database

Adjacent to the main pipeline, there is an additional NVD & MITRE module that add additional vulnerability information
in realtime.

### Table of Contents

- [Starting the Database](#starting-the-database)
- [Launching Graven (Docker: RECOMMENDED)](#graven-quickstart)
- [Local Deployment](#local-deployment)
- [Usage](#usage)

## Starting the Database

The [compose file](compose.yaml) will create a volume so the database contents will persist between launches

1. Create an `.env` file
   Creating an `.env` file in this directory and copy the values below. Set any `<...-here>` with your credentials:

```
# connection details
MYSQL_HOST=localhost
MYSQL_DATABASE=<db-name-here>
EXTERNAL_PORT=3306
# user details
MYSQL_ROOT_PASSWORD=<root-pw-here>
MYSQL_USER=<username-here>
MYSQL_PASSWORD=<user-pw-here>
# optional NVD API Key
NVD_API_KEY=<your-key-here>
```

2. Launch the database

```bash
docker compose -p "graven_database" up -d
```

Remove `-d` if you want to see the logs

To access the database, run

```bash
docker exec -it graven_database mysql -u <name set for MYSQL_USER> -p <db set for MYSQL_DATABASE>
```

and enter the `MYSQL_PASSWORD` set in the `.env` file when prompted.

For external connections, the database will be hosted at `localhost:3306`

## Graven Quickstart

1. Build the graven image

```bash
docker build -t graven:2.2.1 .
```

2. Run the container attached to the database network

```bash
docker run --rm -it --env-file .env \
    -e MYSQL_HOST=mysql \
    -v grype_db:/home/graven/.cache/grype \
    --network=graven_database_graven graven:2.2.1 run --root-url <start-url>
```

- `--rm`: remove container when finished
- `-it`: open an interactive terminal (so can see logs)
- `--env-file <path/to/.env>`: .env file to use, same one as for the database
- `-e MYSQL_HOST=mysql`: Set the MYSQL_HOST to `mysql` (name of database service) since database not running on
  localhost inside the container
- `-v grype_db:/home/graven/.cache/grype`: Create a cached volume for the grype security database, so it doesn't need
  to download everytime a new container is launched
- `--network=graven_database_graven`: Attach to the same network the database is running on
- `graven`: Name of image
- `--root-url <start-url>`: Root url to start parsing from

If using the `--seed-urls-csv` flag, you will also need to mount the directory containing the csv file like so:

```bash
docker run --rm -it --env-file .env \
    -e MYSQL_HOST=mysql \
    -v grype_db:/home/graven/.cache/grype \
    -v "<path-to-csv-dir>:/csv" \
    --network=graven_database_graven graven:2.2.1 run --seed-urls-csv /csv/<your csv file>
```

On first run, the grype database will take 1-3 minutes to initialize. If you want to setup the grype database before
running graven, you can do so with the following docker command:

```bash
docker run --rm -it -v grype_db:/home/graven/.cache/grype --entrypoint ash graven -c "grype db update"
```

## Local Deployment

### Pre-req: Installing Anchore tools

Graven uses [syft](https://github.com/anchore/syft) and [grype](https://github.com/anchore/grype) to generate SBOMs and
scan for CVEs.

For Linux:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

For Windows: Go to the [releases](https://github.com/anchore/grype/releases) page and download the latest version.

Either place the path to the binary on the PATH or use the `--syft-path` and `--grype-path` arguments respectively to
use an absolute path.

### Deployment

1. Create venv

```bash
python -m venv venv 
```

2. Activate venv

```bash
. venv/bin/activate 
```

3. Install dependencies

```bash
pip install -r graven/requirements.txt
```

## Usage

```
usage: graven [-h] [-l <log level>] [-s]
              {run,crawl,process,update-vuln,export} ...

Recursive and optimized crawler for scraping the Maven Central Repository

positional arguments:
  {run,crawl,process,update-vuln,export}
    run                 Run the entire graven pipeline
    crawl               Crawl Maven Central for jars
    process             Process jars stored in the database
    update-vuln         Update CVE and CWE data
    export              Export SBOMs in the database to file

options:
  -h, --help            show this help message and exit
  -l <log level>, --log-level <log level>
                        Set log level (Default: INFO) (['INFO', 'DEBUG',
                        'ERROR'])
  -s, --silent          Run in silent mode
```

### run

```
usage: graven run [-h]
                  (--root-url <starting url> | --seed-urls-csv <path to csv>)
                  [--update-domain] [--update-jar] [-u]
                  [--download-cache-size <cache size in MB>]
                  [--jar-limit <max jar count>]
                  [--syft-path <absolute path to syft binary>]
                  [--syft-cache-size <cache size in MB>] [--disable-syft]
                  [--grype-path <absolute path to grype binary>]
                  [--grype-db-source <url of grype database to use>]
                  [--grype-cache-size <cache size in MB>]
                  [--max-concurrent-maven-requests <number of requests>]
                  [--max-cpu-threads <number of the threads>]
                  [--disable-update-vuln]

Run the entire graven pipeline

options:
  -h, --help            show this help message and exit

Input Options:
  Only one flag is permitted

  --root-url <starting url>
                        Root URL to start crawler at
  --seed-urls-csv <path to csv>
                        CSV file of root urls to restart the crawler at once
                        the current root url is exhausted

Crawler Options:
  --update-domain       Update domains that have already been crawled. Useful
                        for ensuring no jars were missed in a domain
  --update-jar          Update jars that have already been crawled
  -u, --update          Update domains AND jars that have already been
                        crawled. Supersedes --update-* flags

Downloader Options:
  --download-cache-size <cache size in MB>
                        Limit of the number of jars to be saved at one time.
                        (Default: 5120.0 MB)
  --jar-limit <max jar count>
                        Limit the number of jars downloaded at once

Generator Options:
  --syft-path <absolute path to syft binary>
                        Path to syft binary to use. By default, assumes syft
                        is already on the PATH
  --syft-cache-size <cache size in MB>
                        Limit of the number of grype files to be saved at one
                        time. (Default: 5120.0 MB)
  --disable-syft        Disable SBOM generation and scan jars directly

Scanner Options:
  --grype-path <absolute path to grype binary>
                        Path to Grype binary to use. By default, assumes grype
                        is already on the PATH
  --grype-db-source <url of grype database to use>
                        URL of specific grype database to use. To see the full
                        list, run 'grype db list'
  --grype-cache-size <cache size in MB>
                        Limit of the number of grype files to be saved at one
                        time. (Default: 5120.0 MB)

Miscellaneous Options:
  --max-concurrent-maven-requests <number of requests>
                        Max number of requests can make at once to Maven
                        Central. (Default: 100)
  --max-cpu-threads <number of the threads>
                        Max number of threads allowed to be used to generate
                        anchore results. Increase with caution (Default: 8)
  --disable-update-vuln
                        Disable real-time queries for CVE and CWE details
```

### crawl

```
usage: graven crawl [-h]
                    (--root-url <starting url> | --seed-urls-csv <path to csv>)
                    [--update-domain] [--update-jar] [-u]
                    [--max-concurrent-maven-requests <number of requests>]

Crawl Maven Central for jars

options:
  -h, --help            show this help message and exit

Input Options:
  Only one flag is permitted

  --root-url <starting url>
                        Root URL to start crawler at
  --seed-urls-csv <path to csv>
                        CSV file of root urls to restart the crawler at once
                        the current root url is exhausted

Crawler Options:
  --update-domain       Update domains that have already been crawled. Useful
                        for ensuring no jars were missed in a domain
  --update-jar          Update jars that have already been crawled
  -u, --update          Update domains AND jars that have already been
                        crawled. Supersedes --update-* flags

Miscellaneous Options:
  --max-concurrent-maven-requests <number of requests>
                        Max number of requests can make at once to Maven
                        Central. (Default: 100)
```

### process

```
usage: graven process [-h] [--download-cache-size <cache size in MB>]
                      [--jar-limit <max jar count>]
                      [--syft-path <absolute path to syft binary>]
                      [--syft-cache-size <cache size in MB>] [--disable-syft]
                      [--grype-path <absolute path to grype binary>]
                      [--grype-db-source <url of grype database to use>]
                      [--grype-cache-size <cache size in MB>]
                      [--max-concurrent-maven-requests <number of requests>]
                      [--max-cpu-threads <number of the threads>]
                      [--enable-update-vuln]

Process jars stored in the database

options:
  -h, --help            show this help message and exit

Downloader Options:
  --download-cache-size <cache size in MB>
                        Limit of the number of jars to be saved at one time.
                        (Default: 5120.0 MB)
  --jar-limit <max jar count>
                        Limit the number of jars downloaded at once

Generator Options:
  --syft-path <absolute path to syft binary>
                        Path to syft binary to use. By default, assumes syft
                        is already on the PATH
  --syft-cache-size <cache size in MB>
                        Limit of the number of grype files to be saved at one
                        time. (Default: 5120.0 MB)
  --disable-syft        Disable SBOM generation and scan jars directly

Scanner Options:
  --grype-path <absolute path to grype binary>
                        Path to Grype binary to use. By default, assumes grype
                        is already on the PATH
  --grype-db-source <url of grype database to use>
                        URL of specific grype database to use. To see the full
                        list, run 'grype db list'
  --grype-cache-size <cache size in MB>
                        Limit of the number of grype files to be saved at one
                        time. (Default: 5120.0 MB)

Miscellaneous Options:
  --max-concurrent-maven-requests <number of requests>
                        Max number of requests can make at once to Maven
                        Central. (Default: 100)
  --max-cpu-threads <number of the threads>
                        Max number of threads allowed to be used to generate
                        anchore results. Increase with caution (Default: cpu corse)
  --enable-update-vuln  Enable real-time queries for CVE and CWE details
```

### update-vuln

```
usage: graven update-vuln [-h]

Update CVE and CWE data. Will use 'NVD_API_KEY' env variable if available

options:
  -h, --help  show this help message and exit
```

### export

```
usage: graven export [-h] -d DIRECTORY -c {zip,tar.gz}

Export SBOMs in the database to file

options:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Directory to save dump to
  -c {zip,tar.gz}, --compression-method {zip,tar.gz}
                        Compression mode to export data to
```