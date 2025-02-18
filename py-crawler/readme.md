# Graven

> Graven (grype + maven) is a recursive and optimized crawler for scraping
> the [Maven Central Repository](https://repo1.maven.org/maven2).

> [!NOTE]  
> Make sure the database is running before running graven

## Local Deployment

### Pre-req: Installing grype

Graven uses [grype](https://github.com/anchore/grype) to scan jars for CVEs.

For Linux:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

For Windows: Go to the [releases](https://github.com/anchore/grype/releases) page and download the latest version.

Either place the path to the binary on the PATH or use the `--grype-path` argument to use an absolute path.

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
pip install -r requirements.txt
```

### Usage

> [!WARNING]  
> By default, graven uses all CPU cores available, ie it will make your computer make funny noises. Use
> the `--analyzer-threads` flag to reduce the number of threads if it becomes an issue

```
python3 graven -h

usage: graven [-h] [-l <log level>] [-s] [--root-url <starting url>]
              [--seed-urls-csv <path to csv>] [-u]
              [--crawler-retries <number of retries>]
              [--crawler-requests <number of requests>]
              [--downloader-requests <number of requests>]
              [--jar-limit <number of jars>]
              [--analyzer-threads <number of the threads>]
              [--grype-path <absolute path to grype binary>]
              [--grype-db-source <url of grype database to use>]

Recursive and optimized crawler for scraping the Maven Central Repository

options:
  -h, --help            show this help message and exit
  -l <log level>, --log-level <log level>
                        Set log level (Default: INFO) (['INFO', 'DEBUG',
                        'ERROR'])
  -s, --silent          Run in silent mode
  --root-url <starting url>
                        Root URL to start crawler at
  --seed-urls-csv <path to csv>
                        CSV file of root urls to restart the crawler at once
                        the current root url is exhausted
  -u, --update          Download jar and scan even if already in the database

Crawler Options:
  --crawler-retries <number of retries>
                        Max number of times to attempt to pop from the crawl
                        queue before quitting (Default: 3)
  --crawler-requests <number of requests>
                        Max number of requests crawler can make at once
                        (Default: number of cores)

Downloader Options:
  --downloader-requests <number of requests>
                        Max number of downloads downloader can make at once
                        (Default: number of cores)
  --jar-limit <number of jars>
                        Max number of jars allowed to be to downloaded local
                        at once (Default: 100)

Analyzer Options:
  --analyzer-threads <number of the threads>
                        Max number of threads allowed to be used to scan jars.
                        Increase with caution (Default: number of cores)
  --grype-path <absolute path to grype binary>
                        Path to Grype binary to use. By default, assumes grype
                        is already on the PATH
  --grype-db-source <url of grype database to use>
                        URL of specific grype database to use. To see the full
                        list, run 'grype db list'
```