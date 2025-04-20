# Graven

> Graven (grype + maven) is a recursive and optimized crawler for scraping
> the [Maven Central Repository](https://repo1.maven.org/maven2).

Graven 2.0 introduces three additional workers into the pipeline, while existing workers have been specialized:

- Crawler: Recursive Maven Central crawler that parses file trees looking for jars to download

- Downloader: Mass downloader for jars from Maven Central

- Generator: Use `syft` to scan the downloaded jars to generate SBOMs

- Scanner: Use `grype` to scan the generated SBOMs for CVEs

- Analyzer: Parse the `syft` and `grype` reports and save vulnerability, artifact, and dependency information into the
  database

Adjacent to the main pipeline, there is an additional NVD & MITRE module that add additional vulnerability information
in realtime

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

### Local Deployment

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
> the `--max-*-threads` flags to reduce the number of threads if it becomes an issue

```
python graven -h

usage: graven [-h] [-l <log level>] [-s]
              (--root-url <starting url> | --seed-urls-csv <path to csv>)
              [--max-concurrent-crawl-requests <number of requests>]
              [--no-skip-domain] [--no-skip-jar] [--no-skip]
              [--max-concurrent-download-requests <number of requests>]
              [--download-limit <number of jars>]
              [--max-generator-threads <number of the threads>]
              [--syft-path <absolute path to syft binary>]
              [--max-scanner-threads <number of the threads>]
              [--grype-path <absolute path to grype binary>]
              [--grype-db-source <url of grype database to use>]
              [--max-analyzer-threads <number of the threads>]

Recursive and optimized crawler for scraping the Maven Central Repository

options:
  -h, --help            show this help message and exit
  -l <log level>, --log-level <log level>
                        Set log level (Default: INFO) (['INFO', 'DEBUG',
                        'ERROR'])
  -s, --silent          Run in silent mode

Input Options:
  Only one flag is permitted

  --root-url <starting url>
                        Root URL to start crawler at
  --seed-urls-csv <path to csv>
                        CSV file of root urls to restart the crawler at once
                        the current root url is exhausted

Crawler Options:
  --max-concurrent-crawl-requests <number of requests>
                        Max number of requests crawler can make at once
                        (Default: 8)
  --update-domain       Update domains that have already been crawled. Useful
                        for ensuring no jars were missed in a domain
  --update-jar          Update jars that have already been crawled
  -u, --update          Update domains AND jars that have already been
                        crawled. Supersedes --update-* flags

Downloader Options:
  --max-concurrent-download-requests <number of requests>
                        Max number of downloads downloader can make at once
                        (Default: 8)
  --download-limit <number of jars>
                        Max number of jars allowed to be to downloaded local
                        at once (Default: 100)

Generator Options:
  --max-generator-threads <number of the threads>
                        Max number of threads allowed to be used to generate
                        sboms. Increase with caution
  --syft-path <absolute path to syft binary>
                        Path to syft binary to use. By default, assumes syft
                        is already on the PATH

Scanner Options:
  --max-scanner-threads <number of the threads>
                        Max number of threads allowed to be used to scan
                        SBOMs. Increase with caution
  --grype-path <absolute path to grype binary>
                        Path to Grype binary to use. By default, assumes grype
                        is already on the PATH
  --grype-db-source <url of grype database to use>
                        URL of specific grype database to use. To see the full
                        list, run 'grype db list'

Analyzer Options:
  --max-analyzer-threads <number of the threads>
                        Max number of threads allowed to be used to parse and
                        upload Anchore results. Increase with caution
```