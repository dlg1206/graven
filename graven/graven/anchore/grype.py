"""
File: grype.py
Description: Interface for interacting with the Grype binary

@author Derek Garcia
"""

import hashlib
import os
import platform
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import requests
import yaml

from shared.logger import logger
from shared.timer import Timer

GRYPE_BIN = "grype.exe" if platform.system() == "Windows" else "grype"
DB_SOURCE_FILE = "db_source"

GRYPE_TIMEOUT = 120  # 2 minute timeout


class GrypeScanFailure(RuntimeError):
    """
    Failed to scan with grype
    """

    def __init__(self, file_name: str, return_code: int, stderr: str = None):
        """
        Create new scan failure

        :param file_name: Name of file scanned
        :param stderr: grype stderr output
        :param stderr: optional grype stderr output
        """
        super().__init__(f"grype scan failed for {file_name}")
        self.file_name = file_name
        self.return_code = return_code
        self.stderr = stderr


class GrypeDatabaseInstallFailure(RuntimeError):
    """
    Failed to install grype database
    """

    def __init__(self, grype_db_url: str, error_code: int, stderr: str):
        """
        Create new installation failure

        :param grype_db_url: URL of database attempted to install
        """
        super().__init__(f"{error_code} | Failed to install '{grype_db_url}' | {stderr}")


class Grype:
    """
    Grype scanner
    """

    def __init__(self, bin_path: str = GRYPE_BIN, check_for_updates: bool = True, db_source_url: str = None):
        """
        Create new grype interface

        :param bin_path: Path to grype bin (Default: assume on path or in pwd)
        :param check_for_updates: Check grype db for updates (Default: true)
        :param db_source_url:
            Source url of specific grype database to use.
            If defined, database will not be updated
        """
        self._bin_path = bin_path
        self._db_source_url = db_source_url
        self._verify_grype_installation()
        # ensure auto updates are off
        os.environ["GRYPE_DB_AUTO_UPDATE"] = "false"
        os.environ["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
        # use java cpes
        os.environ["GRYPE_MATCH_STOCK_USING_CPES"] = "false"
        os.environ["GRYPE_MATCH_JAVA_USING_CPES"] = "true"

        # install requested db if not match
        if db_source_url and not self._cache_match_url():
            try:
                self._install_grype_db()
            except Exception as e:
                logger.fatal(e)
        # else download updates if requested
        if not db_source_url and check_for_updates:
            self._update_grype_db()

    def _verify_grype_installation(self) -> None:
        """
        Check that grype is installed

        :raises FileNotFoundError: if grype is not present
        """
        try:
            version = self.get_version()
        except subprocess.CalledProcessError as e:
            raise FileNotFoundError("Could not find grype binary; is it on the path or in pwd?") from e
        logger.info(f"Using grype {version}")

    def _get_grype_cache_dir(self) -> str:
        """
        :return: Path to Grype db cache dir
        """
        result = subprocess.run(
            f"{self._bin_path} config",
            shell=True,
            capture_output=True,  # Capture stdout & stderr
            text=True,  # Return output as string
            check=True  # Raise error if command fails
        )
        cache_dir = yaml.safe_load(result.stdout.strip())['db']['cache-dir']
        return str(Path(cache_dir).expanduser())

    def _cache_match_url(self) -> bool:
        """
        Check if cached hash of the url downloaded database matches the one requested

        :return: True if match, false otherwise
        """
        logger.info("Checking cached database")
        cache_dir = self._get_grype_cache_dir()
        cache_source_file = f"{cache_dir}{os.sep}{DB_SOURCE_FILE}"
        if os.path.exists(cache_source_file):
            with open(cache_source_file, 'r', encoding='utf-8') as f:
                cache_source_hash = f.read().strip()
            # check if already downloaded
            if cache_source_hash == hashlib.sha256(self._db_source_url.encode()).hexdigest():
                logger.info(f"'{self._db_source_url}' already downloaded")
                return True
            logger.warn("Cached source does not match requested url")
        else:
            logger.warn("No cached source to check")
        return False

    def _install_grype_db(self) -> None:
        """
        Download database to use from url
        """

        logger.info(f"Downloading grype database, this may take a few minutes | {self._db_source_url}")
        with TemporaryDirectory() as tmp_dir:
            grype_db_file = self._db_source_url.split('/')[-1].replace(':', '_')
            grype_db_tarball = f"{tmp_dir}{os.sep}{grype_db_file}"
            # download tarball
            with requests.get(self._db_source_url, timeout=999) as response:
                response.raise_for_status()
                with open(grype_db_tarball, "wb") as file:
                    file.write(response.content)
            # install db
            logger.info("Downloaded grype database. Installing database. . .")
            result = subprocess.run([self._bin_path, "db", "import", grype_db_tarball],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE,
                                    encoding='utf-8',
                                    check=False)
            if result.returncode:
                raise GrypeDatabaseInstallFailure(self._db_source_url, result.returncode, result.stderr)
        logger.info("Installed database")

        # cache download
        cache_source_file = f"{self._get_grype_cache_dir()}{os.sep}{DB_SOURCE_FILE}"
        with open(cache_source_file, 'w', encoding='utf-8') as f:
            f.write(hashlib.sha256(self._db_source_url.encode('utf-8')).hexdigest())

    def _update_grype_db(self) -> None:
        """
        Update local grype db if needed
        """
        logger.info("Checking grype database status. . .")
        db_status = subprocess.run([self._bin_path, "db", "check"],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL,
                                   check=False).returncode
        if db_status:
            start_time = time.time()
            logger.warn("grype database needs to be updated!")
            logger.warn(
                "THIS MAY TAKE A FEW MINUTES, ESPECIALLY IF THIS IS THE FIRST RUN")
            logger.warn(
                "Subsequent runs will be faster (only if using cached volume if using docker)")
            result = subprocess.run([self._bin_path, "db", "update"],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE,
                                    encoding='utf-8',
                                    check=False)
            if result.returncode:
                raise GrypeDatabaseInstallFailure("latest", result.returncode, result.stderr)
            logger.info(f"Updated grype vulnerability database in {time.time() - start_time:.2f} seconds")

            # remove the cached source if it exists
            cache_source_file = f"{self._get_grype_cache_dir()}{os.sep}{DB_SOURCE_FILE}"
            if os.path.exists(cache_source_file):
                os.remove(cache_source_file)
                logger.debug_msg("Removed cached source url")

        logger.info("grype database is up to date")

    def scan(self, file_path: str, out_path: str) -> int:
        """
        Scan jar or sbom and save results to file

        :param file_path: Path to jar or sbom to scan
        :param out_path: Path to save JSON result to
        :raises GrypeScanFailure: If grype fails to scan
        :raises TimeoutExpired: If the grype scan exceeds max timeout
        :return: Return code of the operation
        """
        timer = Timer(True)
        result = subprocess.run([self._bin_path, "--by-cve", "-o", f"json={out_path}", file_path],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE,
                                check=False,
                                timeout=GRYPE_TIMEOUT)
        # non-zero error
        if result.returncode:
            raise GrypeScanFailure(file_path, result.returncode, result.stderr.decode())
        logger.debug_msg(f"Scanned in {timer.format_time()}s | {file_path.split(os.sep)[-1]}")
        return result.returncode

    def get_version(self) -> str:
        """
        Check the version of grype

        :return: grype version
        """
        result = subprocess.run(f"{self._bin_path} --version",
                                shell=True,
                                capture_output=True,  # Capture stdout & stderr
                                text=True,  # Return output as string
                                check=True  # Raise error if command fails
                                )
        return result.stdout.strip().removeprefix("grype ")

    @property
    def db_source(self) -> str | None:
        """
        :return: Grype database source
        """
        return self._db_source_url
