import os
import platform
import subprocess
import time

from logger import logger

"""
File: syft.py
Description: Interface for interacting with the Syft binary

@author Derek Garcia
"""

SYFT_BIN = "syft.exe" if platform.system() == "Windows" else "syft"


class SyftScanFailure(RuntimeError):
    def __init__(self, file_name: str, stderr: str):
        """
        Create new scan failure

        :param file_name: Name of file scanned
        :param stderr: syft stderr output
        """
        super().__init__(f"syft scan failed for {file_name}")
        self.file_name = file_name
        self.stderr = stderr


class Syft:
    def __init__(self, bin_path: str = SYFT_BIN):
        """
        Create new syft interface

        :param bin_path: Path to syft bin (Default: assume on path or in pwd)
        """
        self._bin_path = bin_path
        self._verify_syft_installation()
        # ensure auto updates are off
        os.environ["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
        # ensure just using jar scanner
        os.environ["SYFT_DEFAULT_CATALOGERS"] = "java-archive-cataloger"

    def _verify_syft_installation(self) -> None:
        """
        Check that grype is installed

        :raises FileNotFoundError: if syft is not present
        """
        try:
            version = self.get_version()
        except subprocess.CalledProcessError:
            raise FileNotFoundError("Could not find syft binary; is it on the path or in pwd?")
        logger.info(f"Using syft {version}")

    def scan(self, jar_path: str, out_path: str) -> int:
        """
        Scan jar and save sbom to file

        :param jar_path: Path to jar to scan
        :param out_path: Path to save JSON result to
        :raises SyftScanFailure: If syft fails to scan
        :return: Return code of the operation
        """
        start_time = time.time()
        result = subprocess.run([self._bin_path, f"-o json={out_path}", jar_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        # non-zero, non-one error
        if result.returncode:
            raise SyftScanFailure(jar_path, result.stderr.decode())
        logger.debug_msg(f"Scanned {jar_path} in {time.time() - start_time:.2f}s")
        return result.returncode

    def get_version(self) -> str:
        """
        Check the version of syft

        :return: syft version
        """
        result = subprocess.run(
            f"{self._bin_path} --version",
            shell=True,
            capture_output=True,  # Capture stdout & stderr
            text=True,  # Return output as string
            check=True  # Raise error if command fails
        )
        return result.stdout.strip().removeprefix("syft ")
