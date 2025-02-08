"""
File: tables.py

Description: Abstract collection of tables in the breadcrumbs database

@author Derek Garcia
"""
from enum import Enum


class Table(Enum):
    """
    Generic table to be expanded on by implementations
    """


class JoinTable(Table):
    """
    Generic join table to be expanded on by implementations
    """


class Data(Table):
    """
    Tables that hold data
    """
    CVE = "cve"
    CWE = "cwe"
    JAR = "jar"
    ERROR_LOG = "error_log"


class Association(JoinTable):
    """
    Tables that associate data
    """
    CVE__CWE = "cve_cwe"
    JAR__CVE = "jar_cve"
