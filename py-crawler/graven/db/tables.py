"""
File: tables.py

Description: Abstract collection of tables in the breadcrumbs database

@author Derek Garcia
"""

from db.database import Table, JoinTable


class Data(Table):
    """
    Tables that hold data
    """
    CVE = "cve"
    CWE = "cwe"
    JAR = "jar"
    ERROR_LOG = "error_log"
    DOMAIN = "domain"


class Association(JoinTable):
    """
    Tables that associate data
    """
    CVE__CWE = "cve__cwe"
    JAR__CVE = "jar__cve"
