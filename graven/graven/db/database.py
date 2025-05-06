import os
from enum import Enum
from typing import List, Tuple, Any

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, OperationalError

from shared.logger import logger

"""
File: database.py
Description: MySQL database interface for handling cve data
@author Derek Garcia
"""

DEFAULT_POOL_SIZE = 10
MAX_OVERFLOW_RATIO = 2  # default 200% of pool size


class TableEnum(Enum):
    """
    Shared parent table enumb
    """


class Table(TableEnum):
    """
    Tables that hold data
    """
    CVE = "cve"
    CWE = "cwe"
    JAR = "jar"
    SBOM = "sbom"
    ARTIFACT = "artifact"
    DOMAIN = "domain"
    ERROR_LOG = "error_log"
    RUN_LOG = "run_log"


class JoinTable(TableEnum):
    """
    Tables that associate data
    """
    CVE__CWE = "cve__cwe"
    JAR__CVE = "jar__cve"
    SBOM__ARTIFACT = "sbom__artifact"


class MySQLDatabase:
    """
    Generic interface for accessing a SQL Database
    """

    def __init__(self, pool_size: int = DEFAULT_POOL_SIZE):
        """
        Create MySQL interface and connection pool to use. Uses environment variables for credentials

        :param pool_size: Size of connection pool to create
        """
        db_config = {
            "user": os.getenv("MYSQL_USER"),
            "password": os.getenv("MYSQL_PASSWORD"),
            "host": os.getenv("MYSQL_HOST"),
            "port": int(os.getenv("EXTERNAL_PORT")),
            "database": os.getenv("MYSQL_DATABASE"),
        }

        self._engine = create_engine(
            "mysql+mysqlconnector://{user}:{password}@{host}:{port}/{database}".format(**db_config),
            pool_size=pool_size,
            max_overflow=pool_size * MAX_OVERFLOW_RATIO
        )

    def _insert(self, table: TableEnum, inserts: List[Tuple[str, Any]], on_success_msg: str = None) -> int | None:
        """
        Generic insert into the database

        :param table: Table to insert into
        :param inserts: Values to insert (column, value)
        :param on_success_msg: Optional debug message to print on success (default: nothing)
        :return: Autoincrement id of inserted row if used, else None
        """
        # pre-process input
        # todo - use dicts instead of lists
        columns, values = zip(*inserts)
        columns = list(columns)
        values = list(values)

        # build named parameter dictionary
        param_names = [f":{col}" for col in columns]
        param_dict = {col: val for col, val in zip(columns, values)}
        # build sql
        columns_sql = f"({', '.join(columns)})"
        params_sql = f"({', '.join(param_names)})"
        sql = f"INSERT INTO {table.value} {columns_sql} VALUES {params_sql}"
        # exe sql
        try:
            # begin handles commit and rollback
            with self._engine.begin() as conn:
                result = conn.execute(text(sql), param_dict)
                # print success message if given one
                if on_success_msg:
                    logger.debug_msg(on_success_msg)
                # return auto incremented id if used
                return result.lastrowid
        except IntegrityError as ie:
            # duplicate entry
            # logger.debug_msg(f"{ie.errno} | {table.value} | ({', '.join(values)})") # disabled b/c annoying
            pass
        except OperationalError as oe:
            # failed to insert
            logger.error_exp(oe)
            return None

    def _select(self, table: TableEnum, columns: List[str] = None,
                where_equals: List[Tuple[str, Any]] = None) \
            -> List[Tuple[Any]]:
        """
        Generic select from the database

        :param table: Table to select from
        :param columns: optional column names to insert into (default: *)
        :param where_equals: optional where equals clause (column, value)
        """
        # build SQL
        columns_names = f"{', '.join(columns)}" if columns else '*'  # c1, ..., cN
        sql = f"SELECT {columns_names} FROM {table.value}"
        # add where clauses if given
        if where_equals:
            sql += ' WHERE ' + ' AND '.join(
                [f"{clause[0]} = :{clause[0]}" for clause in where_equals]
            )
            params = {clause[0]: clause[1] for clause in where_equals}
        else:
            params = {}
        # execute with where params if present
        params = {clause[0]: clause[1] for clause in where_equals} if where_equals else {}
        # connect is simple
        with self._engine.connect() as conn:
            rows = conn.execute(text(sql), params).fetchall()
        # convert to tuples
        return [tuple(row) for row in rows]

    def _update(self, table: TableEnum, updates: List[Tuple[str, Any]],
                where_equals: List[Tuple[str, Any]] = None, on_success: str = None, amend: bool = False) -> bool:
        """
        Generic update from the database

        :param table: Table to select from
        :param updates: list of updates to the table (column, value)
        :param where_equals: optional where equals clause (column, value)
        :param on_success: Optional debug message to print on success (default: nothing)
        :param amend: Amend to row instead of replacing (default: False)
        :return: True if update, false otherwise
        """
        # build SQL
        if amend:
            set_clause = ', '.join(f"{col} = {col} || :set_{col}" for col, _ in updates)
        else:
            set_clause = ', '.join(f"{col} = :set_{col}" for col, _ in updates)

        sql = f"UPDATE {table.value} SET {set_clause}"
        params = {f"set_{col}": val for col, val in updates}

        # add where clauses if given
        if where_equals:
            where_clause = ' AND '.join(f"{col} = :where_{col}" for col, _ in where_equals)
            sql += f" WHERE {where_clause}"
            params.update({f"where_{col}": val for col, val in where_equals})
        # execute
        try:
            with self._engine.begin() as conn:
                # execute with where params if present
                result = conn.execute(text(sql), params)
                # print success message if given one
                if result.rowcount > 0 and on_success:
                    logger.debug_msg(on_success)
                return result.rowcount > 0  # rows changed
        except OperationalError as oe:
            # failed to update
            logger.error_exp(oe)
            return False

    def _upsert(self, table: TableEnum, primary_key: List[Tuple[str, Any]], updates: List[Tuple[str, Any]],
                print_on_success: bool = True) -> None:
        """
        Generic upsert to the database

        :param table: Table to select from
        :param primary_key: Primary key to update (column, value)
        :param updates: list of updates to the table (column, value)
        :param print_on_success: Print debug message on success (default: True)
        """
        # attempt to update
        msg = None
        if print_on_success:
            msg = ", ".join([f"{pk[0]} '{pk[1]}'" for pk in primary_key])
        if not self._update(table, updates,
                            where_equals=primary_key,
                            on_success=f"Updated {msg}" if print_on_success else None,
                            amend=False):
            # if fail, insert
            updates += primary_key
            self._insert(table, updates,
                         on_success_msg=f"Inserted {msg}" if print_on_success else None)
