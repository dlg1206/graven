import os
from datetime import datetime
from enum import Enum
from typing import List, Tuple, Any, Dict

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

    #
    # CRUD methods
    #

    def _insert(self, table: TableEnum, inserts: Dict[str, str | int | datetime],
                on_success_msg: str = None) -> int | None:
        """
        Generic insert into the database

        :param table: Table to insert into
        :param inserts: Values to insert (column, value)
        :param on_success_msg: Optional debug message to print on success (default: nothing)
        :return: Autoincrement id of inserted row if used, else None
        """
        # build sql
        columns = list(inserts.keys())
        columns_sql = f"({', '.join(columns)})"
        params_sql = f"({', '.join([f":{col}" for col in columns])})"
        sql = f"INSERT INTO {table.value} {columns_sql} VALUES {params_sql}"
        # exe sql
        try:
            # begin handles commit and rollback
            with self._engine.begin() as conn:
                result = conn.execute(text(sql), inserts)
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
                where_equals: Dict[str, str | int | datetime] = None, fetch_all: bool = True) -> List[Tuple[Any]]:
        """
        Generic select from the database

        :param table: Table to select from
        :param columns: optional column names to insert into (default: *)
        :param where_equals: optional where equals clause (column, value)
        :param fetch_all: Fetch all rows, fetch one if false. Useful if checking to table contains value (Default: True)
        """
        # build SQL
        columns_names = f"{', '.join(columns)}" if columns else '*'  # c1, ..., cN
        sql = f"SELECT {columns_names} FROM {table.value}"
        # add where clauses if given
        if where_equals:
            where_clause = ' AND '.join([f"{clause} = :{clause}" for clause in where_equals.keys()])
            sql += f" WHERE {where_clause}"

        # connect is simple
        with self._engine.connect() as conn:
            result = conn.execute(text(sql), where_equals if where_equals else {})
            if fetch_all:
                rows = result.fetchall()
            else:
                rows = result.fetchone()

        # convert to tuples if response, else return nothing
        return [tuple(row) for row in rows] if rows else []

    def _update(self, table: TableEnum, updates: Dict[str, str | int | datetime],
                where_equals: Dict[str, str | int | datetime] = None,
                on_success: str = None, amend: bool = False) -> bool:
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
            set_clause = ', '.join(f"{col} = {col} || :set_{col}" for col in updates.keys())
        else:
            set_clause = ', '.join(f"{col} = :set_{col}" for col in updates.keys())

        sql = f"UPDATE {table.value} SET {set_clause}"
        params = {f"set_{col}": val for col, val in updates.items()}

        # add where clauses if given
        if where_equals:
            where_clause = ' AND '.join(f"{col} = :where_{col}" for col in where_equals.keys())
            sql += f" WHERE {where_clause}"
            params.update({f"where_{col}": val for col, val in where_equals.items()})
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

    def _upsert(self, table: TableEnum, primary_keys: Dict[str, str | int | datetime],
                updates: Dict[str, str | int | datetime],
                print_on_success: bool = False) -> None:
        """
        Generic upsert to the database

        :param table: Table to select from
        :param primary_keys: Primary key(s) to update (column, value)
        :param updates: list of updates to the table (column, value)
        :param print_on_success: Print debug message on success (default: False)
        """
        # attempt to update
        msg = None
        if print_on_success:
            msg = ", ".join([f"{k} '{v}'" for k, v in primary_keys.items()])
        updated = self._update(table, updates,
                               where_equals=primary_keys,
                               on_success=f"Updated {msg}" if print_on_success else None,
                               amend=False)
        if not updated:
            # if fail, insert
            updates.update(primary_keys)
            self._insert(table, updates, on_success_msg=f"Inserted {msg}" if print_on_success else None)
