"""
Shared database client for AWS Lambda functions.
"""

import os
import logging
import time
from typing import Dict, List, Optional, Any
import pymysql
from contextlib import contextmanager

from .secrets_helper import get_secret, get_database_credentials
from .error_handler import retry_on_db_error

# Optional PostgreSQL support
try:
    import psycopg2
    import psycopg2.extras

    HAS_POSTGRESQL = True
except ImportError:
    HAS_POSTGRESQL = False

log = logging.getLogger(__name__)

# Connection pool for reuse across invocations
_connection_pool = {}


def _safe_close_connection(connection) -> None:
    """
    Safely close a database connection with proper error handling.

    Args:
        connection: Database connection to close
    """
    if connection and hasattr(connection, "close"):
        # Check if connection is already closed (pymysql specific)
        if hasattr(connection, "_closed") and connection._closed:
            return

        # Check PyMySQL's open flag if available
        if hasattr(connection, "open") and not connection.open:
            return

        try:
            connection.close()
        except (pymysql.MySQLError, OSError) as e:
            log.debug(f"Error closing connection: {e}")


def _clean_expired_connections(pool_key: str, pool_recycle: int) -> None:
    """
    Clean up expired connections from the pool proactively.

    Args:
        pool_key: Pool identifier
        pool_recycle: Maximum age in seconds (0 or None disables recycling)
    """
    if not pool_recycle or pool_recycle <= 0:
        return

    if pool_key not in _connection_pool:
        return

    current_time = time.time()
    pool_entries = _connection_pool[pool_key]

    # Filter out expired connections
    active_entries = []
    expired_count = 0

    for entry in pool_entries:
        age = current_time - entry["timestamp"]
        if age >= pool_recycle:
            # Connection expired, close it safely
            _safe_close_connection(entry["connection"])
            expired_count += 1
        else:
            active_entries.append(entry)

    # Update the pool with only active connections
    _connection_pool[pool_key] = active_entries

    if expired_count > 0:
        log.debug(f"Cleaned {expired_count} expired connections from pool {pool_key}")


def get_pool_stats() -> Dict[str, Any]:
    """
    Get current connection pool statistics.

    Returns:
        Dict with pool status for monitoring
    """
    stats = {"total_pools": len(_connection_pool), "pools": {}}
    current_time = time.time()

    for pool_key, connection_entries in _connection_pool.items():
        stats["pools"][pool_key] = {
            "active_connections": len(connection_entries),
            "healthy_connections": 0,
            "aged_connections": 0,
        }

        # Test health of pooled connections
        healthy = 0
        aged = 0
        for entry in connection_entries:
            conn = entry["connection"]
            timestamp = entry["timestamp"]
            age = current_time - timestamp

            try:
                conn.ping(reconnect=False)
                healthy += 1
            except (pymysql.MySQLError, OSError, AttributeError, Exception):
                # Connection is unhealthy, don't count it
                pass

            # Count connections older than 1 hour as aged (for monitoring)
            if age > 3600:
                aged += 1

        stats["pools"][pool_key]["healthy_connections"] = healthy
        stats["pools"][pool_key]["aged_connections"] = aged

    return stats


class DatabaseClient:
    def __init__(
        self, secret_name: Optional[str] = None, use_pool: bool = True, pool_size: int = 5, pool_recycle: int = 3600
    ):
        """
        Initialize database client with credentials from Secrets Manager.

        Args:
            secret_name: Override default secret name
            use_pool: Enable connection pooling for Lambda reuse
            pool_size: Maximum number of pooled connections
            pool_recycle: Recycle connections after this many seconds
        """
        self.credentials = get_database_credentials(secret_name)
        self.use_pool = use_pool
        self.pool_size = pool_size
        self.pool_recycle = pool_recycle
        self._pool_key = f"{self.credentials['host']}:{self.credentials['port']}"

    @contextmanager
    def get_connection(self, database: Optional[str] = None):
        """
        Context manager for database connections with optional pooling.

        Args:
            database: Override default database

        Yields:
            pymysql connection object
        """
        connection = None
        pool_key = None

        try:
            # Use pooling if enabled and for default database only
            if self.use_pool and not database:
                pool_key = f"{self._pool_key}_{self.credentials.get('database', 'app')}"
                current_time = time.time()

                # Try to get from pool first, checking for expired connections
                if pool_key in _connection_pool:
                    pool_entries = _connection_pool[pool_key]

                    # Look for a fresh, healthy connection
                    while pool_entries:
                        entry = pool_entries.pop()
                        conn = entry["connection"]
                        timestamp = entry["timestamp"]
                        age = current_time - timestamp

                        # Check if connection has exceeded recycle time
                        if self.pool_recycle and self.pool_recycle > 0 and age >= self.pool_recycle:
                            # Connection too old, close it safely and continue looking
                            _safe_close_connection(conn)
                            log.debug(f"Recycled expired connection (age: {age:.1f}s) for {pool_key}")
                            continue

                        # Test if connection is still alive
                        try:
                            conn.ping(reconnect=False)
                            connection = conn
                            log.debug(f"Reused pooled connection (age: {age:.1f}s) for {pool_key}")
                            break
                        except (pymysql.MySQLError, OSError, AttributeError, Exception) as e:
                            # Connection dead, close it safely and continue looking
                            _safe_close_connection(conn)
                            log.debug(f"Closed dead pooled connection for {pool_key}: {e}")
                            conn = None
                            continue

            # Create new connection if no pooled connection available
            if connection is None:
                connection = pymysql.connect(
                    host=self.credentials["host"],
                    port=self.credentials.get("port", 3306),
                    user=self.credentials["username"],
                    password=self.credentials["password"],
                    database=database or self.credentials.get("database", "app"),
                    charset="utf8mb4",
                    cursorclass=pymysql.cursors.DictCursor,
                    connect_timeout=10,
                    read_timeout=30,
                )
                if self.use_pool and not database:
                    log.debug(f"Created new pooled connection for {pool_key}")

            yield connection

        finally:
            if connection:
                # Return to pool if pooling enabled and healthy
                if self.use_pool and not database and pool_key:
                    try:
                        # Test connection health before returning to pool
                        connection.ping(reconnect=False)

                        # Initialize pool for this key if needed
                        if pool_key not in _connection_pool:
                            _connection_pool[pool_key] = []

                        # Clean up expired connections before adding new one
                        _clean_expired_connections(pool_key, self.pool_recycle)

                        # Add back to pool if under limit
                        if len(_connection_pool[pool_key]) < self.pool_size:
                            # Store connection with current timestamp
                            entry = {"connection": connection, "timestamp": time.time()}
                            _connection_pool[pool_key].append(entry)
                            log.debug(
                                f"Returned connection to pool {pool_key} (pool size: {len(_connection_pool[pool_key])})"
                            )
                        else:
                            # Pool full, close connection safely
                            _safe_close_connection(connection)
                            log.debug(f"Pool {pool_key} full, closed connection")
                    except (pymysql.MySQLError, OSError, AttributeError, Exception) as e:
                        # Connection unhealthy, close it safely
                        _safe_close_connection(connection)
                        log.debug(f"Connection unhealthy, closed instead of pooling: {e}")
                        connection = None
                else:
                    # Not using pooling, close immediately
                    _safe_close_connection(connection)

    def query(self, sql: str, params: Optional[tuple] = None, database: Optional[str] = None) -> List[Dict]:
        """
        Execute a SELECT query and return results.

        Args:
            sql: SQL query with %s placeholders
            params: Query parameters
            database: Override default database

        Returns:
            List of result rows as dicts
        """
        try:
            with self.get_connection(database) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql, params)
                    return cursor.fetchall()
        except Exception as e:
            log.error(
                f"Database query error: {e}",
                exc_info=True,
                extra={"sql": sql[:100], "database": database},  # First 100 chars for safety
            )
            return []

    @retry_on_db_error
    def execute(self, sql: str, params: Optional[tuple] = None, database: Optional[str] = None) -> int:
        """
        Execute an INSERT, UPDATE, or DELETE query.

        Args:
            sql: SQL query with %s placeholders
            params: Query parameters
            database: Override default database

        Returns:
            Number of affected rows
        """
        try:
            with self.get_connection(database) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql, params)
                    conn.commit()
                    return cursor.rowcount
        except Exception as e:
            log.error(f"Database execute error: {e}", exc_info=True, extra={"sql": sql[:100], "database": database})
            raise

    def bulk_insert(
        self,
        table: str,
        records: List[Dict],
        database: Optional[str] = None,
        batch_size: int = 1000,
        ignore_duplicates: bool = False,
    ) -> int:
        """
        Bulk insert records into a table.

        Args:
            table: Table name
            records: List of dicts to insert
            database: Override default database
            batch_size: Number of records per batch
            ignore_duplicates: Use INSERT IGNORE

        Returns:
            Total number of inserted rows
        """
        if not records:
            return 0

        # Get column names from first record
        columns = list(records[0].keys())
        placeholders = ", ".join(["%s"] * len(columns))
        columns_str = ", ".join(f"`{col}`" for col in columns)

        insert_cmd = "INSERT IGNORE" if ignore_duplicates else "INSERT"
        sql = f"{insert_cmd} INTO `{table}` ({columns_str}) VALUES ({placeholders})"

        total_inserted = 0

        try:
            with self.get_connection(database) as conn:
                with conn.cursor() as cursor:
                    # Process in batches
                    for i in range(0, len(records), batch_size):
                        batch = records[i : i + batch_size]
                        values = [tuple(record.get(col) for col in columns) for record in batch]

                        cursor.executemany(sql, values)
                        total_inserted += cursor.rowcount

                    conn.commit()

            log.info(f"Bulk inserted {total_inserted} rows into {table}")
            return total_inserted

        except Exception as e:
            log.error(
                f"Bulk insert error: {e}",
                exc_info=True,
                extra={"table": table, "record_count": len(records), "database": database},
            )
            raise

    def get_entity_stats(self, entity_table: str = "entities", user_table: str = "users") -> Dict[str, Any]:
        """
        Get entity statistics from the database.

        Args:
            entity_table: Name of the entity table (default: "entities")
            user_table: Name of the user table (default: "users")

        Returns:
            Dict with entity counts and activity
        """
        # Get active entities
        active_entities = self.query(
            f"""
            SELECT 
                e.id,
                e.name,
                COUNT(DISTINCT u.id) as user_count
            FROM {entity_table} e
            LEFT JOIN {user_table} u ON u.entity_id = e.id
            WHERE e.deleted_at IS NULL OR e.deleted_at = 0
            GROUP BY e.id
            HAVING user_count > 0
            ORDER BY user_count DESC
            LIMIT 20
        """
        )

        # Get total counts
        totals = self.query(
            f"""
            SELECT 
                COUNT(DISTINCT e.id) as total_entities,
                COUNT(DISTINCT CASE WHEN u.id IS NOT NULL THEN e.id END) as active_entities,
                COUNT(DISTINCT u.id) as total_users
            FROM {entity_table} e
            LEFT JOIN {user_table} u ON u.entity_id = e.id
            WHERE e.deleted_at IS NULL OR e.deleted_at = 0
        """
        )

        return {"totals": totals[0] if totals else {}, "top_entities": active_entities}

    def get_record_stats(self, table: str = "records", hours: int = 24, **kwargs) -> Dict[str, Any]:
        """
        Get record statistics for the time period.

        Args:
            table: Table name to query (default: "records")
            hours: Hours to look back
            **kwargs: Additional column mappings (e.g., status_col="status", value_col="amount")

        Returns:
            Dict with record counts and values
        """
        status_col = kwargs.get("status_col", "status")
        value_col = kwargs.get("value_col", "total_value")
        created_col = kwargs.get("created_col", "created_at")

        stats = self.query(
            f"""
            SELECT 
                COUNT(*) as total_records,
                SUM({value_col}) as total_value,
                AVG({value_col}) as avg_value,
                COUNT(CASE WHEN {status_col} = 'confirmed' THEN 1 END) as confirmed_records,
                COUNT(CASE WHEN {status_col} = 'cancelled' THEN 1 END) as cancelled_records
            FROM {table}
            WHERE {created_col} >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        """,
            (hours,),
        )

        return stats[0] if stats else {}


class PostgreSQLClient:
    """PostgreSQL database client for auth database."""

    def __init__(self, secret_name: Optional[str] = None, use_auth_credentials: bool = True):
        """
        Initialize PostgreSQL client with credentials from Secrets Manager.

        Args:
            secret_name: Override default secret name
            use_auth_credentials: Use auth-specific credentials from the secret
        """
        if not HAS_POSTGRESQL:
            raise ImportError("psycopg2 is not installed. Install with: pip install psycopg2-binary")

        # Get the raw secret to preserve auth-specific fields
        secret_name = secret_name or os.environ.get("DB_CREDENTIALS_SECRET")
        if not secret_name:
            raise ValueError("No database secret name provided")

        raw_creds = get_secret(secret_name)

        # Use auth-specific credentials if available
        if use_auth_credentials and "auth_host" in raw_creds:
            self.credentials = {
                "host": raw_creds["auth_host"],
                "port": int(raw_creds.get("auth_port", 5432)),
                "username": raw_creds.get("auth_username"),
                "password": raw_creds.get("auth_password"),
                "database": raw_creds.get("auth_database", "auth-service-db"),
            }
            log.info(f"Using PostgreSQL auth database at {self.credentials['host']}:{self.credentials['port']}")
        else:
            # Fall back to normalized credentials
            self.credentials = get_database_credentials(secret_name)

    @contextmanager
    def get_connection(self, database: Optional[str] = None):
        """
        Context manager for PostgreSQL connections.

        Args:
            database: Override default database

        Yields:
            psycopg2 connection object
        """
        connection = None
        try:
            # PostgreSQL connection parameters
            connect_params = {
                "host": self.credentials["host"],
                "port": self.credentials.get("port", 5432),
                "user": self.credentials["username"],
                "password": self.credentials["password"],
                "database": database or self.credentials.get("database", "postgres"),
                "connect_timeout": 5,
            }

            connection = psycopg2.connect(**connect_params)
            yield connection
        finally:
            if connection:
                connection.close()

    def query(self, sql: str, params: Optional[tuple] = None, database: Optional[str] = None) -> List[Dict]:
        """
        Execute a SELECT query and return results as list of dicts.

        Args:
            sql: SQL query with %s placeholders
            params: Query parameters
            database: Override default database

        Returns:
            List of result rows as dicts
        """
        try:
            with self.get_connection(database) as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                    cursor.execute(sql, params)
                    # Convert DictRow objects to regular dicts
                    return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            log.error(f"PostgreSQL query error: {e}", exc_info=True, extra={"sql": sql[:100], "database": database})
            return []
