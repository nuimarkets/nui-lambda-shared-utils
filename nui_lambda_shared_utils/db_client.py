"""
Refactored Database client using BaseClient for DRY code patterns.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from contextlib import contextmanager
import pymysql

from .base_client import BaseClient, ServiceHealthMixin
from .utils import handle_client_errors, safe_close_connection
from .secrets_helper import get_database_credentials

# Optional PostgreSQL support
try:
    import psycopg2
    import psycopg2.extras
    HAS_POSTGRESQL = True
except ImportError:
    HAS_POSTGRESQL = False

log = logging.getLogger(__name__)

# Global connection pool for reuse across invocations
_connection_pool = {}


def _clean_expired_connections(pool_key: str, pool_recycle: int) -> None:
    """
    Clean expired connections from the pool (standalone function for backward compatibility).
    
    Args:
        pool_key: Pool identifier
        pool_recycle: Maximum connection age in seconds (0 disables recycling)
    """
    if not pool_recycle or pool_recycle <= 0:
        return
    
    if pool_key not in _connection_pool:
        return
    
    current_time = time.time()
    pool_entries = _connection_pool[pool_key]
    
    # Find expired connections
    expired_connections = []
    fresh_connections = []
    
    for entry in pool_entries:
        age = current_time - entry["timestamp"]
        if age > pool_recycle:
            expired_connections.append(entry["connection"])
        else:
            fresh_connections.append(entry)
    
    # Close expired connections
    for conn in expired_connections:
        safe_close_connection(conn)
    
    # Update pool with only fresh connections
    _connection_pool[pool_key] = fresh_connections
    
    if expired_connections:
        log.debug(
            f"Cleaned {len(expired_connections)} expired connections from pool {pool_key}"
        )


def get_pool_stats() -> Dict[str, Any]:
    """
    Get current connection pool statistics.
    
    Returns:
        Dictionary with pool status for monitoring
    """
    stats = {"total_pools": len(_connection_pool), "pools": {}}
    current_time = time.time()

    for pool_key, connection_entries in _connection_pool.items():
        pool_stats = {
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
            except Exception:
                pass  # Connection is unhealthy

            # Count connections older than 1 hour as aged
            if age > 3600:
                aged += 1

        pool_stats["healthy_connections"] = healthy
        pool_stats["aged_connections"] = aged
        stats["pools"][pool_key] = pool_stats

    return stats


class DatabaseClient(BaseClient, ServiceHealthMixin):
    """
    Refactored Database client with connection pooling and standardized patterns.
    """

    def __init__(
        self,
        secret_name: Optional[str] = None,
        use_pool: bool = True,
        pool_size: int = 5,
        pool_recycle: int = 3600,
        **kwargs
    ):
        """
        Initialize database client.
        
        Args:
            secret_name: Override secret name
            use_pool: Enable connection pooling
            pool_size: Maximum pooled connections
            pool_recycle: Recycle connections after seconds
            **kwargs: Additional configuration
        """
        self.use_pool = use_pool
        self.pool_size = pool_size
        self.pool_recycle = pool_recycle
        
        super().__init__(secret_name=secret_name, **kwargs)
        
        # Build pool key for connection management
        self._pool_key = f"{self.credentials['host']}:{self.credentials['port']}"

    def _get_default_config_prefix(self) -> str:
        """Return configuration prefix for database."""
        return "db"

    def _get_default_secret_name(self) -> str:
        """Return default secret name for DB credentials."""
        return "database-credentials"

    def _create_service_client(self) -> None:
        """Database client doesn't have a single service client - uses connections."""
        return None

    def _resolve_credentials(self, secret_name: Optional[str]) -> Dict[str, Any]:
        """
        Override to use get_database_credentials for normalized field names.

        Args:
            secret_name: Optional secret name override

        Returns:
            Normalized database credentials
        """
        # Use BaseClient's resolution logic to determine the secret name
        from .utils import resolve_config_value, validate_required_param

        resolved_secret_name = resolve_config_value(
            secret_name,
            [
                f"{self.config_key_prefix.upper()}_CREDENTIALS_SECRET",
                f"{self.config_key_prefix.upper()}CREDENTIALS_SECRET"  # Alternative format
            ],
            getattr(self.config, f"{self.config_key_prefix}_credentials_secret", self._get_default_secret_name())
        )

        validate_required_param(resolved_secret_name, "secret_name")

        # Now use the resolved secret name with get_database_credentials
        return get_database_credentials(resolved_secret_name)

    def _clean_expired_connections(self, pool_key: str) -> None:
        """
        Clean expired connections from the pool.
        
        Args:
            pool_key: Pool identifier
        """
        if not self.pool_recycle or self.pool_recycle <= 0:
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
            if age >= self.pool_recycle:
                safe_close_connection(entry["connection"])
                expired_count += 1
            else:
                active_entries.append(entry)

        _connection_pool[pool_key] = active_entries

        if expired_count > 0:
            log.debug(f"Cleaned {expired_count} expired connections from pool {pool_key}")

    @contextmanager
    def get_connection(self, database: Optional[str] = None):
        """
        Context manager for database connections with pooling support.
        
        Args:
            database: Override default database
            
        Yields:
            Database connection object
        """
        connection = None
        pool_key = None

        try:
            # Use pooling if enabled and for default database only
            if self.use_pool and not database:
                pool_key = f"{self._pool_key}_{self.credentials.get('database', 'app')}"
                current_time = time.time()

                # Try to get from pool first
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
                            safe_close_connection(conn)
                            log.debug(f"Recycled expired connection (age: {age:.1f}s) for {pool_key}")
                            continue

                        # Test if connection is still alive
                        try:
                            conn.ping(reconnect=False)
                            connection = conn
                            log.debug(f"Reused pooled connection (age: {age:.1f}s) for {pool_key}")
                            break
                        except Exception as e:
                            safe_close_connection(conn)
                            log.debug(f"Closed dead pooled connection for {pool_key}: {e}")
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
                        self._clean_expired_connections(pool_key)

                        # Add back to pool if under limit
                        if len(_connection_pool[pool_key]) < self.pool_size:
                            entry = {"connection": connection, "timestamp": time.time()}
                            _connection_pool[pool_key].append(entry)
                            log.debug(
                                f"Returned connection to pool {pool_key} "
                                f"(pool size: {len(_connection_pool[pool_key])})"
                            )
                        else:
                            # Pool full, close connection
                            safe_close_connection(connection)
                            log.debug(f"Pool {pool_key} full, closed connection")
                    except Exception as e:
                        # Connection unhealthy, close it
                        safe_close_connection(connection)
                        log.debug(f"Connection unhealthy, closed instead of pooling: {e}")
                        connection = None
                else:
                    # Not using pooling, close immediately
                    safe_close_connection(connection)

    @handle_client_errors(default_return=[])
    def query(
        self, 
        sql: str, 
        params: Optional[tuple] = None, 
        database: Optional[str] = None
    ) -> List[Dict]:
        """
        Execute a SELECT query with error handling.
        
        Args:
            sql: SQL query with %s placeholders
            params: Query parameters
            database: Override default database
            
        Returns:
            List of result rows as dictionaries
        """
        def _query_operation():
            with self.get_connection(database) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql, params)
                    return cursor.fetchall()

        return self._execute_with_error_handling(
            "query",
            _query_operation,
            sql=sql[:100],  # First 100 chars for safety
            database=database
        )

    @handle_client_errors(reraise=True)
    def execute(
        self,
        sql: str,
        params: Optional[tuple] = None,
        database: Optional[str] = None
    ) -> int:
        """
        Execute an INSERT, UPDATE, or DELETE query with error handling.
        
        Args:
            sql: SQL query with %s placeholders
            params: Query parameters
            database: Override default database
            
        Returns:
            Number of affected rows
        """
        def _execute_operation():
            with self.get_connection(database) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(sql, params)
                    conn.commit()
                    return cursor.rowcount

        return self._execute_with_error_handling(
            "execute",
            _execute_operation,
            sql=sql[:100],
            database=database
        )

    @handle_client_errors(reraise=True)
    def bulk_insert(
        self,
        table: str,
        records: List[Dict],
        database: Optional[str] = None,
        batch_size: int = 1000,
        ignore_duplicates: bool = False,
    ) -> int:
        """
        Bulk insert records with error handling.
        
        Args:
            table: Table name
            records: List of dictionaries to insert
            database: Override default database
            batch_size: Records per batch
            ignore_duplicates: Use INSERT IGNORE
            
        Returns:
            Total number of inserted rows
        """
        if not records:
            return 0

        def _bulk_insert_operation():
            # Prepare query
            columns = list(records[0].keys())
            placeholders = ", ".join(["%s"] * len(columns))
            columns_str = ", ".join(f"`{col}`" for col in columns)

            insert_cmd = "INSERT IGNORE" if ignore_duplicates else "INSERT"
            sql = f"{insert_cmd} INTO `{table}` ({columns_str}) VALUES ({placeholders})"

            total_inserted = 0

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

        return self._execute_with_error_handling(
            "bulk_insert",
            _bulk_insert_operation,
            table=table,
            record_count=len(records),
            database=database
        )

    @handle_client_errors(default_return={})
    def get_entity_stats(
        self,
        entity_table: str = "entities",
        user_table: str = "users"
    ) -> Dict[str, Any]:
        """
        Get entity statistics with error handling.
        
        Args:
            entity_table: Name of entities table
            user_table: Name of users table
            
        Returns:
            Dictionary with entity statistics
        """
        def _stats_operation():
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

            return {
                "totals": totals[0] if totals else {},
                "top_entities": active_entities
            }

        return self._execute_with_error_handling(
            "get_entity_stats",
            _stats_operation,
            entity_table=entity_table,
            user_table=user_table
        )

    @handle_client_errors(default_return={})
    def get_record_stats(
        self,
        table: str = "records",
        hours: int = 24,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Get record statistics with error handling.
        
        Args:
            table: Table name to query
            hours: Hours to look back
            **kwargs: Column name mappings
            
        Returns:
            Dictionary with record statistics
        """
        def _record_stats_operation():
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
                (hours,)
            )

            return stats[0] if stats else {}

        return self._execute_with_error_handling(
            "get_record_stats",
            _record_stats_operation,
            table=table,
            hours=hours
        )

    def _perform_health_check(self):
        """Perform database health check."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    if not result or result.get("1") != 1:
                        raise Exception("Database health check query failed")
        except Exception as e:
            raise Exception(f"Database health check failed: {e}")

    def get_connection_info(self) -> Dict:
        """
        Get database connection information.
        
        Returns:
            Dictionary with connection details
        """
        return {
            "host": self.credentials["host"],
            "port": self.credentials["port"],
            "database": self.credentials["database"],
            "username": self.credentials["username"],
            "pool_enabled": self.use_pool,
            "pool_size": self.pool_size,
            "pool_recycle_seconds": self.pool_recycle,
        }


class PostgreSQLClient(BaseClient, ServiceHealthMixin):
    """
    Refactored PostgreSQL client for auth database.
    """

    def __init__(
        self,
        secret_name: Optional[str] = None,
        use_auth_credentials: bool = True,
        **kwargs
    ):
        """
        Initialize PostgreSQL client.
        
        Args:
            secret_name: Override secret name
            use_auth_credentials: Use auth-specific credentials
            **kwargs: Additional configuration
        """
        if not HAS_POSTGRESQL:
            raise ImportError("psycopg2 is not installed. Install with: pip install psycopg2-binary")

        self.use_auth_credentials = use_auth_credentials
        super().__init__(secret_name=secret_name, **kwargs)

    def _get_default_config_prefix(self) -> str:
        """Return configuration prefix for PostgreSQL."""
        return "db"

    def _get_default_secret_name(self) -> str:
        """Return default secret name for PostgreSQL credentials."""
        return "database-credentials"

    def _create_service_client(self) -> None:
        """PostgreSQL client doesn't have a single service client - uses connections."""
        return None

    def _resolve_credentials(self, secret_name: Optional[str]) -> Dict[str, Any]:
        """
        Resolve PostgreSQL credentials with auth-specific handling.
        
        Args:
            secret_name: Optional secret name override
            
        Returns:
            PostgreSQL credentials
        """
        from .secrets_helper import get_secret
        
        # Get raw secret to access auth-specific fields
        resolved_secret_name = secret_name or self._get_default_secret_name()
        raw_creds = get_secret(resolved_secret_name)

        # Use auth-specific credentials if available and requested
        if self.use_auth_credentials and "auth_host" in raw_creds:
            return {
                "host": raw_creds["auth_host"],
                "port": int(raw_creds.get("auth_port", 5432)),
                "username": raw_creds.get("auth_username"),
                "password": raw_creds.get("auth_password"),
                "database": raw_creds.get("auth_database", "auth-service-db"),
            }
        else:
            # Fall back to normalized credentials
            return get_database_credentials(resolved_secret_name)

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

    @handle_client_errors(default_return=[])
    def query(
        self,
        sql: str,
        params: Optional[tuple] = None,
        database: Optional[str] = None
    ) -> List[Dict]:
        """
        Execute PostgreSQL SELECT query.
        
        Args:
            sql: SQL query with %s placeholders
            params: Query parameters
            database: Override default database
            
        Returns:
            List of result rows as dictionaries
        """
        def _query_operation():
            with self.get_connection(database) as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                    cursor.execute(sql, params)
                    return [dict(row) for row in cursor.fetchall()]

        return self._execute_with_error_handling(
            "query",
            _query_operation,
            sql=sql[:100],
            database=database
        )

    def _perform_health_check(self):
        """Perform PostgreSQL health check."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    if not result or result[0] != 1:
                        raise Exception("PostgreSQL health check query failed")
        except Exception as e:
            raise Exception(f"PostgreSQL health check failed: {e}")