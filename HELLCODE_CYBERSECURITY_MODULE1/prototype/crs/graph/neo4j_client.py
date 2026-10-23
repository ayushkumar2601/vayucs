from __future__ import annotations
"""Resilient, fail-soft Neo4j driver client for the VAYU Code Property Graph."""

import logging
import os
from typing import Any, Optional

try:
    from neo4j import GraphDatabase, Driver
    from neo4j.exceptions import ServiceUnavailable, AuthError, Neo4jError
    NEO4J_INSTALLED = True
except ImportError:
    NEO4J_INSTALLED = False
    Driver = Any  # type: ignore

logger = logging.getLogger("crs.graph.neo4j")


class Neo4jClient:
    """Manages connection pooling and Cypher queries against a Neo4j database."""

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
    ) -> None:
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "password")
        self.database = database or os.getenv("NEO4J_DATABASE", "neo4j")
        self._driver: Optional[Driver] = None
        self._connected: bool = False

    @property
    def is_available(self) -> bool:
        """Return True if Neo4j is installed and successfully connected."""
        return self._connected and self._driver is not None

    def connect(self) -> bool:
        """Attempt to establish connectivity with the Neo4j instance.

        Returns True on success, False on connection failure (fail-soft).
        """
        if not NEO4J_INSTALLED:
            logger.info("neo4j library is not installed; operating in in-memory CPG mode.")
            self._connected = False
            return False

        try:
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=300,
                connection_acquisition_timeout=3.0,
            )
            self._driver.verify_connectivity()
            self._connected = True
            logger.info("Connected to Neo4j at %s", self.uri)
            return True
        except Exception as exc:
            logger.warning(
                "Could not connect to Neo4j (%s): %s. Operating in local in-memory fallback.",
                self.uri,
                exc,
            )
            self._connected = False
            if self._driver:
                try:
                    self._driver.close()
                except Exception:
                    pass
                self._driver = None
            return False

    def init_schema(self) -> bool:
        """Create standard indexes and constraints for CPG entities."""
        if not self.is_available:
            return False

        constraints = [
            "CREATE CONSTRAINT file_path_uniq IF NOT EXISTS FOR (f:File) REQUIRE f.id IS UNIQUE",
            "CREATE CONSTRAINT func_id_uniq IF NOT EXISTS FOR (fn:Function) REQUIRE fn.id IS UNIQUE",
            "CREATE CONSTRAINT source_id_uniq IF NOT EXISTS FOR (s:TaintSource) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT sink_id_uniq IF NOT EXISTS FOR (k:TaintSink) REQUIRE k.id IS UNIQUE",
            "CREATE CONSTRAINT finding_id_uniq IF NOT EXISTS FOR (fd:Finding) REQUIRE fd.id IS UNIQUE",
        ]

        for stmt in constraints:
            try:
                self.execute_write(stmt)
            except Exception as exc:
                logger.debug("Schema constraint skipped/failed: %s", exc)
        return True

    def execute_query(self, cypher: str, params: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """Execute a read-only Cypher query and return results as a list of dicts."""
        if not self.is_available:
            return []

        params = params or {}
        try:
            with self._driver.session(database=self.database) as session:
                result = session.run(cypher, params)
                return [record.data() for record in result]
        except Exception as exc:
            logger.error("Error executing Cypher query: %s | error: %s", cypher, exc)
            return []

    def execute_write(self, cypher: str, params: Optional[dict[str, Any]] = None) -> Any:
        """Execute a write transaction Cypher statement."""
        if not self.is_available:
            return None

        params = params or {}
        try:
            with self._driver.session(database=self.database) as session:
                return session.execute_write(lambda tx: tx.run(cypher, params).consume())
        except Exception as exc:
            logger.error("Error executing Cypher write: %s | error: %s", cypher, exc)
            return None

    def clear_graph(self, repo_id: Optional[str] = None) -> bool:
        """Delete graph nodes and relationships."""
        if not self.is_available:
            return False

        if repo_id:
            query = "MATCH (n {repo_id: $repo_id}) DETACH DELETE n"
            self.execute_write(query, {"repo_id": repo_id})
        else:
            query = "MATCH (n) DETACH DELETE n"
            self.execute_write(query)
        return True

    def close(self) -> None:
        """Close driver connection pool."""
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None
            self._connected = False

    def __enter__(self) -> "Neo4jClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
