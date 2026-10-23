from __future__ import annotations
"""Blast Radius & Dependency Impact Analysis for candidate patches."""

from dataclasses import dataclass, field
import logging
from typing import Any, Optional

from crs.graph.cpg_indexer import CodePropertyGraph, NodeType, RelationType
from crs.graph.neo4j_client import Neo4jClient

logger = logging.getLogger("crs.graph.blast_radius")


@dataclass
class BlastRadiusResult:
    target_file: str
    target_function: str
    affected_functions: list[str] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    prioritized_test_files: list[str] = field(default_factory=list)
    impact_score: float = 0.0  # Normalized 0.0 (isolated) to 1.0 (critical core)


class BlastRadiusAnalyzer:
    """Analyzes the ripple effect of modifications using the Code Property Graph."""

    def __init__(
        self,
        cpg: Optional[CodePropertyGraph] = None,
        neo4j_client: Optional[Neo4jClient] = None,
    ) -> None:
        self.cpg = cpg
        self.neo4j = neo4j_client

    def analyze(self, target_file: str, function_name: str, max_depth: int = 4) -> BlastRadiusResult:
        """Calculate blast radius across call dependencies."""
        if self.neo4j and self.neo4j.is_available:
            return self._analyze_via_neo4j(target_file, function_name, max_depth)
        elif self.cpg:
            return self._analyze_via_cpg(target_file, function_name, max_depth)
        return BlastRadiusResult(
            target_file=target_file,
            target_function=function_name,
            affected_functions=[function_name],
            affected_files=[target_file],
            impact_score=0.1,
        )

    def _analyze_via_neo4j(self, target_file: str, function_name: str, max_depth: int) -> BlastRadiusResult:
        """Run Cypher query to trace callers up to max_depth."""
        query = f"""
        MATCH (target:Function {{name: $fn}})
        WHERE target.file CONTAINS $file OR $file CONTAINS target.file
        OPTIONAL MATCH path = (caller:Function)-[:CALLS*1..{max_depth}]->(target)
        WITH target, collect(DISTINCT caller) AS callers
        RETURN target.name AS target_name,
               target.file AS target_file,
               [c IN callers | c.name] AS caller_names,
               [c IN callers | c.file] AS caller_files
        """
        records = self.neo4j.execute_query(query, {"fn": function_name, "file": target_file})
        if not records or not records[0].get("target_name"):
            return BlastRadiusResult(
                target_file=target_file,
                target_function=function_name,
                affected_functions=[function_name],
                affected_files=[target_file],
                impact_score=0.1,
            )

        row = records[0]
        caller_names = row.get("caller_names", [])
        caller_files = list(set(row.get("caller_files", [])))

        all_functions = list(set([function_name] + caller_names))
        all_files = list(set([target_file] + caller_files))

        test_files = [f for f in all_files if "test" in f.lower()]
        score = min(1.0, round(len(all_functions) * 0.15, 2))

        return BlastRadiusResult(
            target_file=target_file,
            target_function=function_name,
            affected_functions=all_functions,
            affected_files=all_files,
            prioritized_test_files=test_files,
            impact_score=score,
        )

    def _analyze_via_cpg(self, target_file: str, function_name: str, max_depth: int) -> BlastRadiusResult:
        """Run in-memory graph traversal to trace callers."""
        target_nodes = [
            n for n in self.cpg.nodes.values()
            if n.label == NodeType.FUNCTION and n.name == function_name and (target_file in n.file or n.file in target_file)
        ]
        if not target_nodes:
            # Fallback to function name match
            target_nodes = [
                n for n in self.cpg.nodes.values()
                if n.label == NodeType.FUNCTION and n.name == function_name
            ]

        if not target_nodes:
            return BlastRadiusResult(
                target_file=target_file,
                target_function=function_name,
                affected_functions=[function_name],
                affected_files=[target_file],
                impact_score=0.1,
            )

        start_id = target_nodes[0].id
        affected_fn_ids: set[str] = {start_id}
        frontier: set[str] = {start_id}

        for _ in range(max_depth):
            next_frontier: set[str] = set()
            for curr in frontier:
                callers = [
                    e.source_id for e in self.cpg._rev_adj.get(curr, [])
                    if e.type == RelationType.CALLS
                ]
                for caller_id in callers:
                    if caller_id not in affected_fn_ids:
                        affected_fn_ids.add(caller_id)
                        next_frontier.add(caller_id)
            frontier = next_frontier
            if not frontier:
                break

        affected_functions = [
            self.cpg.nodes[fn_id].name for fn_id in affected_fn_ids
            if fn_id in self.cpg.nodes
        ]
        affected_files = list(set(
            self.cpg.nodes[fn_id].file for fn_id in affected_fn_ids
            if fn_id in self.cpg.nodes
        ))

        test_files = [f for f in affected_files if "test" in f.lower()]
        score = min(1.0, round(len(affected_functions) * 0.15, 2))

        return BlastRadiusResult(
            target_file=target_file,
            target_function=function_name,
            affected_functions=affected_functions,
            affected_files=affected_files,
            prioritized_test_files=test_files,
            impact_score=score,
        )
