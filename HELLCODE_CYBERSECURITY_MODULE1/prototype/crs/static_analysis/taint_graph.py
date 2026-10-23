"""AST and Neo4j-based Cross-File Taint Flow Analysis engine."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Optional

from crs.graph.cpg_indexer import CPGIndexer, CodePropertyGraph, NodeType
from crs.graph.neo4j_client import Neo4jClient

logger = logging.getLogger("crs.static_analysis.taint")


@dataclass
class TaintNode:
    file: str
    line: int
    name: str
    is_source: bool = False
    is_sink: bool = False


@dataclass
class TaintFlow:
    source: TaintNode
    sink: TaintNode
    call_stack: list[str] = field(default_factory=list)


class TaintGraphAnalyzer:
    """Constructs cross-file call and taint propagation graphs using Neo4j and CPG."""

    DANGEROUS_SINKS = {
        "eval",
        "exec",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "os.system",
        "os.popen",
        "cursor.execute",
    }

    def __init__(
        self,
        neo4j_client: Optional[Neo4jClient] = None,
        indexer: Optional[CPGIndexer] = None,
    ) -> None:
        self.neo4j = neo4j_client
        self.indexer = indexer or CPGIndexer(neo4j_client=self.neo4j)
        self._last_cpg: Optional[CodePropertyGraph] = None

    def get_cpg(self) -> Optional[CodePropertyGraph]:
        """Return the most recently indexed Code Property Graph."""
        return self._last_cpg

    def analyze_repository(self, repo_path: Path) -> list[TaintFlow]:
        """Discover taint flows using Neo4j if available, falling back to CPG/AST."""
        flows: list[TaintFlow] = []

        # 1. Build CPG representation
        self._last_cpg = self.indexer.index_repository(repo_path, repo_id=repo_path.name)

        # 2. If Neo4j is connected, execute Cypher graph traversal
        if self.neo4j and self.neo4j.is_available:
            flows.extend(self._analyze_via_cypher(repo_path))

        # 3. If Neo4j not connected or found no flows, query CPG in-memory paths
        if not flows and self._last_cpg:
            paths = self._last_cpg.find_taint_paths()
            for path in paths:
                src_node = self._last_cpg.nodes.get(path[0])
                sink_node = self._last_cpg.nodes.get(path[-1])
                if src_node and sink_node:
                    call_stack = [
                        f"{self._last_cpg.nodes[nid].file}:{self._last_cpg.nodes[nid].line} ({self._last_cpg.nodes[nid].name})"
                        for nid in path
                        if nid in self._last_cpg.nodes
                    ]
                    flows.append(
                        TaintFlow(
                            source=TaintNode(
                                file=src_node.file,
                                line=src_node.line,
                                name=src_node.name,
                                is_source=True,
                            ),
                            sink=TaintNode(
                                file=sink_node.file,
                                line=sink_node.line,
                                name=sink_node.name,
                                is_sink=True,
                            ),
                            call_stack=call_stack,
                        )
                    )

        # 4. Fallback: Local AST walking for direct sinks if no CPG entrypoints triggered
        if not flows:
            flows.extend(self._analyze_local_ast(repo_path))

        return flows

    def _analyze_via_cypher(self, repo_path: Path) -> list[TaintFlow]:
        """Run Cypher query for variable-length taint flows."""
        cypher = """
        MATCH path = (src:TaintSource)-[:FLOWS_TO*1..10]->(sink:TaintSink)
        RETURN src.name AS src_name, src.file AS src_file, src.line AS src_line,
               sink.name AS sink_name, sink.file AS sink_file, sink.line AS sink_line,
               [n IN nodes(path) | n.file + ":" + n.line + " (" + n.name + ")"] AS call_stack
        """
        results = self.neo4j.execute_query(cypher)
        flows: list[TaintFlow] = []
        for r in results:
            flows.append(
                TaintFlow(
                    source=TaintNode(
                        file=r.get("src_file", ""),
                        line=r.get("src_line", 1),
                        name=r.get("src_name", "user_input"),
                        is_source=True,
                    ),
                    sink=TaintNode(
                        file=r.get("sink_file", ""),
                        line=r.get("sink_line", 1),
                        name=r.get("sink_name", "sink"),
                        is_sink=True,
                    ),
                    call_stack=r.get("call_stack", []),
                )
            )
        return flows

    def _analyze_local_ast(self, repo_path: Path) -> list[TaintFlow]:
        """Direct AST walk to catch single-file direct sinks without explicit entrypoint."""
        flows: list[TaintFlow] = []
        python_files = list(repo_path.rglob("*.py"))

        for file_path in python_files:
            try:
                tree = ast.parse(file_path.read_text(encoding="utf-8"))
                rel_file = str(file_path.relative_to(repo_path))

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = self._get_func_name(node.func)
                        if func_name in self.DANGEROUS_SINKS:
                            sink_node = TaintNode(
                                file=rel_file,
                                line=node.lineno,
                                name=func_name,
                                is_sink=True,
                            )
                            source_node = TaintNode(
                                file=rel_file,
                                line=max(1, node.lineno - 2),
                                name="user_input",
                                is_source=True,
                            )
                            call_chain = [f"{rel_file}:{node.lineno} ({func_name})"]
                            if self._last_cpg:
                                call_chain = self._last_cpg.get_call_chain_for_line(rel_file, node.lineno)
                            flows.append(
                                TaintFlow(
                                    source=source_node,
                                    sink=sink_node,
                                    call_stack=call_chain,
                                )
                            )
            except Exception:
                continue

        return flows

    def _get_func_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_func_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""
