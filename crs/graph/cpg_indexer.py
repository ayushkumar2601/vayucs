from __future__ import annotations
"""Code Property Graph (CPG) Indexer and In-Memory Graph Engine."""

import ast
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
from typing import Any, Optional

from crs.graph.neo4j_client import Neo4jClient

logger = logging.getLogger("crs.graph.cpg")


class NodeType(str, Enum):
    FILE = "File"
    FUNCTION = "Function"
    VARIABLE = "Variable"
    TAINT_SOURCE = "TaintSource"
    TAINT_SINK = "TaintSink"
    FINDING = "Finding"


class RelationType(str, Enum):
    CONTAINS = "CONTAINS"
    DEFINES = "DEFINES"
    CALLS = "CALLS"
    HAS_PARAM = "HAS_PARAM"
    FLOWS_TO = "FLOWS_TO"
    PROPAGATES_TO = "PROPAGATES_TO"


@dataclass
class CPGNode:
    id: str
    label: NodeType
    name: str
    file: str
    line: int = 1
    end_line: int = 1
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class CPGEdge:
    source_id: str
    target_id: str
    type: RelationType
    properties: dict[str, Any] = field(default_factory=dict)


class CodePropertyGraph:
    """In-memory representation of the Code Property Graph (CPG)."""

    def __init__(self, repo_id: str = "default") -> None:
        self.repo_id = repo_id
        self.nodes: dict[str, CPGNode] = {}
        self.edges: list[CPGEdge] = []
        self._adj: dict[str, list[CPGEdge]] = {}
        self._rev_adj: dict[str, list[CPGEdge]] = {}

    def add_node(self, node: CPGNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self._adj:
            self._adj[node.id] = []
        if node.id not in self._rev_adj:
            self._rev_adj[node.id] = []

    def add_edge(self, edge: CPGEdge) -> None:
        self.edges.append(edge)
        if edge.source_id not in self._adj:
            self._adj[edge.source_id] = []
        if edge.target_id not in self._rev_adj:
            self._rev_adj[edge.target_id] = []
        self._adj[edge.source_id].append(edge)
        self._rev_adj[edge.target_id].append(edge)

    def find_taint_paths(self) -> list[list[str]]:
        """Discover reachability paths from TaintSources to TaintSinks."""
        sources = [n.id for n in self.nodes.values() if n.label == NodeType.TAINT_SOURCE]
        sinks = {n.id for n in self.nodes.values() if n.label == NodeType.TAINT_SINK}

        paths: list[list[str]] = []
        for src in sources:
            # BFS for path finding
            queue: list[list[str]] = [[src]]
            visited: set[str] = {src}
            while queue:
                current_path = queue.pop(0)
                tail = current_path[-1]
                if tail in sinks and len(current_path) > 1:
                    paths.append(current_path)
                    continue
                for edge in self._adj.get(tail, []):
                    nxt = edge.target_id
                    if nxt not in visited:
                        visited.add(nxt)
                        queue.append(current_path + [nxt])
        return paths

    def get_k_hop_context(self, node_id: str, k: int = 2) -> dict[str, Any]:
        """Extract a k-hop causal subgraph around a target node."""
        if node_id not in self.nodes:
            return {"nodes": [], "edges": []}

        visited_nodes: set[str] = {node_id}
        frontier: set[str] = {node_id}

        for _ in range(k):
            next_frontier: set[str] = set()
            for current in frontier:
                for edge in self._adj.get(current, []):
                    next_frontier.add(edge.target_id)
                for edge in self._rev_adj.get(current, []):
                    next_frontier.add(edge.source_id)
            new_nodes = next_frontier - visited_nodes
            visited_nodes.update(new_nodes)
            frontier = new_nodes
            if not frontier:
                break

        subgraph_nodes = [
            {
                "id": n_id,
                "label": self.nodes[n_id].label.value,
                "name": self.nodes[n_id].name,
                "file": self.nodes[n_id].file,
                "line": self.nodes[n_id].line,
                "properties": self.nodes[n_id].properties,
            }
            for n_id in visited_nodes
            if n_id in self.nodes
        ]
        subgraph_edges = [
            {
                "source": e.source_id,
                "target": e.target_id,
                "type": e.type.value,
                "properties": e.properties,
            }
            for e in self.edges
            if e.source_id in visited_nodes and e.target_id in visited_nodes
        ]
        return {"nodes": subgraph_nodes, "edges": subgraph_edges}

    def get_call_chain_for_line(self, file_path: str, line_no: int) -> list[str]:
        """Find the call chain leading to a file and line number."""
        target_fn = None
        for n in self.nodes.values():
            if n.label == NodeType.FUNCTION and n.file == file_path:
                if n.line <= line_no <= n.end_line:
                    target_fn = n
                    break

        if not target_fn:
            return [f"{file_path}:{line_no}"]

        chain: list[str] = [f"{target_fn.file}:{target_fn.line} ({target_fn.name})"]
        curr_id = target_fn.id
        # Traverse callers up to 5 levels
        for _ in range(5):
            callers = [
                e.source_id for e in self._rev_adj.get(curr_id, [])
                if e.type == RelationType.CALLS
            ]
            if not callers:
                break
            caller_node = self.nodes.get(callers[0])
            if not caller_node:
                break
            chain.insert(0, f"{caller_node.file}:{caller_node.line} ({caller_node.name})")
            curr_id = caller_node.id
        return chain

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary for frontend / API."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label.value,
                    "name": n.name,
                    "file": n.file,
                    "line": n.line,
                    "end_line": n.end_line,
                    "properties": n.properties,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.type.value,
                    "properties": e.properties,
                }
                for e in self.edges
            ],
        }


class CPGIndexer:
    """Parses repositories into Code Property Graphs and synchronizes with Neo4j."""

    DANGEROUS_SINKS = {
        "subprocess.run": "SUBPROCESS",
        "subprocess.Popen": "SUBPROCESS",
        "subprocess.call": "SUBPROCESS",
        "os.system": "OS_SYSTEM",
        "os.popen": "OS_SYSTEM",
        "eval": "CODE_EVAL",
        "exec": "CODE_EVAL",
        "cursor.execute": "SQL_INJECTION",
        "pickle.loads": "DESERIALIZATION",
    }

    ENTRYPOINT_DECORATORS = {"route", "get", "post", "put", "delete", "endpoint", "api_view"}

    def __init__(self, neo4j_client: Optional[Neo4jClient] = None) -> None:
        self.neo4j = neo4j_client

    def index_repository(self, repo_path: Path, repo_id: str = "target_repo") -> CodePropertyGraph:
        """Parse all Python files in repo_path and build the Code Property Graph."""
        cpg = CodePropertyGraph(repo_id=repo_id)
        python_files = list(repo_path.rglob("*.py"))

        functions_by_name: dict[str, list[CPGNode]] = {}

        # First pass: Index Files, Functions, Parameters, Sinks, and Sources
        for fpath in python_files:
            rel_path = str(fpath.relative_to(repo_path))
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content)
            except Exception as exc:
                logger.debug("Failed to parse %s: %s", rel_path, exc)
                continue

            file_node_id = f"file:{rel_path}"
            file_node = CPGNode(
                id=file_node_id,
                label=NodeType.FILE,
                name=rel_path,
                file=rel_path,
                line=1,
                end_line=len(content.splitlines()),
            )
            cpg.add_node(file_node)

            for item in ast.walk(tree):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_id = f"fn:{rel_path}:{item.name}:{item.lineno}"
                    end_lineno = getattr(item, "end_lineno", item.lineno)

                    is_entry = False
                    for dec in item.decorator_list:
                        dec_name = self._get_attr_name(dec)
                        if any(term in dec_name.lower() for term in self.ENTRYPOINT_DECORATORS):
                            is_entry = True

                    fn_node = CPGNode(
                        id=fn_id,
                        label=NodeType.FUNCTION,
                        name=item.name,
                        file=rel_path,
                        line=item.lineno,
                        end_line=end_lineno,
                        properties={"is_entrypoint": is_entry},
                    )
                    cpg.add_node(fn_node)
                    cpg.add_edge(CPGEdge(file_node_id, fn_id, RelationType.DEFINES))

                    if item.name not in functions_by_name:
                        functions_by_name[item.name] = []
                    functions_by_name[item.name].append(fn_node)

                    # Extract params
                    for arg in item.args.args:
                        param_id = f"var:{fn_id}:{arg.arg}"
                        param_node = CPGNode(
                            id=param_id,
                            label=NodeType.VARIABLE,
                            name=arg.arg,
                            file=rel_path,
                            line=item.lineno,
                        )
                        cpg.add_node(param_node)
                        cpg.add_edge(CPGEdge(fn_id, param_id, RelationType.HAS_PARAM))

                        # If entrypoint, param is considered a TaintSource
                        if is_entry:
                            source_id = f"src:{fn_id}:{arg.arg}"
                            src_node = CPGNode(
                                id=source_id,
                                label=NodeType.TAINT_SOURCE,
                                name=f"input_{arg.arg}",
                                file=rel_path,
                                line=item.lineno,
                                properties={"source_type": "HTTP_PARAM"},
                            )
                            cpg.add_node(src_node)
                            cpg.add_edge(CPGEdge(source_id, param_id, RelationType.FLOWS_TO))

                    # Scan for sinks and internal calls within function
                    for sub in ast.walk(item):
                        if isinstance(sub, ast.Call):
                            call_name = self._get_attr_name(sub.func)
                            if call_name in self.DANGEROUS_SINKS:
                                sink_id = f"sink:{rel_path}:{sub.lineno}:{call_name}"
                                sink_node = CPGNode(
                                    id=sink_id,
                                    label=NodeType.TAINT_SINK,
                                    name=call_name,
                                    file=rel_path,
                                    line=sub.lineno,
                                    properties={"sink_type": self.DANGEROUS_SINKS[call_name]},
                                )
                                cpg.add_node(sink_node)
                                cpg.add_edge(CPGEdge(fn_id, sink_id, RelationType.CONTAINS))

                                # Link params to sink if param name appears in call args
                                call_args_str = [
                                    arg_node.id for arg_node in ast.walk(sub)
                                    if isinstance(arg_node, ast.Name)
                                ]
                                for arg in item.args.args:
                                    if arg.arg in call_args_str:
                                        p_id = f"var:{fn_id}:{arg.arg}"
                                        cpg.add_edge(CPGEdge(p_id, sink_id, RelationType.PROPAGATES_TO))
                            else:
                                # Regular function call
                                fn_call_name = call_name.split(".")[-1]
                                sub_callees = functions_by_name.get(fn_call_name, [])
                                for target_fn in sub_callees:
                                    cpg.add_edge(
                                        CPGEdge(
                                            fn_id,
                                            target_fn.id,
                                            RelationType.CALLS,
                                            properties={"line": sub.lineno},
                                        )
                                    )

        # Synchronize with Neo4j if available
        if self.neo4j and self.neo4j.is_available:
            self._sync_to_neo4j(cpg)

        return cpg

    def _sync_to_neo4j(self, cpg: CodePropertyGraph) -> None:
        """Batch upload nodes and edges to Neo4j database."""
        if not self.neo4j or not self.neo4j.is_available:
            return

        self.neo4j.init_schema()

        # Batch upload nodes by label
        node_batches: dict[str, list[dict[str, Any]]] = {}
        for node in cpg.nodes.values():
            label = node.label.value
            if label not in node_batches:
                node_batches[label] = []
            node_batches[label].append(
                {
                    "id": node.id,
                    "name": node.name,
                    "file": node.file,
                    "line": node.line,
                    "end_line": node.end_line,
                    "repo_id": cpg.repo_id,
                    **node.properties,
                }
            )

        for label, batch in node_batches.items():
            cypher = (
                f"UNWIND $batch AS row "
                f"MERGE (n:{label} {{id: row.id}}) "
                f"SET n += row"
            )
            self.neo4j.execute_write(cypher, {"batch": batch})

        # Batch upload edges by type
        edge_batches: dict[str, list[dict[str, Any]]] = {}
        for edge in cpg.edges:
            rel = edge.type.value
            if rel not in edge_batches:
                edge_batches[rel] = []
            edge_batches[rel].append(
                {
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    **edge.properties,
                }
            )

        for rel, batch in edge_batches.items():
            cypher = (
                f"UNWIND $batch AS row "
                f"MATCH (s {{id: row.source_id}}), (t {{id: row.target_id}}) "
                f"MERGE (s)-[r:{rel}]->(t) "
                f"SET r += row"
            )
            self.neo4j.execute_write(cypher, {"batch": batch})

    def _get_attr_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_attr_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""
