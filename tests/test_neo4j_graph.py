"""Tests for Neo4j Client, Code Property Graph (CPG) Indexer, Graph-RAG & Blast Radius."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from crs.core.schemas import Evidence, VulnerabilityFinding, Severity, PatchProposal
from crs.graph.neo4j_client import Neo4jClient
from crs.graph.cpg_indexer import CPGIndexer, CodePropertyGraph, CPGNode, CPGEdge, NodeType, RelationType
from crs.graph.blast_radius import BlastRadiusAnalyzer
from crs.patching.patch_validator import PatchValidator
from crs.reasoning.evidence_builder import EvidenceBuilder
from vayu_mcp.tools import tool_trace_taint_path, tool_get_blast_radius


def test_neo4j_client_fail_soft_when_offline():
    """Verify Neo4jClient fails softly and does not crash when port 7687 is offline."""
    client = Neo4jClient(uri="bolt://127.0.0.1:9999", user="test", password="pwd")
    assert not client.is_available
    connected = client.connect()
    assert not connected
    assert not client.is_available
    assert client.execute_query("MATCH (n) RETURN n") == []
    assert client.execute_write("CREATE (n:Test)") is None
    assert not client.init_schema()
    client.close()


def test_neo4j_client_with_mock_driver():
    """Verify Neo4jClient executes queries properly when driver is active."""
    client = Neo4jClient()
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    mock_driver.verify_connectivity.return_value = True

    mock_record = MagicMock()
    mock_record.data.return_value = {"val": 42}
    mock_session.run.return_value = [mock_record]

    client._driver = mock_driver
    client._connected = True

    assert client.is_available
    res = client.execute_query("MATCH (n) RETURN n")
    assert res == [{"val": 42}]

    assert client.init_schema()
    assert client.clear_graph("repo1")
    client.close()
    assert not client.is_available


def test_cpg_indexer_on_vulnerable_repository(tmp_path: Path):
    """Verify CPGIndexer parses ASTs, detects functions, entrypoints, sinks, and taint paths."""
    repo = tmp_path / "test_repo"
    repo.mkdir()

    # Create multi-file flow: api.py -> service.py
    api_code = """
def route_handler(user_input):
    from service import execute_task
    execute_task(user_input)
"""
    service_code = """
import subprocess

def execute_task(cmd):
    subprocess.run(cmd, shell=True)
"""
    (repo / "api.py").write_text(api_code, encoding="utf-8")
    (repo / "service.py").write_text(service_code, encoding="utf-8")

    indexer = CPGIndexer()
    cpg = indexer.index_repository(repo, repo_id="demo")

    assert len(cpg.nodes) >= 4
    # Check that File nodes exist
    file_nodes = [n for n in cpg.nodes.values() if n.label == NodeType.FILE]
    assert len(file_nodes) == 2

    # Check Function nodes
    fn_nodes = [n for n in cpg.nodes.values() if n.label == NodeType.FUNCTION]
    fn_names = {f.name for f in fn_nodes}
    assert "route_handler" in fn_names
    assert "execute_task" in fn_names

    # Check TaintSink node
    sinks = [n for n in cpg.nodes.values() if n.label == NodeType.TAINT_SINK]
    assert len(sinks) == 1
    assert sinks[0].name == "subprocess.run"
    assert sinks[0].file == "service.py"

    # Check k-hop context
    context = cpg.get_k_hop_context(sinks[0].id, k=2)
    assert len(context["nodes"]) >= 2

    # Check call chain resolution
    chain = cpg.get_call_chain_for_line("service.py", sinks[0].line)
    assert any("execute_task" in item for item in chain)


def test_blast_radius_analyzer(tmp_path: Path):
    """Verify BlastRadiusAnalyzer computes callers and impact scores."""
    cpg = CodePropertyGraph(repo_id="test")

    fn1 = CPGNode(id="fn:billing.py:process_payment:10", label=NodeType.FUNCTION, name="process_payment", file="billing.py", line=10, end_line=20)
    fn2 = CPGNode(id="fn:api.py:checkout:5", label=NodeType.FUNCTION, name="checkout", file="api.py", line=5, end_line=15)
    fn3 = CPGNode(id="fn:test_api.py:test_checkout:1", label=NodeType.FUNCTION, name="test_checkout", file="test_api.py", line=1, end_line=10)

    cpg.add_node(fn1)
    cpg.add_node(fn2)
    cpg.add_node(fn3)

    # checkout -> process_payment
    cpg.add_edge(CPGEdge(fn2.id, fn1.id, RelationType.CALLS))
    # test_checkout -> checkout
    cpg.add_edge(CPGEdge(fn3.id, fn2.id, RelationType.CALLS))

    analyzer = BlastRadiusAnalyzer(cpg=cpg)
    result = analyzer.analyze("billing.py", "process_payment")

    assert "process_payment" in result.affected_functions
    assert "checkout" in result.affected_functions
    assert "test_checkout" in result.affected_functions
    assert "billing.py" in result.affected_files
    assert "api.py" in result.affected_files
    assert "test_api.py" in result.prioritized_test_files
    assert result.impact_score > 0.0


def test_patch_validator_blast_radius(tmp_path: Path):
    """Verify PatchValidator.compute_blast_radius returns structured impact results."""
    repo = tmp_path / "repo"
    repo.mkdir()
    app_py = repo / "app.py"
    app_py.write_text("def ping(host):\n    pass\n", encoding="utf-8")

    proposal = PatchProposal(
        finding_id="FINDING-001",
        target_file="app.py",
        rationale="Fix injection",
        unified_diff="--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@ def ping\n- pass\n+ return True\n",
        expected_security_effect="Safe",
        confidence=0.9,
    )

    validator = PatchValidator()
    blast = validator.compute_blast_radius(proposal, str(repo))
    assert blast["target_file"] == "app.py"
    assert "affected_functions" in blast
    assert "impact_score" in blast


def test_evidence_builder_with_graph_rag(tmp_path: Path):
    """Verify EvidenceBuilder injects Graph-RAG causal call chain into EvidencePackage."""
    repo = tmp_path / "repo"
    repo.mkdir()
    code = "import subprocess\n\ndef run_cmd(c):\n    subprocess.run(c, shell=True)\n"
    (repo / "app.py").write_text(code, encoding="utf-8")

    cpg = CodePropertyGraph()
    fn = CPGNode(id="fn:app.py:run_cmd:3", label=NodeType.FUNCTION, name="run_cmd", file="app.py", line=3, end_line=4)
    caller = CPGNode(id="fn:controller.py:handle_request:10", label=NodeType.FUNCTION, name="handle_request", file="controller.py", line=10, end_line=20)
    cpg.add_node(fn)
    cpg.add_node(caller)
    cpg.add_edge(CPGEdge(caller.id, fn.id, RelationType.CALLS))

    finding = VulnerabilityFinding(
        finding_id="FIND-1",
        title="Command Injection",
        vulnerability_type="CWE-78",
        severity=Severity.HIGH,
        confidence=0.9,
        file="app.py",
        line_start=4,
        evidence=[],
    )

    builder = EvidenceBuilder(cpg=cpg)
    pkg = builder.build(finding, str(repo))

    # Verify that Graph-RAG enriched the evidence package
    graph_evidence = [e for e in pkg.scanner_evidence if e.source == "Neo4j_CPG_GraphRAG"]
    assert len(graph_evidence) == 1
    assert "handle_request" in graph_evidence[0].description
    assert "graph_context" in pkg.instructions


def test_mcp_graph_tools(tmp_path: Path):
    """Verify tool_trace_taint_path and tool_get_blast_radius execute cleanly."""
    repo = tmp_path / "mcp_repo"
    repo.mkdir()
    (repo / "main.py").write_text("import os\ndef ping(h):\n    os.system(h)\n", encoding="utf-8")

    taint_res = tool_trace_taint_path(str(repo))
    assert taint_res["flow_count"] >= 1
    assert "main.py" in taint_res["flows"][0]["sink"]["file"]

    blast_res = tool_get_blast_radius(str(repo), "main.py", "ping")
    assert blast_res["target_function"] == "ping"
    assert "main.py" in blast_res["affected_files"]
