#!/usr/bin/env python3
"""
VAYU Neo4j Code Property Graph (CPG) Synchronizer.
Indexes a target codebase into Neo4j and prints Cypher queries for the demo.
"""

import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from crs.graph.neo4j_client import Neo4jClient
from crs.graph.cpg_indexer import CPGIndexer
from crs.static_analysis.taint_graph import TaintGraphAnalyzer

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "samples/vulnerable/command_injection"
    target_path = Path(target_dir).resolve()

    print(f"\n⚡ Connecting to Neo4j at bolt://127.0.0.1:7687...")
    client = Neo4jClient()
    if not client.connect():
        print("❌ Could not connect to Neo4j. Is the Docker container running?")
        print("👉 Run: docker run -d --name vayu-neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest")
        sys.exit(1)

    print("✓ Successfully connected to Neo4j!")
    print(f"📦 Indexing AST & Code Property Graph for: {target_path}")

    # Synchronize with Neo4j
    indexer = CPGIndexer(neo4j_client=client)
    cpg = indexer.index_repository(target_path, repo_id=target_path.name)

    print(f"✓ Uploaded {len(cpg.nodes)} Nodes and {len(cpg.edges)} Edges to Neo4j!")
    
    # Run Taint Analysis
    analyzer = TaintGraphAnalyzer(neo4j_client=client, indexer=indexer)
    flows = analyzer.analyze_repository(target_path)
    print(f"✓ Detected {len(flows)} Taint Propagation Paths in Graph.")

    print("\n" + "=" * 65)
    print("🎬 READY TO SHOW IN DEMO VIDEO:")
    print("=" * 65)
    print("1. Open your browser: http://localhost:7474")
    print("2. Login:")
    print("   - Username: neo4j")
    print("   - Password: password")
    print("3. Paste and run these Cypher queries in the top search bar:\n")
    print("   👉 Query 1 (Show all colorful nodes and relations):")
    print("      MATCH (n) RETURN n LIMIT 100\n")
    print("   👉 Query 2 (Show the exact vulnerability Taint Path):")
    print("      MATCH path = (s:TaintSource)-[:FLOWS_TO*]->(k:TaintSink) RETURN path\n")
    print("   👉 Query 3 (Show call hierarchy):")
    print("      MATCH (caller:Function)-[:CALLS*]->(target:Function) RETURN caller, target\n")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
