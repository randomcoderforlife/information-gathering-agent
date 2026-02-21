from __future__ import annotations

import networkx as nx
from neo4j import GraphDatabase


def push_graph_to_neo4j(
    graph: nx.Graph,
    uri: str,
    user: str,
    password: str,
) -> tuple[int, int]:
    if graph.number_of_nodes() == 0:
        return (0, 0)
    if not uri or not user or not password:
        raise ValueError("Missing Neo4j credentials. Set NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD.")

    driver = GraphDatabase.driver(uri, auth=(user, password))
    node_count = 0
    rel_count = 0

    with driver.session() as session:
        for node, attrs in graph.nodes(data=True):
            session.run(
                """
                MERGE (n:Entity {id: $id})
                SET n.type = $type
                """,
                id=str(node),
                type=str(attrs.get("type", "unknown")),
            )
            node_count += 1

        for source, target, attrs in graph.edges(data=True):
            session.run(
                """
                MATCH (a:Entity {id: $source})
                MATCH (b:Entity {id: $target})
                MERGE (a)-[r:RELATED_TO {relation: $relation}]->(b)
                """,
                source=str(source),
                target=str(target),
                relation=str(attrs.get("relation", "related_to")),
            )
            rel_count += 1

    driver.close()
    return (node_count, rel_count)

