"""AEGIS - RedBlue Loop research prototype.

Phase 1 ("Foundation") provides:
- a normalized asset / identity / vulnerability / control / attack-step model (``aegis.model``)
- collectors that turn tool output into that model (``aegis.collectors``)
- a temporal SQLite store that keeps every version of every node and edge (``aegis.store``)
- an attack-graph engine that finds and scores attack paths at any point in time (``aegis.graph``)
- a FastAPI service and dashboard (``aegis.api``)
"""

__version__ = "0.2.0"
