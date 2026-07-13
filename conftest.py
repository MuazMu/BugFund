"""Root conftest for BugFund tests.

Presence at the project root anchors ``rootdir`` so the absolute packages
(``ai_gateway``, ``agent_swarm``, ``execution_engine``, ``control_plane``)
resolve via the ``pythonpath = ["."]`` setting in ``pyproject.toml``.
"""
