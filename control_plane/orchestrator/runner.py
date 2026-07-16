"""Campaign runner — compiles the graph and drives a campaign to completion.

Called by the Celery ``run_campaign_task``. ``build_graph`` is imported lazily
so ``graph.py`` can re-export :func:`run_campaign` without an import cycle.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from agent_swarm import HuntState

__all__ = ["run_campaign"]


async def run_campaign(
    initial_state: HuntState,
    *,
    checkpointer: Any = None,
    thread_id: Optional[str] = None,
) -> HuntState:
    """Compile (or reuse) the graph and invoke it to completion.

    Args:
        initial_state: The seeded swarm state (see
            :func:`control_plane.orchestrator.state.build_initial_state`).
        checkpointer: Optional LangGraph checkpointer for resume/replay.
        thread_id: Checkpoint thread id (auto-generated if omitted).
    """
    # Lazy import avoids a graph <-> runner import cycle.
    from control_plane.orchestrator.graph import build_graph

    compiled = build_graph(checkpointer=checkpointer)
    config: Optional[dict[str, Any]] = None
    if checkpointer is not None:
        config = {"configurable": {"thread_id": thread_id or str(uuid.uuid4())}}
    result = await compiled.ainvoke(initial_state, config=config)
    return result  # type: ignore[return-value]
