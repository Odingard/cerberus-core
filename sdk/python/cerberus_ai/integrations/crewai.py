"""
cerberus_ai.integrations.crewai
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CrewAI integration — wraps crew task execution with Cerberus inspection.

Install: pip install cerberus-ai[crewai]
"""
from __future__ import annotations

import logging
from typing import Any

from cerberus_ai import Cerberus, SecurityError
from cerberus_ai.models import CerberusConfig


class CerberusCrewCallback:
    """
    Attaches to a CrewAI crew and inspects each task execution.

    Usage:
        from cerberus_ai.integrations.crewai import wrap_crew
        secured_crew = wrap_crew(my_crew, config=config)
        result = secured_crew.kickoff(inputs={"topic": "AI security"})
    """

    def __init__(self, cerberus: Cerberus, raise_on_block: bool = True) -> None:
        self._cerberus = cerberus
        self._raise_on_block = raise_on_block

    def on_task_end(self, task_output: Any, **kwargs: Any) -> None:
        try:
            output_str = str(getattr(task_output, "raw", str(task_output)))
            result = self._cerberus.inspect(
                messages=[{"role": "tool", "content": output_str}]
            )
            if result.blocked and self._raise_on_block:
                raise SecurityError(result)
        except SecurityError:
            raise
        except Exception:
            logging.debug("Cerberus inspection error in on_task_end", exc_info=True)


def wrap_crew(crew: Any, config: CerberusConfig | None = None, raise_on_block: bool = True) -> Any:
    """
    Wrap a CrewAI crew with Cerberus inspection on every task.

    Usage:
        from crewai import Crew
        from cerberus_ai.integrations.crewai import wrap_crew

        crew = Crew(agents=[...], tasks=[...])
        secured = wrap_crew(crew)
        result = secured.kickoff()
    """
    cerberus = Cerberus(config or CerberusConfig())
    callback = CerberusCrewCallback(cerberus, raise_on_block=raise_on_block)

    existing_callbacks = getattr(crew, "task_callback", None)
    if existing_callbacks is None:
        crew.task_callback = callback.on_task_end
    else:
        original = existing_callbacks
        def combined(task_output: Any, **kw: Any) -> None:
            original(task_output, **kw)
            callback.on_task_end(task_output, **kw)
        crew.task_callback = combined

    return crew
