from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any, Protocol

from .models import Proposal, TaskRecord


class Worker(Protocol):
    """An untrusted AI or deterministic proposer.

    A worker may reason and propose. It receives no capability to execute,
    approve, write the ledger or promote knowledge by itself.
    """

    def propose(self, task: TaskRecord, context: dict[str, Any]) -> Proposal:
        ...


class ScriptedWorker:
    def __init__(self, proposal: Proposal):
        self._proposal = proposal

    def propose(self, task: TaskRecord, context: dict[str, Any]) -> Proposal:
        return replace(self._proposal, proposal_id=f"{task.task_id}:{self._proposal.proposal_id}")


class CallableWorker:
    def __init__(self, fn: Callable[[TaskRecord, dict[str, Any]], Proposal]):
        self._fn = fn

    def propose(self, task: TaskRecord, context: dict[str, Any]) -> Proposal:
        return self._fn(task, context)
