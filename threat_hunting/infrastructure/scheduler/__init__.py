"""Scheduler adapter.

Runs collection cycles over a set of targets, either once or on an interval.
Uses ``APScheduler`` when installed for cron-like scheduling; otherwise falls
back to a simple sleep loop so the scheduler always works.
"""

from threat_hunting.infrastructure.scheduler.runner import SchedulerRunner

__all__ = ["SchedulerRunner"]
