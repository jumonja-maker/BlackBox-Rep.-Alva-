"""BLACK.BOX Investigation Engine: independent, offline, stdlib-only analytics."""
from .model import InvestigationError, Policy
from .engine import analyze, compare_reports
from .sqlite_adapter import analyze_session, load_session
from .snapshot_adapter import analyze_snapshot
from .report import to_html

__all__ = ["InvestigationError", "Policy", "analyze", "analyze_session", "load_session",
           "analyze_snapshot", "compare_reports", "to_html"]
__version__ = "0.1.2"
