"""The ten checks, and the default set used by audit_server()."""

from .base import Check
from .broad_tool import BroadToolCheck
from .dangerous_combo import DangerousComboCheck
from .description_injection import DescriptionInjectionCheck
from .missing_auth import MissingAuthCheck
from .no_rate_limit import NoRateLimitCheck
from .prompt_template_injection import PromptTemplateInjectionCheck
from .sensitive_resource import SensitiveResourceCheck
from .tool_impersonation import ToolImpersonationCheck
from .verbose_errors import VerboseErrorsCheck
from .weak_input_schema import WeakInputSchemaCheck


def default_checks() -> list[Check]:
    """All checks, in a stable order."""
    return [
        DescriptionInjectionCheck(),
        BroadToolCheck(),
        MissingAuthCheck(),
        DangerousComboCheck(),
        SensitiveResourceCheck(),
        PromptTemplateInjectionCheck(),
        ToolImpersonationCheck(),
        WeakInputSchemaCheck(),
        VerboseErrorsCheck(),
        NoRateLimitCheck(),
    ]


def check_by_id(check_id: str) -> Check | None:
    for check in default_checks():
        if check.id == check_id:
            return check
    return None


__all__ = [
    "Check",
    "BroadToolCheck",
    "DangerousComboCheck",
    "DescriptionInjectionCheck",
    "MissingAuthCheck",
    "NoRateLimitCheck",
    "PromptTemplateInjectionCheck",
    "SensitiveResourceCheck",
    "ToolImpersonationCheck",
    "VerboseErrorsCheck",
    "WeakInputSchemaCheck",
    "check_by_id",
    "default_checks",
]
