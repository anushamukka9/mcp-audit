"""The twenty-eight checks, and the default set used by audit_server()."""

from .approval_bypass import ApprovalBypassCheck
from .base import Check
from .broad_tool import BroadToolCheck
from .config_insecure_transport import ConfigInsecureTransportCheck
from .config_plaintext_secret import ConfigPlaintextSecretCheck
from .config_remote_package import ConfigRemotePackageCheck
from .config_shell_pipe import ConfigShellPipeCheck
from .config_unauthenticated_http import ConfigUnauthenticatedHttpCheck
from .credential_request import CredentialRequestCheck
from .dangerous_combo import DangerousComboCheck
from .dangerous_default_port import DangerousDefaultPortCheck
from .description_injection import DescriptionInjectionCheck
from .elevated_privilege import ElevatedPrivilegeCheck
from .embedded_secret import EmbeddedSecretCheck
from .exfiltration_path import ExfiltrationPathCheck
from .exposed_bind import ExposedBindCheck
from .known_vulnerable_package import KnownVulnerablePackageCheck
from .missing_auth import MissingAuthCheck
from .network_tool_bridge import NetworkToolBridgeCheck
from .no_rate_limit import NoRateLimitCheck
from .path_traversal import PathTraversalCheck
from .privilege_mixing import PrivilegeMixingCheck
from .prompt_reads_sensitive import PromptReadsSensitiveCheck
from .prompt_template_injection import PromptTemplateInjectionCheck
from .sensitive_resource import SensitiveResourceCheck
from .tool_impersonation import ToolImpersonationCheck
from .unauthenticated_exposure import UnauthenticatedExposureCheck
from .verbose_errors import VerboseErrorsCheck
from .weak_input_schema import WeakInputSchemaCheck


def default_checks() -> list[Check]:
    """All checks, in a stable order."""
    return [
        DescriptionInjectionCheck(),
        ApprovalBypassCheck(),
        BroadToolCheck(),
        MissingAuthCheck(),
        DangerousComboCheck(),
        SensitiveResourceCheck(),
        PromptTemplateInjectionCheck(),
        ToolImpersonationCheck(),
        WeakInputSchemaCheck(),
        VerboseErrorsCheck(),
        NoRateLimitCheck(),
        PathTraversalCheck(),
        EmbeddedSecretCheck(),
        CredentialRequestCheck(),
        ElevatedPrivilegeCheck(),
        ExfiltrationPathCheck(),
        PrivilegeMixingCheck(),
        PromptReadsSensitiveCheck(),
        # Threat-intel check: matches names against the bundled CVE feed
        # snapshot (offline; see mcp_audit.cve_feed). Inert when no named
        # package matches an entry.
        KnownVulnerablePackageCheck(),
        # Live-transport checks: inert unless the manifest's server block
        # carries a "transport" section (filled in by mcp-audit live).
        UnauthenticatedExposureCheck(),
        ExposedBindCheck(),
        DangerousDefaultPortCheck(),
        NetworkToolBridgeCheck(),
        # Client-config checks: inert unless the manifest carries a
        # "client_servers" list (built by scan_client_config).
        ConfigRemotePackageCheck(),
        ConfigPlaintextSecretCheck(),
        ConfigUnauthenticatedHttpCheck(),
        ConfigInsecureTransportCheck(),
        ConfigShellPipeCheck(),
    ]


def check_by_id(check_id: str) -> Check | None:
    for check in default_checks():
        if check.id == check_id:
            return check
    return None


__all__ = [
    "Check",
    "ApprovalBypassCheck",
    "BroadToolCheck",
    "ConfigInsecureTransportCheck",
    "ConfigPlaintextSecretCheck",
    "ConfigRemotePackageCheck",
    "ConfigShellPipeCheck",
    "ConfigUnauthenticatedHttpCheck",
    "CredentialRequestCheck",
    "KnownVulnerablePackageCheck",
    "DangerousComboCheck",
    "DangerousDefaultPortCheck",
    "DescriptionInjectionCheck",
    "ElevatedPrivilegeCheck",
    "EmbeddedSecretCheck",
    "ExfiltrationPathCheck",
    "ExposedBindCheck",
    "MissingAuthCheck",
    "NetworkToolBridgeCheck",
    "NoRateLimitCheck",
    "PathTraversalCheck",
    "PrivilegeMixingCheck",
    "PromptReadsSensitiveCheck",
    "PromptTemplateInjectionCheck",
    "SensitiveResourceCheck",
    "ToolImpersonationCheck",
    "UnauthenticatedExposureCheck",
    "VerboseErrorsCheck",
    "WeakInputSchemaCheck",
    "check_by_id",
    "default_checks",
]
