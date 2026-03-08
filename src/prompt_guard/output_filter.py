"""
Output filter layer - scans LLM responses BEFORE they reach the user.
Catches data leaks, path exposure, secret leakage, and prompt extraction.
"""

import re
from dataclasses import dataclass, field


@dataclass
class OutputScanResult:
    blocked: bool = False
    redacted_text: str = ""
    findings: list[str] = field(default_factory=list)

    def add(self, finding: str):
        self.findings.append(finding)

    def block(self, finding: str):
        self.findings.append(finding)
        self.blocked = True


# Patterns that indicate sensitive data in LLM output
SECRET_PATTERNS = [
    # Private keys and certificates
    (r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*(PRIVATE KEY|CERTIFICATE)-----", "Private key/certificate"),

    # Generic secrets
    (r"\b(sk|pk|api[_-]?key|token|secret)[_-]?[a-zA-Z0-9]{20,}\b", "API key/token"),
    (r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", "Bearer token"),
    (r"\b(password|passwd|pwd)\s*[=:]\s*\S+", "Password in output"),
    (r"\b(secret|token|key|apikey|api_key|auth)\s*[=:]\s*['\"]?[A-Za-z0-9\-._]{8,}", "Secret assignment"),

    # Cloud providers
    (r"\bAIza[0-9A-Za-z\-_]{35}\b", "Google API key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key ID"),
    (r"\b[A-Za-z0-9/+=]{40}\b(?=.*aws)", "AWS secret access key"),
    (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*(azure|tenant|subscription))", "Azure GUID"),

    # Git platforms
    (r"\bghp_[0-9A-Za-z]{36}\b", "GitHub personal access token"),
    (r"\bgho_[0-9A-Za-z]{36}\b", "GitHub OAuth token"),
    (r"\bghu_[0-9A-Za-z]{36}\b", "GitHub user-to-server token"),
    (r"\bghs_[0-9A-Za-z]{36}\b", "GitHub server-to-server token"),
    (r"\bghr_[0-9A-Za-z]{36}\b", "GitHub refresh token"),
    (r"\bglpat-[0-9A-Za-z\-_]{20,}\b", "GitLab personal access token"),
    (r"\bbitbucket_[0-9A-Za-z]{20,}\b", "Bitbucket token"),

    # AI providers
    (r"\bsk-[A-Za-z0-9]{20,}\b", "OpenAI API key"),
    (r"\bsk-ant-[A-Za-z0-9\-]{20,}\b", "Anthropic API key"),
    (r"\bhf_[A-Za-z0-9]{20,}\b", "Hugging Face token"),

    # Messaging and SaaS
    (r"\bxoxb-[0-9]{10,}-[0-9A-Za-z]{20,}\b", "Slack bot token"),
    (r"\bxoxp-[0-9]{10,}-[0-9A-Za-z]{20,}\b", "Slack user token"),
    (r"\bxoxs-[0-9]{10,}-[0-9A-Za-z]{20,}\b", "Slack session token"),
    (r"\b[0-9]{8,}:AA[A-Za-z0-9_-]{30,}\b", "Telegram bot token"),
    (r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b", "SendGrid API key"),
    (r"\bkey-[0-9a-zA-Z]{32}\b", "Mailgun API key"),

    # Payment
    (r"\b(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}\b", "Stripe API key"),
    (r"\bsq0[a-z]{3}-[0-9A-Za-z\-_]{22,}\b", "Square access token"),

    # Infrastructure
    (r"\b(mongodb|postgres|mysql|redis|amqp|mssql)://[^\s]+@[^\s]+", "Database connection string"),
    (r"\bDOPAT_[0-9A-Za-z]{40,}\b", "DigitalOcean personal access token"),
    (r"\bnpm_[A-Za-z0-9]{36}\b", "npm access token"),
    (r"\bpypi-[A-Za-z0-9]{50,}\b", "PyPI API token"),
    (r"\bdop_v1_[a-f0-9]{64}\b", "DigitalOcean OAuth token"),
    (r"\bvault:v1:[A-Za-z0-9+/=]+", "HashiCorp Vault token"),

    # JWT
    (r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+", "JWT token"),

    # SSH and host credentials
    (r"\bssh-rsa\s+AAAA[A-Za-z0-9+/=]+", "SSH public key (may indicate private key context)"),
    (r"\b[A-Z0-9]{20}:[A-Za-z0-9/+=]{40}\b", "AWS-style access key pair"),
]

# Paths that should never appear in output
SENSITIVE_PATHS = [
    r"/etc/(passwd|shadow|sudoers|ssh/)",
    r"~?/?\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts|config)",
    r"~?/?\.gnupg/",
    r"~?/?\.aws/(credentials|config)",
    r"~?/?\.kube/config",
    r"~?/?\.env\b",
    r"~?/?\.netrc\b",
    r"~?/?\.docker/config\.json",
    r"~?/?\.git-credentials",
]


def check_canary(text: str, canary: str) -> bool:
    """Check if the canary token from the system prompt leaked into the output."""
    return canary in text


def scan_secrets(text: str) -> list[tuple[str, str]]:
    """Scan output for leaked secrets. Returns list of (match, description)."""
    hits = []
    for pattern, desc in SECRET_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            hits.append((str(matches[0])[:20] + "...", desc))
    return hits


def scan_sensitive_paths(text: str) -> list[str]:
    """Find sensitive file paths in the output."""
    hits = []
    for pattern in SENSITIVE_PATHS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(pattern)
    return hits


def redact_paths(text: str, allowed_dirs: list[str]) -> str:
    """Redact absolute paths that are outside allowed directories."""
    def replacer(match):
        path = match.group(0)
        if any(path.startswith(d) for d in allowed_dirs):
            return path
        return "[REDACTED_PATH]"

    return re.sub(r"/[a-zA-Z0-9_./-]{3,}", replacer, text)


def redact_secrets(text: str) -> str:
    """Redact detected secrets from the output."""
    result = text
    for pattern, _ in SECRET_PATTERNS:
        result = re.sub(pattern, "[REDACTED_SECRET]", result, flags=re.IGNORECASE)
    return result


def scan_output(text: str, canary: str, allowed_dirs: list[str] | None = None) -> OutputScanResult:
    """
    Run all output filters on the LLM response.
    Returns an OutputScanResult with findings and potentially redacted text.
    """
    result = OutputScanResult()
    result.redacted_text = text

    if not text or not text.strip():
        result.redacted_text = text
        return result

    # Canary check - system prompt leaked
    if check_canary(text, canary):
        result.block("CANARY token detected in output - system prompt leaked")
        result.redacted_text = "[Response blocked: system prompt leak detected]"
        return result

    # Secret scanning
    secrets = scan_secrets(text)
    for match_preview, desc in secrets:
        result.add(f"Secret leaked: {desc} ({match_preview})")

    # Sensitive path scanning
    sensitive_paths = scan_sensitive_paths(text)
    for path_pattern in sensitive_paths:
        result.add(f"Sensitive path in output: {path_pattern}")

    # Apply redactions
    if secrets:
        result.redacted_text = redact_secrets(result.redacted_text)

    if allowed_dirs and sensitive_paths:
        result.redacted_text = redact_paths(result.redacted_text, allowed_dirs)

    return result
