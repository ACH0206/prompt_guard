"""
Input filter layer - scans user messages BEFORE they reach the LLM.
Detects prompt injection attempts, path traversal, command injection, and encoding tricks.
"""

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    blocked: bool = False
    score: float = 0.0
    findings: list[str] = field(default_factory=list)

    def add(self, finding: str, points: float):
        self.findings.append(finding)
        self.score += points
        if self.score >= 5.0:
            self.blocked = True

    def block(self, finding: str):
        self.findings.append(finding)
        self.score += 10.0
        self.blocked = True


# --- Pattern databases ---

INJECTION_PATTERNS = [
    # Instruction override
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)", 5.0),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", 5.0),
    (r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", 5.0),
    (r"override\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?)", 5.0),
    (r"new\s+instructions?\s*:", 4.0),
    (r"updated?\s+instructions?\s*:", 4.0),
    (r"revised?\s+instructions?\s*:", 4.0),

    # Role switching
    (r"you\s+are\s+now\s+(a|an|the)\s+", 3.0),
    (r"act\s+as\s+(root|admin|superuser|system)", 5.0),
    (r"pretend\s+(you\s+are|to\s+be)\s+(a|an|the)\s+", 3.0),
    (r"switch\s+to\s+(a\s+)?new\s+role", 4.0),
    (r"enter\s+(developer|debug|admin|god)\s+mode", 5.0),
    (r"enable\s+(developer|debug|admin|sudo)\s+mode", 5.0),
    (r"jailbreak", 5.0),
    (r"DAN\s+mode", 5.0),

    # Prompt extraction
    (r"(repeat|print|show|display|output|reveal|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|configuration)", 5.0),
    (r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?)", 4.0),
    (r"(copy|paste|echo)\s+(the\s+)?(entire|full|complete)\s+(system\s+)?(prompt|message|instructions?)", 5.0),
    (r"everything\s+(above|before)\s+this\s+(message|line|point)", 4.0),

    # Delimiter/role injection
    (r"\[SYSTEM\]", 5.0),
    (r"\[INST\]", 4.0),
    (r"<<\s*SYS\s*>>", 5.0),
    (r"<\|im_start\|>", 5.0),
    (r"<\|system\|>", 5.0),
    (r"###\s*(System|Assistant|Human)\s*:", 4.0),
    (r"<system>", 4.0),
    (r"</?(system|assistant|user|instruction)>", 4.0),

    # Data exfiltration
    (r"send\s+(the\s+)?(data|contents?|info|results?)\s+to", 3.0),
    (r"(upload|post|transmit|exfiltrate)\s+.{0,30}\s+(to|at)\s+https?://", 5.0),
    (r"(fetch|curl|wget|request)\s+https?://", 3.0),
]

PATH_PATTERNS = [
    # Sensitive system paths
    (r"/etc/(passwd|shadow|hosts|sudoers|ssh)", 5.0),
    (r"~/.ssh/", 5.0),
    (r"~/.gnupg/", 5.0),
    (r"~/.aws/", 5.0),
    (r"~/.kube/", 4.0),
    (r"\.(env|pem|key|crt|p12|pfx|jks)\b", 4.0),
    (r"id_rsa|id_ed25519|id_ecdsa", 5.0),

    # Path traversal
    (r"\.\./", 3.0),
    (r"\.\.\x5c", 3.0),  # ..\
    (r"%2e%2e[/\\]", 5.0),
    (r"\.\.%2f", 5.0),
]

COMMAND_PATTERNS = [
    (r"\$\(.*\)", 4.0),
    (r"`[^`]+`", 2.0),  # Lower score - could be markdown
    (r"\b(os\.system|subprocess\.|exec\(|eval\(|popen\()", 5.0),
    (r"\b(rm\s+-rf|chmod\s+777|chown|mkfs|dd\s+if=)", 5.0),
    (r"\|\s*(bash|sh|zsh|python|perl|ruby|node)\b", 5.0),
    (r"\b(nc|netcat|ncat)\s+.*-[elp]", 5.0),
    (r"\b(curl|wget)\s+.*\|\s*(bash|sh)", 5.0),
    (r";\s*(cat|ls|pwd|whoami|id|uname)\b", 4.0),
    (r"\bsudo\b", 4.0),
]


def scan_patterns(text: str, patterns: list[tuple[str, float]], category: str) -> list[tuple[str, float]]:
    """Scan text against a list of (regex, score) patterns."""
    hits = []
    for pattern, score in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((f"[{category}] Matched: {pattern}", score))
    return hits


def check_encoding_tricks(text: str) -> list[tuple[str, float]]:
    """Detect unicode obfuscation and encoding tricks."""
    hits = []

    # Zero-width characters
    zero_width = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"]
    zw_count = sum(text.count(c) for c in zero_width)
    if zw_count > 0:
        hits.append((f"[ENCODING] {zw_count} zero-width characters detected", min(zw_count * 1.0, 5.0)))

    # RTL/LTR override characters (can hide text direction)
    bidi_chars = ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]
    bidi_count = sum(text.count(c) for c in bidi_chars)
    if bidi_count > 0:
        hits.append((f"[ENCODING] {bidi_count} bidirectional override characters", 4.0))

    # Homoglyph detection - characters that look like ASCII but aren't
    homoglyph_count = 0
    for char in text:
        if ord(char) > 127:
            cat = unicodedata.category(char)
            if cat.startswith("L"):  # Letter category
                try:
                    name = unicodedata.name(char, "")
                    if "LATIN" in name or "CYRILLIC" in name or "GREEK" in name:
                        homoglyph_count += 1
                except ValueError:
                    pass
    if homoglyph_count > 5:
        hits.append((f"[ENCODING] {homoglyph_count} potential homoglyph characters", 3.0))

    # Base64-encoded content (might hide instructions)
    b64_pattern = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    if b64_pattern:
        import base64
        for match in b64_pattern[:3]:  # Check first 3 matches
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                # Check if decoded content contains injection patterns
                for pattern, score in INJECTION_PATTERNS[:5]:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        hits.append((f"[ENCODING] Base64-encoded injection: {pattern}", 5.0))
                        break
            except Exception:
                pass

    return hits


def check_structure(text: str) -> list[tuple[str, float]]:
    """Detect structural anomalies in the message."""
    hits = []

    # Excessive length
    if len(text) > 10000:
        hits.append(("[STRUCTURE] Message exceeds 10,000 characters", 2.0))

    # Multiple newlines trying to push instructions out of view
    if text.count("\n") > 50:
        hits.append(("[STRUCTURE] Excessive newlines (>50) - possible visual separation attack", 2.0))

    # Repeated whitespace padding
    long_spaces = re.findall(r" {20,}", text)
    if long_spaces:
        hits.append(("[STRUCTURE] Long whitespace padding detected", 2.0))

    # Markdown/HTML comments that might hide instructions
    hidden_comments = re.findall(r"<!--.*?-->", text, re.DOTALL)
    if hidden_comments:
        hits.append((f"[STRUCTURE] {len(hidden_comments)} HTML comments (may hide instructions)", 3.0))

    # Fake conversation turns
    fake_turns = re.findall(r"^(User|Human|Assistant|AI|System)\s*:", text, re.MULTILINE | re.IGNORECASE)
    if len(fake_turns) >= 2:
        hits.append((f"[STRUCTURE] {len(fake_turns)} fake conversation role markers", 4.0))

    return hits


def check_path_access(text: str, allowed_dirs: list[str]) -> list[tuple[str, float]]:
    """Check for attempts to access paths outside allowed directories."""
    hits = []

    # Find absolute paths in the text
    abs_paths = re.findall(r"(/[a-zA-Z0-9_./-]{3,})", text)
    for path in abs_paths:
        # Normalize to catch traversal
        normalized = re.sub(r"/\.\./", "/", path)
        if not any(normalized.startswith(d) for d in allowed_dirs):
            hits.append((f"[PATH] Unauthorized path reference: {path}", 3.0))

    return hits


def scan_input(text: str, allowed_dirs: list[str] | None = None) -> ScanResult:
    """
    Run all input filters on the given text.
    Returns a ScanResult with findings and whether to block.
    """
    result = ScanResult()

    if not text or not text.strip():
        return result

    # Run all checks
    all_hits = []
    all_hits.extend(scan_patterns(text, INJECTION_PATTERNS, "INJECTION"))
    all_hits.extend(scan_patterns(text, PATH_PATTERNS, "PATH"))
    all_hits.extend(scan_patterns(text, COMMAND_PATTERNS, "COMMAND"))
    all_hits.extend(check_encoding_tricks(text))
    all_hits.extend(check_structure(text))

    if allowed_dirs:
        all_hits.extend(check_path_access(text, allowed_dirs))

    for finding, score in all_hits:
        result.add(finding, score)

    return result
