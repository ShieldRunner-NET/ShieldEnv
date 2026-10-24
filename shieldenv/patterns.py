from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PatternRule:
    name: str
    pattern: re.Pattern[str]
    confidence: str


PATTERN_RULES = (
    PatternRule("OpenAI API Key", re.compile(r"sk-[a-zA-Z0-9]{32,}", re.IGNORECASE), "high"),
    PatternRule("Anthropic API Key", re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}", re.IGNORECASE), "high"),
    PatternRule("Google Gemini / AIza Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.IGNORECASE), "high"),
    PatternRule("GitHub Personal Access Token", re.compile(r"gh[pousr]_[a-zA-Z0-9_]{20,}", re.IGNORECASE), "high"),
    PatternRule("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    PatternRule("Azure Storage Key", re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+", re.IGNORECASE), "high"),
    PatternRule("Stripe Secret Key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{20,}", re.IGNORECASE), "high"),
    PatternRule("Slack Webhook / Token", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "high"),
    PatternRule("Database Connection URL", re.compile(r"(postgres|mysql|mongodb(\+srv)?):\//[^\s]+:[^\s]+@[^\s]+", re.IGNORECASE), "high"),
    PatternRule("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium"),
    PatternRule("Generic Private Key", re.compile(r"-----BEGIN (RSA|EC|PRIVATE|OPENSSH) KEY-----"), "high"),
    PatternRule("Generic Secret Assignment", re.compile(
        r"""(?:"?(api_key|secret_key|password|passwd|auth_token|bearer)"?\s*(?:=|:)\s*['"][^'"]{8,200}['"])""",
        re.IGNORECASE,
    ), "medium"),
)

SECRET_PATTERNS = {rule.name: rule.pattern for rule in PATTERN_RULES}