"""Prompt construction and response shaping for local-Ollama alert explanations.

Phase 5 asks the local model for four things (see ``context.md``): a simple
explanation, the alert rationale, the possible impact, and recommended
mitigation steps. This module owns the prompt and the parsing of the reply;
the HTTP call itself lives in the router, mirroring ``routers/health.py``.
"""

import re
from dataclasses import dataclass, field

# Backend LLM calls must only ever target the local daemon (context.md rule 5).
OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"
GENERATION_TIMEOUT_SECONDS = 120.0

SECTION_LABELS = ("EXPLANATION", "RATIONALE", "IMPACT", "MITIGATION")

# Some local models (qwen3, deepseek-r1, ...) emit a reasoning block first.
_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_CODE_FENCE = re.compile(r"^\s*```[a-zA-Z0-9_-]*\s*$", re.MULTILINE)
_LABEL = re.compile(rf"^[\s>*#-]*({'|'.join(SECTION_LABELS)})\s*[:\-]\s*", re.IGNORECASE | re.MULTILINE)
_BULLET = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")
_EMPHASIS = re.compile(r"(\*\*|__|\*|`)")
_HEADING = re.compile(r"^\s*#{1,6}\s*", re.MULTILINE)


@dataclass(frozen=True)
class AlertExplanation:
    """One parsed model reply, ready for the template."""

    explanation: str = ""
    rationale: str = ""
    impact: str = ""
    mitigation: list[str] = field(default_factory=list)
    fallback: str = ""

    @property
    def is_structured(self) -> bool:
        return bool(self.explanation or self.rationale or self.impact or self.mitigation)


def build_explanation_prompt(alert) -> str:
    """Build the Ollama prompt for one Alert row."""
    detected_at = alert.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.detected_at else "unknown"
    labels = "\n".join(
        f"{label}: <{description}>"
        for label, description in (
            ("EXPLANATION", "in plain language, what this alert means for someone new to security"),
            ("RATIONALE", "why SentinelAI flagged it, referring to the threat name, source IP and risk score above"),
            ("IMPACT", "what could happen if this is a genuine attack"),
            ("MITIGATION", "concrete remediation steps, one per line, each starting with '- '"),
        )
    )
    return (
        "You are a security analyst assistant for SentinelAI, a lightweight SIEM that "
        "analyses uploaded log files. Explain the following alert to a junior analyst.\n\n"
        "ALERT DETAILS\n"
        f"Threat name: {alert.threat_name}\n"
        f"Severity: {alert.severity.value.upper()}\n"
        f"Risk score: {alert.risk_score:.0f} out of 100\n"
        f"Source IP: {alert.source_ip or 'not recorded'}\n"
        f"Current status: {alert.status.value}\n"
        f"Detected at: {detected_at}\n"
        f"Detector description: {alert.description}\n\n"
        "Reply with exactly these four sections, using these labels verbatim, each label "
        "starting a new line:\n\n"
        f"{labels}\n\n"
        "Rules:\n"
        "- Write in plain language and keep EXPLANATION, RATIONALE and IMPACT to 2-4 sentences each.\n"
        "- Refer to the actual values above; do not invent hostnames, usernames, ports or timestamps.\n"
        "- Do not use markdown headings, bold text or code fences.\n"
        "- Do not add any section other than the four listed above."
    )


def _clean(text: str) -> str:
    """Strip model formatting artefacts and collapse stray whitespace."""
    text = _EMPHASIS.sub("", text)
    text = _HEADING.sub("", text)
    return "\n".join(line.rstrip() for line in text.strip().splitlines()).strip()


def _to_steps(text: str) -> list[str]:
    """Split a mitigation block into individual steps."""
    steps = [_BULLET.sub("", line).strip() for line in text.splitlines() if line.strip()]
    return [step for step in steps if step]


def parse_explanation(raw: str) -> AlertExplanation:
    """Turn a raw model reply into the four sections the template renders.

    Falls back to showing the whole reply when the model ignores the labels,
    so a usable answer is never dropped.
    """
    text = _CODE_FENCE.sub("", _THINK_BLOCK.sub("", raw or "")).strip()
    if not text:
        return AlertExplanation()

    matches = list(_LABEL.finditer(text))
    if not matches:
        return AlertExplanation(fallback=_clean(text))

    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = _clean(text[match.end():end])
        if body:
            sections.setdefault(match.group(1).upper(), body)

    return AlertExplanation(
        explanation=sections.get("EXPLANATION", ""),
        rationale=sections.get("RATIONALE", ""),
        impact=sections.get("IMPACT", ""),
        mitigation=_to_steps(sections.get("MITIGATION", "")),
        fallback="" if sections else _clean(text),
    )
