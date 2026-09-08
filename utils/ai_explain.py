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

# Hard ceiling on generated tokens. Wall-clock generation time on a local model
# is very nearly linear in the number of tokens produced, so output length is
# the only latency lever this layer has. Measured against llama3:8b the prompt
# below lands at ~160 output tokens; this cap sits at roughly twice that as a
# runaway guard, not as the shaping tool -- a cap tight enough to bite would
# truncate mid-sentence, which is why the prompt does the actual shaping.
MAX_RESPONSE_TOKENS = 300

# Low temperature: this is a summarisation task over values already present in
# the prompt, so sampling variety buys nothing and costs coherence.
GENERATION_OPTIONS: dict[str, float | int] = {
    "num_predict": MAX_RESPONSE_TOKENS,
    "temperature": 0.2,
    "top_p": 0.9,
}

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
    """Build the Ollama prompt for one Alert row.

    Written to be answered briefly: every section carries an explicit sentence
    budget and the mitigation list is capped. A junior analyst triaging a queue
    wants the shape of the threat, not an essay -- and the shorter answer is
    also the faster one to generate.
    """
    detected_at = alert.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC") if alert.detected_at else "unknown"
    labels = "\n".join(
        f"{label}: <{description}>"
        for label, description in (
            ("EXPLANATION", "2-3 sentences in plain language on what this alert means"),
            ("RATIONALE", "2-3 sentences on why SentinelAI flagged it, citing the threat name, source IP and risk score above"),
            ("IMPACT", "2-3 sentences on what could happen if this is a genuine attack"),
            ("MITIGATION", "2 or 3 concrete remediation steps, one per line, each starting with '- ' and under 15 words"),
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
        # Deliberately conservative wording. A stronger "answer immediately, no
        # preamble" instruction made llama3 drop the MITIGATION label entirely
        # and run the bullets onto the end of IMPACT, so brevity is asked for
        # as a length budget rather than as a ban on preamble.
        "- Write in plain language and be concise: keep EXPLANATION, RATIONALE and IMPACT to "
        "2-3 short sentences each, and give at most 3 mitigation steps of one sentence each.\n"
        "- Keep the whole reply under 130 words.\n"
        "- Refer to the actual values above; do not invent hostnames, usernames, ports or timestamps.\n"
        "- Do not use markdown headings, bold text or code fences.\n"
        "- Do not add any section other than the four listed above."
    )


def build_generate_payload(alert, model: str, *, stream: bool) -> dict:
    """Assemble the ``/api/generate`` request body for one alert.

    Shared by the streaming and non-streaming callers so the prompt, the token
    cap and the sampling settings cannot drift apart between the two paths.
    """
    return {
        "model": model,
        "prompt": build_explanation_prompt(alert),
        "stream": stream,
        "options": dict(GENERATION_OPTIONS),
    }


def _clean(text: str) -> str:
    """Strip model formatting artefacts and collapse stray whitespace."""
    text = _EMPHASIS.sub("", text)
    text = _HEADING.sub("", text)
    return "\n".join(line.rstrip() for line in text.strip().splitlines()).strip()


def _strip_bullets(line: str) -> str:
    """Remove every leading bullet marker from one line.

    Applied repeatedly because models sometimes echo the bullet character from
    the prompt on top of their own, producing "- - Block the source IP"; a
    single substitution would leave the stray dash in the rendered step.
    """
    previous = None
    while previous != line:
        previous = line
        line = _BULLET.sub("", line)
    return line.strip()


def _to_steps(text: str) -> list[str]:
    """Split a mitigation block into individual steps."""
    steps = [_strip_bullets(line) for line in text.splitlines() if line.strip()]
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
