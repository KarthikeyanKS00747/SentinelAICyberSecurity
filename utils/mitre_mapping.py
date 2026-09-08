"""Static mapping from SentinelAI detection rules to MITRE ATT&CK techniques.

Pure lookup, no database and no I/O: a labelling layer over the alerts the
detector already produces. IDs, names and tactics below were checked against
attack.mitre.org (Enterprise matrix) rather than written from memory.
"""

from dataclasses import dataclass

ATTACK_BASE_URL = "https://attack.mitre.org/techniques"


@dataclass(frozen=True)
class MitreTechnique:
    """One ATT&CK technique as displayed next to an alert."""

    technique_id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        """Canonical attack.mitre.org page (sub-techniques use T1110/001/)."""
        return f"{ATTACK_BASE_URL}/{self.technique_id.replace('.', '/')}/"

    @property
    def label(self) -> str:
        return f"{self.technique_id} · {self.name}"


# -- Verified against attack.mitre.org --------------------------------
T1071 = MitreTechnique("T1071", "Application Layer Protocol", "Command and Control")
T1110 = MitreTechnique("T1110", "Brute Force", "Credential Access")
T1046 = MitreTechnique("T1046", "Network Service Discovery", "Discovery")
# T1078 is listed under four tactics on attack.mitre.org today -- Stealth,
# Persistence, Privilege Escalation and Initial Access (ATT&CK renamed the
# "Defense Evasion" tactic to "Stealth"). MitreTechnique holds a single
# tactic, and Initial Access is the one this rule actually evidences: an
# attacker guessing a password and getting in. The others describe what they
# might do next, which the detector has no evidence of.
T1078 = MitreTechnique("T1078", "Valid Accounts", "Initial Access")

# Rule -> technique(s). Keys are the exact threat_name values utils/detector.py
# writes, so a rename there shows up here as an unmapped alert rather than a
# silently wrong label.
THREAT_TECHNIQUES: dict[str, tuple[MitreTechnique, ...]] = {
    # T1071 over T1090 (Proxy): all this rule establishes is that an IP on the
    # local blocklist was seen communicating over an application protocol
    # (SSH in the sample logs, which T1071 lists explicitly). T1090 would
    # assert the host is acting as a relay or proxy for someone else's
    # traffic, and the detector has no evidence of that -- it only knows the
    # address appears in ThreatIntel.
    "Malicious IP Activity": (T1071,),
    # Repeated failed authentications from one source. T1110.001 (Password
    # Guessing) is the precise sub-technique if this is ever narrowed; the
    # parent is used here because the rule does not distinguish guessing from
    # spraying or credential stuffing.
    "Brute Force Attack": (T1110,),
    # One source touching many distinct destination ports is service discovery.
    "Potential Port Scan / High Volume": (T1046,),
    # A guessed password that then worked is use of a valid account, not the
    # guessing itself. T1110 deliberately stays off this rule: the Brute Force
    # alert that almost always accompanies it already carries that label, and
    # repeating it here would double-count one behaviour as two techniques in
    # the correlation chain.
    "Credential Compromise Suspected": (T1078,),
}


def techniques_for(threat_name: str | None) -> tuple[MitreTechnique, ...]:
    """Every technique mapped to a rule; empty tuple when unmapped."""
    return THREAT_TECHNIQUES.get(threat_name or "", ())


def primary_technique(threat_name: str | None) -> MitreTechnique | None:
    """The technique to show when there is only room for one."""
    mapped = techniques_for(threat_name)
    return mapped[0] if mapped else None


def technique_ids(threat_name: str | None) -> list[str]:
    """Just the IDs, for compact displays such as the correlation chain."""
    return [technique.technique_id for technique in techniques_for(threat_name)]
