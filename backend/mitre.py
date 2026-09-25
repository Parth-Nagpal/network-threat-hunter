from sqlalchemy.orm import Session

import models


TECHNIQUE_DEFINITIONS = (
    {
        "technique_id": "T1046",
        "name": "Network Service Scanning",
        "description": "Scanning remote hosts and ports to identify available network services.",
        "tactic": "Discovery",
        "source_detection_type": "Port Scan, Network Sweep",
    },
    {
        "technique_id": "T1110",
        "name": "Brute Force",
        "description": "Repeated attempts to guess or otherwise obtain valid credentials.",
        "tactic": "Credential Access",
        "source_detection_type": "SSH Brute Force",
    },
)

ALERT_TYPE_TO_TECHNIQUE = {
    "Port Scan": "T1046",
    "Port Scan Detected": "T1046",
    "Network Sweep": "T1046",
    "Network Sweep Detected": "T1046",
    "SSH Brute Force": "T1110",
    "SSH Brute Force Detected": "T1110",
}


def seed_mitre_techniques(db: Session) -> None:
    """Insert the deterministic built-in mapping catalog when absent."""
    for definition in TECHNIQUE_DEFINITIONS:
        if db.get(models.MitreTechnique, definition["technique_id"]) is None:
            db.add(models.MitreTechnique(**definition))
    db.commit()
