from dataclasses import dataclass, field, asdict
from datetime import datetime


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    category: str        # like "SQL Injection", "Reflected XSS"
    severity: str        # critical | high | medium | low | info
    url: str
    cwe: str = ""
    owasp: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    source: str = "scanner"   # "scanner" or "zap"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self):
        return asdict(self)


class FindingsCollector:
    def __init__(self):
        self._findings = []
        self._seen = set()

    def add(self, finding: Finding):
        
        key = (
            finding.category,
            finding.url,
            finding.parameter,
            finding.payload,
            finding.evidence,
        )
        if key in self._seen:
            return
        self._seen.add(key)
        self._findings.append(finding)

    def all(self):
        return sorted(
            self._findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )

    def count_by_severity(self):
        counts = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def __len__(self):
        return len(self._findings)