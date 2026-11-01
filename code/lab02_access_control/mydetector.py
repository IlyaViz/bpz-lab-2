import collections
import re

from accesscontrol.monitor import AnomalyDetector, AuditLog


def split_id(obj: str):
    match = re.fullmatch(r"(\D+)(\d+)", obj)
    if match is None:
        return None
    return match.group(1), int(match.group(2))


def longest_run(numbers: list[int]) -> tuple[int, int, int]:
    best = (0, 0, 0)
    start = None
    prev = None
    for n in sorted(numbers):
        if prev is None or n != prev + 1:
            start = n
        prev = n
        if n - start + 1 > best[0]:
            best = (n - start + 1, start, n)
    return best


class VariantDetector(AnomalyDetector):
    def __init__(
        self, deny_limit: int = 5, window: float = 60, run_limit: int = 5
    ) -> None:
        self.deny_limit = deny_limit
        self.window = window
        self.run_limit = run_limit

    def scan(self, log: AuditLog) -> list[str]:
        entries = log.entries()
        return self.deny_spikes(entries) + self.id_scans(entries)

    def deny_spikes(self, entries: list[dict]) -> list[str]:
        times = collections.defaultdict(list)
        for r in entries:
            if not r["allowed"]:
                times[r["subject"]].append(r["ts"])
        alerts = []
        for subject, ts in sorted(times.items()):
            ts.sort()
            start = 0
            most = 0
            for end in range(len(ts)):
                while ts[end] - ts[start] > self.window:
                    start += 1
                most = max(most, end - start + 1)
            if most >= self.deny_limit:
                alerts.append(
                    f"сплеск відмов: {subject}, {most} відмов за {self.window:g} с"
                )
        return alerts

    def id_scans(self, entries: list[dict]) -> list[str]:
        ids = collections.defaultdict(set)
        for r in entries:
            parsed = split_id(r["object"])
            if parsed is not None:
                ids[(r["subject"], parsed[0])].add(parsed[1])
        alerts = []
        for (subject, prefix), numbers in sorted(ids.items()):
            length, first, last = longest_run(list(numbers))
            if length >= self.run_limit:
                alerts.append(
                    f"перебір ID: {subject}, {prefix}{first}.."
                    f"{prefix}{last} ({length} підряд)"
                )
        return alerts
