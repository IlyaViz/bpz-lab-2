import json
import time

from accesscontrol.monitor import Decision, Permission, Policy, ReferenceMonitor

CRITICAL = Permission.DELETE
CHANGES = Permission.WRITE | Permission.DELETE

SUBJECTS = ["alice", "bob", "carol", "dave", "erin",
            "frank", "grace", "heidi", "ivan", "judy"]
OBJECTS = [f"doc{n}" for n in range(1, 25)]

RW = Permission.READ | Permission.WRITE
TICKETS = [
    ("alice", 1, 24, Permission.READ | Permission.DELETE),
    ("bob", 1, 8, Permission.ADMIN),
    ("carol", 9, 16, Permission.ADMIN),
    ("dave", 17, 24, Permission.ADMIN),
    ("erin", 1, 4, RW),
    ("frank", 5, 8, RW),
    ("grace", 9, 12, RW),
    ("heidi", 13, 16, RW),
    ("ivan", 17, 20, RW),
    ("judy", 21, 24, Permission.READ),
]


def action_name(action: Permission) -> str:
    parts = (Permission.READ, Permission.WRITE, Permission.DELETE)
    return "|".join(p.name for p in parts if p in action)


class CapabilityPolicy(Policy):
    def __init__(self, approvals_needed: int = 1) -> None:
        self._caps: dict[str, dict[str, Permission]] = {}
        self._approvals: dict[tuple[str, str], set[str]] = {}
        self.approvals_needed = approvals_needed

    def grant(self, subject: str, obj: str, perm: Permission) -> None:
        tickets = self._caps.setdefault(subject, {})
        tickets[obj] = tickets.get(obj, Permission.NONE) | perm

    def tickets(self, subject: str) -> dict[str, Permission]:
        return dict(self._caps.get(subject, {}))

    def approve(self, approver: str, subject: str, obj: str) -> Decision:
        if approver == subject:
            return Decision(False, "ініціатор не може підтвердити сам себе")
        own = self._caps.get(approver, {}).get(obj, Permission.NONE)
        if not own & CRITICAL:
            return Decision(False, "підтверджувач не має мандата DELETE")
        self._approvals.setdefault((subject, obj), set()).add(approver)
        return Decision(True, "підтвердження прийнято")

    def drop_object(self, obj: str) -> None:
        for tickets in self._caps.values():
            tickets.pop(obj, None)
        for key in [k for k in self._approvals if k[1] == obj]:
            del self._approvals[key]

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        effective = self._caps.get(subject, {}).get(obj, Permission.NONE)
        if not action or (action & effective) != action:
            return Decision(False, "немає мандата на цю дію (safe default)")
        if action & CRITICAL:
            approvers = self._approvals.get((subject, obj), set())
            if len(approvers) < self.approvals_needed:
                return Decision(False, "критична операція без підтвердження")
        return Decision(True, "надано")

    def objects_accessible_by(self, subject: str, action: Permission):
        own = self._caps.get(subject, {})
        return [o for o in own if self.evaluate(subject, o, action).allowed]


class OperationLog:
    def __init__(self, clock=time.time) -> None:
        self._records: list[dict] = []
        self._clock = clock

    def record(self, subject: str, obj: str, operation: str) -> None:
        self._records.append({"ts": self._clock(), "subject": subject,
                              "object": obj, "operation": operation})

    def entries(self) -> list[dict]:
        return list(self._records)

    def dump(self) -> str:
        lines = [json.dumps(r, ensure_ascii=False) for r in self._records]
        return "\n".join(lines)


class VariantMonitor(ReferenceMonitor):
    def __init__(self, policy: CapabilityPolicy, audit=None,
                 oplog: OperationLog | None = None) -> None:
        super().__init__(policy, audit)
        self._oplog = oplog or OperationLog()

    def perform(self, subject: str, obj: str, action: Permission) -> None:
        self.enforce(subject, obj, action)
        if action & CHANGES:
            self._oplog.record(subject, obj, action_name(action))
        if action & CRITICAL:
            self._policy.drop_object(obj)

    def approve(self, approver: str, subject: str, obj: str):
        decision = self._policy.approve(approver, subject, obj)
        self.audit.record(approver, obj, "APPROVE", decision)
        if decision.allowed:
            self._oplog.record(approver, obj, f"APPROVE {subject}")
        return decision

    @property
    def oplog(self) -> OperationLog:
        return self._oplog


def make_policy(approvals_needed: int = 1) -> CapabilityPolicy:
    policy = CapabilityPolicy(approvals_needed)
    for subject, first, last, perm in TICKETS:
        for n in range(first, last + 1):
            policy.grant(subject, f"doc{n}", perm)
    return policy
