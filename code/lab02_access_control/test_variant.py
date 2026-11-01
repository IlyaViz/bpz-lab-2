from accesscontrol.monitor import (
    AuditLog,
    Permission,
    ReferenceMonitor,
    subjects_with_access,
)
from mydetector import VariantDetector
from mypolicy import OBJECTS, SUBJECTS, VariantMonitor, make_policy

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


class ClockLog(AuditLog):
    def __init__(self, step):
        super().__init__()
        self.now = 0
        self.step = step

    def _now(self):
        self.now += self.step
        return self.now


def run(steps, step=1):
    mon = VariantMonitor(make_policy(), ClockLog(step))
    for s, o in steps:
        mon.check(s, o, R)
    return mon.audit


def test_policy_size():
    p = make_policy()
    assert len(SUBJECTS) == 10 and len(OBJECTS) == 24
    assert all(p.tickets(s) for s in SUBJECTS)
    used = set().union(*(p.tickets(s) for s in SUBJECTS))
    assert used == set(OBJECTS)


def test_ticket_gives_access():
    mon = ReferenceMonitor(make_policy())
    assert mon.check("erin", "doc1", R | W).allowed


def test_safe_default_without_ticket():
    p = make_policy()
    assert not p.evaluate("erin", "doc5", R).allowed
    assert not p.evaluate("judy", "doc21", W).allowed
    d = p.evaluate("mallory", "doc1", R)
    assert not d.allowed and "safe default" in d.reason


def test_delete_needs_second_person():
    assert make_policy(approvals_needed=0).evaluate("bob", "doc5", D).allowed
    p = make_policy()
    d = p.evaluate("bob", "doc5", D)
    assert not d.allowed and "підтвердження" in d.reason
    assert p.approve("alice", "bob", "doc5").allowed
    assert p.evaluate("bob", "doc5", D).allowed


def test_self_approval_rejected():
    p = make_policy()
    assert not p.approve("bob", "bob", "doc5").allowed
    assert not p.evaluate("bob", "doc5", D).allowed


def test_approver_needs_delete_ticket():
    p = make_policy()
    assert not p.approve("frank", "bob", "doc5").allowed
    assert not p.evaluate("bob", "doc5", D).allowed


def test_same_approver_counted_once():
    p = make_policy(approvals_needed=2)
    p.approve("alice", "bob", "doc5")
    p.approve("alice", "bob", "doc5")
    assert not p.evaluate("bob", "doc5", D).allowed


def test_delete_removes_object_and_approval():
    mon = VariantMonitor(make_policy())
    mon.approve("alice", "carol", "doc12")
    mon.perform("carol", "doc12", D)
    assert not mon.check("carol", "doc12", D).allowed
    assert not mon.check("grace", "doc12", R).allowed


def test_every_call_is_logged():
    mon = VariantMonitor(make_policy())
    calls = [("frank", "doc5", R), ("frank", "doc5", W),
             ("judy", "doc21", W), ("bob", "doc5", D)]
    for s, o, a in calls:
        mon.check(s, o, a)
    mon.approve("alice", "bob", "doc5")
    entries = mon.audit.entries()
    assert len(entries) == len(calls) + 1
    assert [r["allowed"] for r in entries] == [True, True, False, False, True]


def test_oplog_has_only_changes():
    mon = VariantMonitor(make_policy())
    mon.perform("frank", "doc5", R)
    mon.perform("frank", "doc5", W)
    mon.check("judy", "doc21", W)
    assert [r["operation"] for r in mon.oplog.entries()] == ["WRITE"]


def test_tickets_are_copies():
    p = make_policy()
    p.tickets("judy")["doc1"] = Permission.ADMIN
    assert not p.evaluate("judy", "doc1", R).allowed


def test_queries_agree():
    p = make_policy()
    assert subjects_with_access(p, SUBJECTS, "doc5", R) == [
        "alice", "bob", "frank"]
    assert p.objects_accessible_by("frank", R) == [
        "doc5", "doc6", "doc7", "doc8"]
    for a in (R, W, D):
        for s in SUBJECTS:
            for o in OBJECTS:
                who = subjects_with_access(p, SUBJECTS, o, a)
                assert (s in who) == (o in p.objects_accessible_by(s, a))


def test_deny_spike_detected():
    log = run([("ivan", f"doc{n}") for n in range(1, 7)])
    alerts = VariantDetector(run_limit=100).scan(log)
    assert alerts == ["сплеск відмов: ivan, 6 відмов за 60 с"]


def test_slow_denials_not_spike():
    log = run([("ivan", f"doc{n}") for n in range(1, 7)], step=120)
    assert VariantDetector(run_limit=100).scan(log) == []


def test_id_scan_detected():
    log = run([("ivan", f"doc{n}") for n in range(15, 21)])
    alerts = VariantDetector().scan(log)
    assert alerts == ["перебір ID: ivan, doc15..doc20 (6 підряд)"]


def test_gaps_break_id_scan():
    log = run([("alice", f"doc{n}") for n in (1, 3, 5, 7, 9, 11)])
    assert VariantDetector().scan(log) == []


def test_clean_log_has_no_alerts():
    log = run([("frank", "doc5"), ("frank", "doc6"), ("erin", "doc1"),
               ("judy", "doc22"), ("judy", "doc9")])
    assert VariantDetector().scan(log) == []
    assert VariantDetector().scan(AuditLog()) == []
