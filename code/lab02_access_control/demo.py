from accesscontrol.monitor import AuditLog, Permission, subjects_with_access
from mydetector import VariantDetector
from mypolicy import (
    OBJECTS,
    SUBJECTS,
    OperationLog,
    VariantMonitor,
    action_name,
    make_policy,
)

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE
START = 1793433600.0


class ClockLog(AuditLog):
    def __init__(self, step: float = 1) -> None:
        super().__init__()
        self.now = START
        self.step = step

    def _now(self) -> float:
        self.now += self.step
        return self.now


def yes(flag: bool) -> str:
    return "так" if flag else "ні"


def who(policy, obj, action):
    return subjects_with_access(policy, SUBJECTS, obj, action)


def show_policy() -> None:
    policy = make_policy()
    total = sum(len(policy.tickets(s)) for s in SUBJECTS)
    print("1. Політика")
    print(f"суб'єктів: {len(SUBJECTS)}, об'єктів: {len(OBJECTS)}, "
          f"мандатів: {total}")
    for s in SUBJECTS:
        own = policy.tickets(s)
        names = list(own)
        span = f"{names[0]}..{names[-1]}"
        print(f"  {s:<6} {span:<13}{action_name(own[names[0]])}")


def decision_table() -> None:
    base = make_policy(approvals_needed=0)
    policy = make_policy()
    cases = [
        ("erin", "doc1", R, True),
        ("erin", "doc5", R, False),
        ("erin", "doc1", D, False),
        ("judy", "doc21", W, False),
        ("frank", "doc5", R | W, True),
        ("mallory", "doc1", R, False),
        ("bob", "doc5", D, False),
    ]
    print("\n2. Очікувані і фактичні рішення evaluate")
    print("  суб.    об.   дія        без 4 очей  очік.  факт.  причина")
    for s, o, a, expected in cases + [("bob*", "doc5", D, True)]:
        if s == "bob*":
            policy.approve("alice", "bob", "doc5")
        name = s.rstrip("*")
        d = policy.evaluate(name, o, a)
        plain = yes(base.evaluate(name, o, a).allowed)
        print(f"  {s:<8}{o:<6}{action_name(a):<11}{plain:<12}"
              f"{yes(expected):<7}{yes(d.allowed):<7}{d.reason}")
    print("  * після підтвердження від alice")


def monitor_demo():
    policy = make_policy()
    audit = ClockLog()
    mon = VariantMonitor(policy, audit, OperationLog(lambda: audit.now))
    print("\n3. Монітор, журнали і правило чотирьох очей")
    calls = 0

    def call(method, *args):
        nonlocal calls
        calls += 1
        try:
            return method(*args)
        except PermissionError as e:
            print("відмову перехоплено:", e)

    call(mon.check, "frank", "doc5", R)
    call(mon.perform, "frank", "doc5", W)
    call(mon.check, "judy", "doc21", W)
    call(mon.perform, "carol", "doc12", D)
    d = call(mon.approve, "carol", "carol", "doc12")
    print("carol підтверджує сама собі:", d.reason)
    d = call(mon.approve, "grace", "carol", "doc12")
    print("grace підтверджує carol:", d.reason)
    d = call(mon.approve, "alice", "carol", "doc12")
    print("alice підтверджує carol:", d.reason)
    call(mon.perform, "carol", "doc12", D)
    d = call(mon.check, "grace", "doc12", R)
    print("doc12 видалено, grace читає doc12:", d.reason)
    print(f"звернень до монітора: {calls}, "
          f"записів у реєстраційному журналі: {len(mon.audit.entries())}")
    print("реєстраційний журнал:")
    print(mon.audit.dump())
    print("операційний журнал:")
    print(mon.oplog.dump())
    return policy, mon


def queries(policy, mon) -> None:
    print("\n4. Запити")
    print("хто читає doc5:", who(policy, "doc5", R))
    print("що читає frank:", policy.objects_accessible_by("frank", R))
    print("хто видаляє doc5:", who(policy, "doc5", D))
    mon.approve("alice", "bob", "doc5")
    print("alice підтвердила видалення doc5 для bob")
    print("хто видаляє doc5:", who(policy, "doc5", D))
    print("що видаляє bob:", policy.objects_accessible_by("bob", D))
    ok = all(
        (s in who(policy, o, a)) == (o in policy.objects_accessible_by(s, a))
        for s in SUBJECTS for o in OBJECTS for a in (R, W, D)
    )
    print("запити узгоджені для всіх пар:", ok)
    print(f"'хто' перевіряє {len(SUBJECTS)} суб'єктів, "
          f"'що' для frank - {len(policy.tickets('frank'))} мандати")


def scan(title: str, steps, step: float = 1, detector=None) -> None:
    mon = VariantMonitor(make_policy(), ClockLog(step))
    for s, o in steps:
        mon.check(s, o, R)
    alerts = (detector or VariantDetector()).scan(mon.audit)
    print(f"{title}:")
    for alert in alerts or ["сигналів немає"]:
        print("   ", alert)


def anomalies(mon) -> None:
    print("\n5. Аномалії (поріг відмов 5 за 60 с, поріг перебору 5)")
    alerts = VariantDetector().scan(mon.audit)
    print("звичайна робота (журнал розділу 3):", alerts or "сигналів немає")
    attack = [("ivan", f"doc{n}") for n in range(13, 25)]
    scan("атака: ivan читає doc13..doc24 щосекунди", attack)
    scan("повільна атака: те саме раз на 2 хв", attack, step=120)
    reading = [("alice", f"doc{n}") for n in range(1, 7)]
    scan("норма: alice читає doc1..doc6 для звіту", reading)
    refresh = [("grace", "doc13")] * 5
    scan("норма: grace 5 разів оновлює doc13", refresh)
    eight = VariantDetector(deny_limit=8)
    scan("поріг відмов 8, норма: grace 5 разів оновлює doc13", refresh,
         detector=eight)
    scan("поріг відмов 8, атака: ivan щосекунди", attack, detector=eight)


if __name__ == "__main__":
    show_policy()
    decision_table()
    policy, mon = monitor_demo()
    queries(policy, mon)
    anomalies(mon)
