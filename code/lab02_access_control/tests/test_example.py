"""Тести навчального прикладу ЛР2. Здобувач пише власні тести за цим зразком.

Перевірки відтворюють табл. 6.2 конспекту лекцій: суб'єкт s має мітку (2, {ФІН}).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from examples.blp_example import BLPPolicy, FanInDetector, Label


def make():
    p = BLPPolicy()
    p.label_subject("s", Label(2, frozenset({"ФІН"})))
    p.label_object("звіт", Label(1, frozenset({"ФІН"})))
    p.label_object("довідка", Label(1, frozenset({"КАДР"})))
    p.label_object("зведення", Label(3, frozenset({"ФІН", "КАДР"})))
    for obj in ("звіт", "довідка", "зведення"):
        p.grant("s", obj, Permission.READ | Permission.WRITE)
    return p


def test_read_down_allowed():
    assert ReferenceMonitor(make()).check("s", "звіт", Permission.READ).allowed


def test_no_read_up():
    d = ReferenceMonitor(make()).check("s", "зведення", Permission.READ)
    assert not d.allowed and "читання вгору" in d.reason


def test_no_write_down():
    d = ReferenceMonitor(make()).check("s", "звіт", Permission.WRITE)
    assert not d.allowed and "запис униз" in d.reason


def test_write_up_allowed():
    assert ReferenceMonitor(make()).check("s", "зведення", Permission.WRITE).allowed


def test_incomparable_categories_deny_both():
    mon = ReferenceMonitor(make())
    assert not mon.check("s", "довідка", Permission.READ).allowed
    assert not mon.check("s", "довідка", Permission.WRITE).allowed


def test_discretionary_permission_required():
    p = make()
    p.label_subject("t", Label(3, frozenset({"ФІН", "КАДР"})))
    d = p.evaluate("t", "звіт", Permission.READ)   # мітка дозволяє, матриця — ні
    assert not d.allowed and "дискреційного" in d.reason


def test_safe_default_for_unlabeled_subject():
    assert not make().evaluate("невідомий", "звіт", Permission.READ).allowed


def test_subjects_with_access():
    assert subjects_with_access(make(), ["s", "t"], "звіт", Permission.READ) == ["s"]


def test_fan_in_anomaly():
    mon = ReferenceMonitor(make())
    for who in ("a", "b", "c"):
        mon.check(who, "зведення", Permission.READ)
    assert FanInDetector(threshold=3).scan(mon.audit)


def test_clean_log_has_no_alerts():
    mon = ReferenceMonitor(make())
    mon.check("s", "звіт", Permission.READ)
    assert FanInDetector(threshold=3).scan(mon.audit) == []
    assert FanInDetector().scan(AuditLog()) == []
