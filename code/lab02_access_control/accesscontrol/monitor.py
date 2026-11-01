"""Диспетчер доступу (reference monitor) — КАРКАС для лабораторної роботи 2.

Здобувач реалізує модель розмежування доступу свого варіанта
(ACL / capabilities / RBAC / ABAC) та вимоги, позначені `TODO`.

Диспетчер доступу має задовольняти три властивості (лекція 6):
  1) повне посередництво — жоден доступ не минає диспетчера;
  2) захищеність — його не можна обійти чи підмінити;
  3) верифіковність — він достатньо малий, щоб бути перевіреним.
"""
from __future__ import annotations

import dataclasses
import enum
import json
import time
from typing import Iterable


class Permission(enum.Flag):
    NONE = 0
    READ = enum.auto()
    WRITE = enum.auto()
    DELETE = enum.auto()
    ADMIN = READ | WRITE | DELETE


@dataclasses.dataclass
class Decision:
    allowed: bool
    reason: str


class AuditLog:
    """Реєстраційний та операційний журнали (лекція 7).

    Реєстраційний журнал фіксує КОЖНЕ рішення диспетчера; операційний —
    лише виконані зміни стану. Журнал захищають від підробки (тут — спрощено).
    """

    def __init__(self) -> None:
        self._records: list[dict] = []

    def record(self, subject: str, obj: str, action: str, decision: Decision) -> None:
        self._records.append({
            "ts": self._now(),
            "subject": subject,
            "object": obj,
            "action": action,
            "allowed": decision.allowed,
            "reason": decision.reason,
        })

    @staticmethod
    def _now() -> float:
        return time.time()

    def entries(self) -> list[dict]:
        return list(self._records)

    def dump(self) -> str:
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in self._records)


class ReferenceMonitor:
    """Єдина точка ухвалення рішень про доступ."""

    def __init__(self, policy: "Policy", audit: AuditLog | None = None) -> None:
        self._policy = policy
        self._audit = audit or AuditLog()

    def check(self, subject: str, obj: str, action: Permission) -> Decision:
        decision = self._policy.evaluate(subject, obj, action)
        self._audit.record(subject, obj, action.name or str(action), decision)
        return decision

    def enforce(self, subject: str, obj: str, action: Permission) -> None:
        decision = self.check(subject, obj, action)
        if not decision.allowed:
            raise PermissionError(decision.reason)

    @property
    def audit(self) -> AuditLog:
        return self._audit


class Policy:
    """Базовий клас політики. Здобувач реалізує підклас за своїм варіантом."""

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        # TODO(варіант): реалізувати обчислення рішення згідно з обраною моделлю.
        # Правило безпечних значень за замовчуванням (лекція 5): якщо явного
        # дозволу немає — доступ заборонено.
        raise NotImplementedError("Реалізуйте політику свого варіанта")


class AnomalyDetector:
    """Виявлення аномалій у журналі (лекція 7).

    Здобувач реалізує детектори двох аномалій свого варіанта.
    """

    def scan(self, log: AuditLog) -> list[str]:
        alerts: list[str] = []
        # TODO(варіант): реалізувати виявлення двох аномалій зі свого завдання,
        # наприклад «сплеск відмов у доступі від одного суб'єкта» або
        # «послідовний перебір ідентифікаторів об'єктів».
        return alerts


def subjects_with_access(policy: Policy, subjects: Iterable[str], obj: str,
                         action: Permission) -> list[str]:
    """Запит «хто має доступ до об'єкта» — природний для подання за стовпцями (ACL)."""
    return [s for s in subjects if policy.evaluate(s, obj, action).allowed]
