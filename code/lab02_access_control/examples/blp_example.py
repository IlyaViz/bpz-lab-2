"""Навчальний ПРИКЛАД структури розв'язання ЛР2 — модель Белла–ЛаПадули.

Модель Белла–ЛаПадули (лекція 6) не входить до переліку моделей варіантів ЛР2,
тому цей файл не є розв'язком жодного варіанта. Він показує, як:
  1) оформити підклас Policy з власними структурами даних;
  2) поєднати кілька правил і повертати обґрунтовану відмову, зберігаючи
     правило безпечних значень за замовчуванням (лекція 5);
  3) побудувати детектор аномалії з порогом-параметром (лекція 7).

Приклад відтворює табл. 6.2 конспекту лекцій (див. tests/test_example.py).
"""
from __future__ import annotations

import collections
import dataclasses

from accesscontrol.monitor import AnomalyDetector, AuditLog, Decision, Permission, Policy

# Операції, що змінюють об'єкт, підпадають під зіркову властивість.
MODIFY = Permission.WRITE | Permission.DELETE


@dataclasses.dataclass(frozen=True)
class Label:
    """Мітка безпеки L = (c, K): класифікація та множина категорій."""

    level: int                                  # 0 — несекретно … 3 — цілком таємно
    categories: frozenset[str] = frozenset()

    def dominates(self, other: "Label") -> bool:
        """L1 ≥ L2, якщо c1 ≥ c2 і K1 ⊇ K2 (частковий порядок)."""
        return self.level >= other.level and self.categories >= other.categories


class BLPPolicy(Policy):
    """Мандатна політика конфіденційності з дискреційною складовою."""

    def __init__(self) -> None:
        self.subject_labels: dict[str, Label] = {}
        self.object_labels: dict[str, Label] = {}
        self.matrix: dict[tuple[str, str], Permission] = {}

    def label_subject(self, subject: str, label: Label) -> None:
        self.subject_labels[subject] = label

    def label_object(self, obj: str, label: Label) -> None:
        self.object_labels[obj] = label

    def grant(self, subject: str, obj: str, perm: Permission) -> None:
        key = (subject, obj)
        self.matrix[key] = self.matrix.get(key, Permission.NONE) | perm

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        ls = self.subject_labels.get(subject)
        lo = self.object_labels.get(obj)
        if ls is None or lo is None:
            return Decision(False, "мітку не призначено (safe default)")
        # Проста властивість безпеки: заборона читання вгору.
        if action & Permission.READ and not ls.dominates(lo):
            return Decision(False, "проста властивість: читання вгору заборонено")
        # Зіркова властивість: заборона запису вниз.
        if action & MODIFY and not lo.dominates(ls):
            return Decision(False, "зіркова властивість: запис униз заборонено")
        # Властивість дискреційної безпеки: операцію має дозволяти й матриця доступу.
        if (action & self.matrix.get((subject, obj), Permission.NONE)) != action:
            return Decision(False, "немає дискреційного дозволу (safe default)")
        return Decision(True, "надано")


class FanInDetector(AnomalyDetector):
    """Аномалія «звернення багатьох різних суб'єктів до одного об'єкта».

    Поріг передають параметром, а не фіксують у коді: так чутливість
    калібрують під політику без зміни детектора.
    """

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = threshold

    def scan(self, log: AuditLog) -> list[str]:
        subjects_by_object: dict[str, set[str]] = collections.defaultdict(set)
        for r in log.entries():
            subjects_by_object[r["object"]].add(r["subject"])
        return [
            f"до об'єкта {obj} звернулися {len(subj)} різних суб'єктів"
            for obj, subj in sorted(subjects_by_object.items())
            if len(subj) >= self.threshold
        ]
