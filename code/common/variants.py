"""Генератор індивідуальних завдань за номером варіанта.

Варіант — номер здобувача у списку академічної групи (1–30). Усі параметри
детерміновані: той самий номер завжди дає той самий набір. Це дозволяє
викладачеві відтворити очікуваний результат, не зберігаючи таблиць.

Використання:

    python -m common.variants 7
    python -m common.variants 7 --lab 4
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys

MIN_VARIANT = 1
MAX_VARIANT = 30


def _params(seq_len: int, salt: str) -> tuple[int, int]:
    """Детерміновані (крок, зсув) для рівномірного розкладу варіантів по списку.

    Крок обирається взаємно простим із довжиною списку, тому послідовність
    index(v) = ((v-1)*step + shift) % seq_len обходить усі елементи циклічно
    й розподіляє 30 варіантів максимально рівномірно, а різні поля
    (різні salt) декорелюються між собою.
    """
    h = hashlib.sha256(f"bpz-2026|{salt}".encode("utf-8")).digest()
    shift = h[0] % seq_len
    step = 1 + h[1] % max(1, seq_len - 1)
    while math.gcd(step, seq_len) != 1:
        step += 1
        if step >= seq_len:
            step = 1
            break
    return step, shift


def _coprimes(n: int) -> list[int]:
    """Кроки, взаємно прості з n, — усі вони обходять список повністю."""
    return [k for k in range(1, n) if math.gcd(k, n) == 1] or [1]


def _index(n: int, variant: int, salt: str, cycle_of: int | None = None) -> int:
    """Індекс елемента для варіанта.

    `cycle_of` — довжина списку поля, з яким це поле утворює пару. Доданок
    (variant-1)//cycle_of зсуває послідовність на кожному оберті ПАРНОГО поля,
    тому комбінація двох полів не повторюється. Без нього списки з довжинами,
    що мають спільний дільник (наприклад 15 і 5), давали б однакові пари, і два
    здобувачі отримали б тотожне завдання.
    """
    step, shift = _params(n, salt)
    v = variant - 1
    return (v * step + shift + v // (cycle_of or n)) % n


def _pick(seq, variant: int, salt: str, cycle_of: int | None = None):
    """Рівномірний детермінований вибір одного елемента."""
    return seq[_index(len(seq), variant, salt, cycle_of)]


def _pick_many(seq, variant: int, salt: str, count: int):
    """Рівномірний детермінований вибір `count` різних елементів.

    Використано перестановку Фішера–Єйтса з детермінованим потоком байтів
    від (salt, variant). Обхід зі сталим кроком тут не годиться: множина
    {s, s+g, …} визначається лише початком, а кроки g і n−g дають ту саму
    множину, тому різних наборів виходило б удвічі менше за потрібне.
    """
    n = len(seq)
    count = min(count, n)
    pool = list(seq)
    stream = hashlib.shake_256(f"bpz-2026|{salt}|{variant}".encode("utf-8")).digest(4 * n)
    for i in range(n - 1, 0, -1):
        j = int.from_bytes(stream[4 * i:4 * i + 4], "big") % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]
    return pool[:count]


# ── Лабораторна робота 1. Модель загроз ──────────────────────────────────────

LAB1_SYSTEMS = [
    "вебсервіс запису на прийом до лікаря",
    "система електронного документообігу кафедри",
    "мобільний застосунок обліку особистих фінансів",
    "платформа онлайн-курсів із перевіркою завдань",
    "система бронювання аудиторій університету",
    "сервіс обміну файлами між студентами",
    "система контролю доступу до лабораторії за перепустками",
    "агрегатор вакансій із відгуками роботодавців",
    "внутрішній чат-сервіс компанії",
    "сервіс приймання показань лічильників",
    "система обліку відвідуваності занять",
    "маркетплейс вживаних підручників",
    "платформа електронного голосування студради",
    "сервіс зберігання резервних копій проєктів",
    "система моніторингу серверів із сповіщеннями",
]

LAB1_FOCUS = [
    "підвищення привілеїв (Elevation of privilege)",
    "розкриття інформації (Information disclosure)",
    "підміна даних (Tampering)",
    "спуфінг (Spoofing)",
    "відмова від авторства (Repudiation)",
]

# ── Лабораторна робота 2. Розмежування доступу ───────────────────────────────

LAB2_MODEL = ["ACL з успадкуванням", "Capabilities", "RBAC з ієрархією ролей", "ABAC"]
LAB2_EXTRA = [
    "заборонні записи (deny) з пріоритетом над дозвільними",
    "тимчасові права з терміном дії",
    "делегування прав із обмеженням глибини",
    "розділення обов'язків (заборона поєднання ролей)",
    "правило «чотирьох очей» для критичних операцій",
]
LAB2_ANOMALY = [
    "сплеск відмов у доступі від одного суб'єкта",
    "доступ поза типовим часовим вікном",
    "послідовний перебір ідентифікаторів об'єктів",
    "різке зростання обсягу зчитаних даних",
    "використання прав, не задіяних раніше",
]

# ── Лабораторна робота 3. Автентифікація ─────────────────────────────────────

LAB3_KDF = ["Argon2id", "scrypt", "bcrypt", "PBKDF2-HMAC-SHA256"]
LAB3_SECOND_FACTOR = ["TOTP (RFC 6238)", "HOTP (RFC 4226)", "одноразові коди відновлення"]
LAB3_ANDERSON = [
    # (період дії пароля, діб; швидкість спроб, за хвилину; допустима ймовірність підбору)
    (30, 8, 1e-6), (60, 10, 1e-6), (90, 5, 1e-7), (30, 20, 1e-6),
    (180, 4, 1e-7), (45, 15, 1e-6), (365, 2, 1e-8), (14, 30, 1e-5),
    (60, 6, 1e-7), (120, 12, 1e-6),
]
LAB3_LOCKOUT = [
    "фіксоване блокування на 15 хв після 5 невдалих спроб",
    "прогресивна затримка (подвоєння інтервалу)",
    "блокування за парою «обліковий запис + IP»",
    "квота спроб у ковзному вікні",
]

# ── Лабораторна робота 4. Криптографія ───────────────────────────────────────

LAB4_AEAD = ["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"]
LAB4_SIGN = ["RSA-PSS (2048)", "ECDSA (P-256)", "Ed25519"]
LAB4_RSA_BITS = [16, 20, 24, 28, 32]  # для навчальної реалізації з малими числами
LAB4_MISUSE = [
    "режим ECB замість AEAD",
    "повторне використання nonce у GCM",
    "статичний вектор ініціалізації в CBC",
    "порівняння тегів оператором ==",
    "хешування пароля без солі",
    "MAC-then-Encrypt замість Encrypt-then-MAC",
]

# ── Лабораторна робота 5. OWASP Top 10 ───────────────────────────────────────

LAB5_VULNS = [
    "SQL-ін'єкція у пошуку",
    "збережений XSS у коментарях",
    "відображений XSS у повідомленні про помилку",
    "CSRF у зміні профілю",
    "IDOR у перегляді документів",
    "SSRF у завантаженні за URL",
    "обхід каталогів у вивантаженні файлу",
    "небезпечна десеріалізація в cookie",
    "розкриття даних у повідомленні про помилку",
    "відсутність перевірки прав в адміністративному маршруті",
]

LAB5_PROOF = [
    "знімок екрана з відповіддю сервера та curl-командою",
    "автоматизований сценарій відтворення (pytest або requests)",
    "HTTP-запит і відповідь у форматі HAR",
    "відеозапис послідовності дій тривалістю до 60 с",
    "покроковий протокол із зазначенням параметрів і очікуваного та фактичного результату",
]

# ── Лабораторна робота 6. CI/CD ──────────────────────────────────────────────

LAB6_SAST = ["Semgrep", "Bandit", "Semgrep + власне правило"]
LAB6_GATE = [
    "блокувати складання за наявності знахідок рівня HIGH",
    "блокувати за появи нових знахідок відносно базової лінії",
    "блокувати за наявності секрету в діффі",
    "блокувати за вразливої залежності з CVSS ≥ 7.0",
]


def variant_spec(variant: int) -> dict:
    """Повертає повний набір параметрів для всіх шести лабораторних робіт."""
    if not MIN_VARIANT <= variant <= MAX_VARIANT:
        raise ValueError(f"Номер варіанта має бути в межах {MIN_VARIANT}–{MAX_VARIANT}")

    return {
        "variant": variant,
        "lab1": {
            "system": _pick(LAB1_SYSTEMS, variant, "lab1-sys"),
            "focus_category": _pick(LAB1_FOCUS, variant, "lab1-focus",
                                    cycle_of=len(LAB1_SYSTEMS)),
            "min_threats": 12,
            "min_high_risk": 3,
        },
        "lab2": {
            "model": _pick(LAB2_MODEL, variant, "lab2-model"),
            "extra_rule": _pick(LAB2_EXTRA, variant, "lab2-extra"),
            "anomalies": _pick_many(LAB2_ANOMALY, variant, "lab2-anom", 2),
            "subjects": 6 + variant % 5,
            "objects": 20 + variant % 11,
        },
        "lab3": {
            "kdf": _pick(LAB3_KDF, variant, "lab3-kdf"),
            "second_factor": _pick(LAB3_SECOND_FACTOR, variant, "lab3-2fa"),
            "lockout": _pick(LAB3_LOCKOUT, variant, "lab3-lock"),
            "anderson": dict(zip(
                ("period_days", "guesses_per_minute", "max_probability"),
                _pick(LAB3_ANDERSON, variant, "lab3-and"))),
        },
        "lab4": {
            "aead": _pick(LAB4_AEAD, variant, "lab4-aead"),
            "signature": _pick(LAB4_SIGN, variant, "lab4-sign"),
            "rsa_demo_bits": _pick(LAB4_RSA_BITS, variant, "lab4-bits"),
            "misuse_to_demonstrate": _pick_many(LAB4_MISUSE, variant, "lab4-misuse", 2),
        },
        "lab5": {
            "required": _pick_many(LAB5_VULNS, variant, "lab5-vuln", 5),
            "proof_form": _pick(LAB5_PROOF, variant, "lab5-proof",
                                cycle_of=len(LAB5_VULNS)),
        },
        "lab6": {
            "sast": _pick(LAB6_SAST, variant, "lab6-sast"),
            "gate": _pick(LAB6_GATE, variant, "lab6-gate"),
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Параметри індивідуального завдання за варіантом")
    ap.add_argument("variant", nargs="?", type=int, default=int(os.environ.get("VARIANT", 1)))
    ap.add_argument("--lab", type=int, choices=range(1, 7), help="показати лише одну роботу")
    ap.add_argument("--json", action="store_true", help="вивід у форматі JSON")
    args = ap.parse_args(argv)

    spec = variant_spec(args.variant)
    if args.lab:
        spec = {"variant": spec["variant"], f"lab{args.lab}": spec[f"lab{args.lab}"]}

    if args.json:
        print(json.dumps(spec, ensure_ascii=False, indent=2))
        return 0

    print(f"Варіант {spec['variant']}")
    for key, value in spec.items():
        if key == "variant":
            continue
        print(f"\n  {key.upper()}")
        for k, v in value.items():
            if isinstance(v, list):
                print(f"    {k}:")
                for item in v:
                    print(f"      – {item}")
            elif isinstance(v, dict):
                print(f"    {k}: " + ", ".join(f"{a}={b}" for a, b in v.items()))
            else:
                print(f"    {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
