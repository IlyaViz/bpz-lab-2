# ЛР2. Розроблення підсистеми розмежування доступу

Дисципліна "Безпека програмного забезпечення", КПІ ім. Ігоря Сікорського.
Віжуткін Ілля, група ІП-31, варіант 4.

Варіант 4: модель Capabilities, правило "чотирьох очей" для критичних операцій,
аномалії "сплеск відмов у доступі від одного суб'єкта" і "послідовний перебір
ідентифікаторів об'єктів", 10 суб'єктів, 24 об'єкти.

Каркас (accesscontrol/, examples/, tests/test_example.py) і common/variants.py
взято з репозиторію курсу без змін. Власні файли:

- lab02_access_control/mypolicy.py - політика CapabilityPolicy, операційний журнал OperationLog, монітор VariantMonitor
- lab02_access_control/mydetector.py - детектор аномалій VariantDetector
- lab02_access_control/demo.py - демонстрація роботи підсистеми
- lab02_access_control/tests/test_variant.py - власні тести
- structure.drawio, structure.png - структурна схема

Запуск (з кореня репозиторію):

    python -m common.variants 4 --lab 2
    cd lab02_access_control
    pip install -r requirements.txt
    python demo.py
    python -m pytest tests/ -v
