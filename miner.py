# Майнер для игры "Майнеры" (блокчейн, Колесник)
# Строка: Номер;Фамилия;Данные;Сложность;ПредыдущийХеш;Nonce
# Ищем первый Nonce, при котором MD5 строки начинается с N нулей (N = сложность)

import hashlib

# ===== ВВОД (меняй тут) =====
NOMER = 2                  # номер блока
FAMILIYA = "Лебедев"       # фамилия
DANNYE = "Явыпилводу"      # любые данные
SLOZHNOST = 1              # сложность = число ведущих нулей
PREV_HASH = "jw21ndho92"   # хеш предыдущего блока (для генезис-блока оставь "")
START_NONCE = 0            # с какого Nonce начинать перебор
ALGO = "md5"               # "md5" или "sha256"
# ============================


def get_hash(s):
    if ALGO == "sha256":
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def make_line(nonce):
    return f"{NOMER};{FAMILIYA};{DANNYE};{SLOZHNOST};{PREV_HASH};{nonce}"


# --- Майнинг ---
target = "0" * SLOZHNOST
nonce = START_NONCE
h = get_hash(make_line(nonce))
while not h.startswith(target):
    nonce += 1
    h = get_hash(make_line(nonce))

print("Nonce:  ", nonce)
print("Строка: ", make_line(nonce))
print("Хеш:    ", h)
print("Попыток:", nonce - START_NONCE + 1)


# --- Проверка чужого блока (шаг 4 правил) ---
# Вставь строку из общей таблицы и хеш, который указал автор. Пусто = пропуск.
CHECK_LINE = ""            # например "2;Иванов;привет;1;abc123;17"
CHECK_HASH = ""            # хеш, который заявлен в таблице
CHECK_SLOZHNOST = 1        # текущая сложность сети

if CHECK_LINE:
    real = get_hash(CHECK_LINE)
    zeros = len(real) - len(real.lstrip("0"))
    print("\n--- Проверка блока ---")
    print("Реальный хеш:  ", real)
    print("Хеш совпадает: ", real == CHECK_HASH.strip().lower())
    print("Ведущих нулей: ", zeros, "(нужно >=", CHECK_SLOZHNOST, ")")
    print("Блок валиден:  ", real == CHECK_HASH.strip().lower() and zeros >= CHECK_SLOZHNOST)
