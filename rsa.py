# RSA: ключи, шифр, подпись, проверка подписи (блокчейн, Колесник)
# Подставь свою строку из таблицы и запусти.

# ===== ВВОД (меняй тут) =====
FAMILIYA = "Безрук"        # фамилия
IMYA = "Арина"             # имя
P = 661                    # P из таблицы
Q = 2017                   # Q из таблицы
E = 65537                  # e (по заданию 65537)

PODPIS = 1068768           # Подпись из таблицы (для задания 4)
PUB_E = 199                # открытый ключ из задания 4: (e, n)
PUB_N = 1113649
# ============================

# Коды букв: А=01, Б=02, ... Ё=07, ... П=17, ... Я=33 (по 2 цифры)
ALFAVIT = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"


def inverse(a, m):
    # обратное число: a*x ≡ 1 (mod m), расширенный алгоритм Евклида
    old_r, r = a, m
    old_x, x = 1, 0
    while r != 0:
        k = old_r // r
        old_r, r = r, old_r - k * r
        old_x, x = x, old_x - k * x
    if old_r != 1:
        return None  # обратного нет (e и phi не взаимно просты)
    return old_x % m


def letter_code(ch):
    return "%02d" % (ALFAVIT.index(ch.upper()) + 1)


# --- Задание 1: ключи ---
n = P * Q
phi = (P - 1) * (Q - 1)
d = inverse(E, phi)
print("=== Задание 1: ключи ===")
print("n = P*Q =", n)
print("phi = (P-1)*(Q-1) =", phi)
if d is None:
    print("ОШИБКА: e и phi не взаимно просты, d не существует")
else:
    print("Проверка: e*d mod phi =", E * d % phi)
    print("Открытый ключ (e, n) = (%d, %d)" % (E, n))
    print("ОТВЕТ: закрытый ключ (d, n) = (%d, %d)" % (d, n))

# --- Задание 2: шифрование ---
code_str = letter_code(FAMILIYA[0]) + letter_code(IMYA[0])
m = int(code_str)
c = pow(m, E, n)
print("\n=== Задание 2: шифр ===")
print("Буквы:", FAMILIYA[0].upper(), IMYA[0].upper(), "-> код", code_str, "-> m =", m)
if m >= n:
    print("ВНИМАНИЕ: m >= n, так шифровать нельзя")
print("c = m^e mod n =", c)
print("Проверка расшифровки: c^d mod n =", pow(c, d, n) if d else "-")
print("ОТВЕТ: шифр =", c)

# --- Задание 3: подпись ---
s = pow(m, d, n) if d else None
print("\n=== Задание 3: подпись ===")
print("s = m^d mod n =", s)
print("Проверка своей подписью: s^e mod n =", pow(s, E, n) if s else "-", "(должно быть", m, ")")
print("ОТВЕТ: подпись =", s)

# --- Задание 4: проверка подписи из таблицы ---
check = pow(PODPIS, PUB_E, PUB_N)
print("\n=== Задание 4: проверка подписи ===")
print("Подпись из таблицы:", PODPIS, " ключ (%d, %d)" % (PUB_E, PUB_N))
print("Подпись^e mod n =", check, " сообщение m =", m)
print("ОТВЕТ: подпись", "ВЕРНА" if check == m else "НЕВЕРНА")
