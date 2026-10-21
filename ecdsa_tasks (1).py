# Практика "Алгоритм ECDSA" (блокчейн, Колесник) — задания 1-5
# Меняй только блок ВВОД и запускай.

import hashlib, hmac, base64, secrets

# ================= ВВОД =================
IMYA = "Лев"
FAMILIYA = "Лебедев"

MOD = 2027               # модуль из заданий 2 и 3
G3 = (24, 354)           # базовая точка из задания 3

# Закрытый ключ для заданий 4-5:
#  ""  -> скрипт сгенерирует новый (потом вставь его сюда, чтобы не менялся)
#  hex -> например "a1b2..."
#  PEM -> весь текст ключа с сайта emn178 в тройных кавычках
PRIV_KEY = ""
# ========================================

# Коды букв: А=1, Б=2, ... Ё=7, ... Я=33 (та же таблица, что в RSA)
ALFAVIT = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
c_im = ALFAVIT.index(IMYA[0].upper()) + 1
c_fam = ALFAVIT.index(FAMILIYA[0].upper()) + 1
print("Коды: %s = %d (имя), %s = %d (фамилия)\n" % (IMYA[0], c_im, FAMILIYA[0], c_fam))


def inv(a, m):
    old_r, r, old_x, x = a % m, m, 1, 0
    while r:
        k = old_r // r
        old_r, r = r, old_r - k * r
        old_x, x = x, old_x - k * x
    return old_x % m if old_r == 1 else None


def add(P, Q, a, p):                      # сложение точек по модулю p (None = бесконечность)
    if P is None: return Q
    if Q is None: return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        m = (3 * x1 * x1 + a) * inv(2 * y1, p) % p
    else:
        m = (y2 - y1) * inv(x2 - x1, p) % p
    x3 = (m * m - x1 - x2) % p
    return (x3, (m * (x1 - x3) - y1) % p)


def mul(k, P, a, p):                      # k*P: удвоение и сложение
    R = None
    while k:
        if k & 1: R = add(R, P, a, p)
        P = add(P, P, a, p)
        k >>= 1
    return R


# ===== Задание 1: P - Q на y^2 = x^3 + 7 над вещественными =====
print("=== Задание 1 ===")
x1, x2 = float(c_im), float(c_fam)
y1, y2 = (x1 ** 3 + 7) ** 0.5, (x2 ** 3 + 7) ** 0.5
print("P = (%g, %.4f)   Q = (%g, %.4f)   -Q = (%g, %.4f)" % (x1, y1, x2, y2, x2, -y2))
if x1 == x2:
    print("Буквы одинаковые: P = Q, значит P - Q = 0 (бесконечно удалённая точка), абсциссы нет")
else:
    m = (-y2 - y1) / (x2 - x1)            # прямая через P и -Q
    x3 = m * m - x1 - x2
    y3 = m * (x1 - x3) - y1
    print("P - Q = P + (-Q) = (%.4f, %.4f)" % (x3, y3))
    print("ОТВЕТ: %.4f" % x3)
print()

# ===== Задание 2: порядок группы y^2 = x^3 + a x + b (mod 2027) =====
print("=== Задание 2 ===")
a2, b2 = c_im, c_fam
print("a = %d, b = %d, p = %d" % (a2, b2, MOD))
if (4 * a2 ** 3 + 27 * b2 ** 2) % MOD == 0:
    print("ВНИМАНИЕ: кривая особая")
kv = {}
for y in range(MOD):
    kv[y * y % MOD] = kv.get(y * y % MOD, 0) + 1
cnt = sum(kv.get((x ** 3 + a2 * x + b2) % MOD, 0) for x in range(MOD))
print("Точек (x, y):", cnt, "+ 1 бесконечная")
print("ОТВЕТ:", cnt + 1)
print()

# ===== Задание 3: k*G на y^2 = x^3 + 7 (mod 2027) =====
print("=== Задание 3 ===")
k3 = c_im + c_fam
print("G = %s на кривой? %s,  k = %d + %d = %d" % (G3, (G3[1] ** 2 - G3[0] ** 3 - 7) % MOD == 0, c_im, c_fam, k3))
R3 = mul(k3, G3, 0, MOD)
print("%d*G =" % k3, R3 if R3 else "бесконечность")
print("ОТВЕТ:", R3[0] if R3 else "точка на бесконечности")
print()

# ===== Задания 4-5: ECDSA secp256k1 + SHA256 =====
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def pem(der_bytes, title):
    b = base64.b64encode(der_bytes).decode()
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----" % (title, "\n".join(lines), title)


def read_priv(s):
    s = s.strip()
    if "BEGIN" in s:                      # ключ лежит после 02 01 01 04 20
        body, inside = "", False           # берём только блок PRIVATE KEY (EC PARAMETERS пропускаем)
        for l in s.splitlines():
            if "BEGIN" in l: inside = "PRIVATE KEY" in l
            elif "END" in l: inside = False
            elif inside: body += l.strip()
        der = base64.b64decode(body)
        i = der.find(b"\x02\x01\x01\x04\x20")
        return int.from_bytes(der[i + 5:i + 37], "big")
    return int(s, 16)


def det_k(d, z):                          # детерминированное k (RFC 6979)
    x, h = d.to_bytes(32, "big"), (z % n).to_bytes(32, "big")
    HM = lambda key, data: hmac.new(key, data, hashlib.sha256).digest()
    K, V = b"\x00" * 32, b"\x01" * 32
    K = HM(K, V + b"\x00" + x + h); V = HM(K, V)
    K = HM(K, V + b"\x01" + x + h); V = HM(K, V)
    while True:
        V = HM(K, V)
        k = int.from_bytes(V, "big")
        if 1 <= k < n: return k
        K = HM(K, V + b"\x00"); V = HM(K, V)


def der_int(v):
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if b[0] & 0x80: b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


print("=== Задание 4 ===")
if PRIV_KEY.strip():
    d = read_priv(PRIV_KEY)
else:
    d = secrets.randbelow(n - 1) + 1
    print("Сгенерирован новый ключ. Вставь hex ниже в PRIV_KEY, чтобы при перезапуске он не менялся.")
Q = mul(d, G, 0, p)
pub_raw = b"\x04" + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
spki = bytes.fromhex("3056301006072a8648ce3d020106052b8104000a034200") + pub_raw
sec1 = (bytes.fromhex("30740201010420") + d.to_bytes(32, "big")
        + bytes.fromhex("a00706052b8104000aa144034200") + pub_raw)
print("Закрытый ключ (hex):", "%064x" % d)
print(pem(sec1, "EC PRIVATE KEY"))
print("ОТВЕТ (открытый ключ PEM):")
print(pem(spki, "PUBLIC KEY"))
print()

print("=== Задание 5 ===")
msg = FAMILIYA.encode("utf-8")
z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
k = det_k(d, z)
r = mul(k, G, 0, p)[0] % n
s = inv(k, n) * (z + r * d) % n
body = der_int(r) + der_int(s)
sig = (b"\x30" + bytes([len(body)]) + body).hex()
print("Сообщение:", FAMILIYA, " SHA256:", hashlib.sha256(msg).hexdigest())
# самопроверка: u1*G + u2*Q должно дать r
w = inv(s, n)
X = add(mul(z * w % n, G, 0, p), mul(r * w % n, Q, 0, p), 0, p)
print("Самопроверка подписи:", "OK" if X[0] % n == r else "ОШИБКА")
print("ОТВЕТ (подпись HEX):")
print(sig)
