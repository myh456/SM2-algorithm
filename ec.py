def scalar_multiply(P, k, a, p):
    # 初始化
    R = None  # R 用来存储计算过程中的临时结果
    # 乘法转加法
    while k:
        R = point_add(R, P, a, p)
        k -= 1
    return R


def point_add(P, Q, a, p):
    # 点加法操作，计算 P + Q
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] == mod_inverse(-Q[1], p) or mod_inverse(-P[1], p) == Q[1]):
        return None  # 反相点相加为无穷远点
    if P[0] == Q[0] and P[1] == Q[1]:
        # 计算斜率 k = (3 * x1^2 + a) / (2 * y1)
        k = ((3 * P[0] * P[0] + a) * mod_inverse(2 * P[1], p)) % p
    else:
        # 计算斜率 k = (y2 - y1) / (x2 - x1)
        k = (Q[1] - P[1]) * mod_inverse(Q[0] - P[0], p)
    x3 = (k * k - P[0] - Q[0]) % p
    y3 = (k * (P[0] - x3) - P[1]) % p
    return [x3, y3]


def exgcd(a, b):
    # 扩展欧几里得算法，返回 (gcd, x, y) 使得 a * x + b * y = gcd
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = exgcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y


def mod_inverse(a, n):
    # 求 a 在模 n 下的逆元
    # 已知 ad ≡ 1 (mod n) 可以写作 ad - nk = 1
    gcd, d, k = exgcd(a, n)
    # d 是 e 的逆元，但是它可能是负数，因此需要调整为正数
    return d % n


def satisfy(C, a, b, p):
    return (C[1] ** 2) % p == (C[0] ** 3 + a * C[0] + b) % p
