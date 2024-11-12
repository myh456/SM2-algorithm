import random
import ec

import utility


class SM2:
    def __init__(self):
        # 需要保存的私钥
        self.d = 0x0
        # SM2规定的参数
        # 用于确定椭圆曲线
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        # Fp的特征值
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        # 基点坐标
        self.G = [
            0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
            0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        ]
        # 椭圆曲线的阶
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

    def subkey(self):
        # 随机生成d作为私钥
        self.d = random.randint(1, self.n - 1)
        # 这里只是为了方便，把公钥保存为数对，SM2的公钥应该保存为256位x坐标拼接256位y坐标的512位数
        return ec.scalar_multiply(self.G, self.d, self.a, self.p)

    # 加密函数
    def enc(self, M, Pb):
        # 如果h * Pb是无穷远点则退出，其中SM2的h余因子为1
        if Pb == 0:
            return 0
        C1 = x2 = y2 = b''
        klen = len(M)
        t = 0
        while t == 0:
            # 随机选择k属于[1, n-1]
            k = random.randint(1, self.n - 1)
            # 计算C1 = kG = (x1, y1)，把x1,y1保存为字节串
            C1 = ec.scalar_multiply(self.G, k, self.a, self.p)
            if C1 is None:
                continue
            x1 = C1[0].to_bytes(32)
            y1 = C1[1].to_bytes(32)
            C1 = x1 + y1
            # 计算kPb = (x2, y2)，把x2，y2保存为字节串，如果kPb是无穷远点就重新生成k
            kPb = ec.scalar_multiply(Pb, k, self.a, self.p)
            if kPb is None:
                continue
            x2 = kPb[0].to_bytes(32)
            y2 = kPb[1].to_bytes(32)
            # 计算密钥t = KDF(x2|y2, klen)，如果是0就重新生成k（这里写一个do while循环合适，但是python没有）
            t = utility.KDF(x2 + y2, klen)
        # C2 = M ⊕ t
        C2 = (int.from_bytes(M) ^ int.from_bytes(t)).to_bytes(klen)
        # C3 = Hash(x2|C2|y2)
        C3 = utility.generate_hash(x2 + C2 + y2)
        # 返回密文C = (C1|C2|C3)
        return C1 + C2 + C3

    def dec(self, C):
        klen = len(C) - 64 - 32
        # 判断C1是不是无穷远点(64位字节串是不是全0)
        if C[0:64].count(b'\x00') == 64:
            return 0
        # 抽取C1的坐标，判断是否满足椭圆曲线群
        x1 = int.from_bytes(C[0:32])
        y1 = int.from_bytes(C[32:64])
        if not ec.satisfy([x1, y1], self.a, self.b, self.p):
            return 1
        # 计算dC1 = (x2, y2)，把x2，y2保存为字节串
        [x2, y2] = ec.scalar_multiply([x1, y1], self.d, self.a, self.p)
        x2 = x2.to_bytes(32)
        y2 = y2.to_bytes(32)
        # 计算密钥t = KDF(x2|y2, klen)，klen是C2的长度
        t = utility.KDF(x2 + y2, klen)
        # 计算明文M = C2 ⊕ t
        M = (int.from_bytes(C[64:-32]) ^ int.from_bytes(t)).to_bytes(klen)
        # 判断完整性
        if utility.generate_hash(x2 + M + y2) == C[-32:]:
            return 3
        # 输出明文
        return M

    def signature(self, M, P):
        r = k = s = 0
        # Za = H256(len(M)|M|a|b|xG|yG|xP|yP)
        Za = utility.generate_hash(
            len(M).to_bytes(16) + M + self.a.to_bytes(32) + self.b.to_bytes(32) + self.G[0].to_bytes(32) +
            self.G[1].to_bytes(32) + P[0].to_bytes(32) + P[1].to_bytes(32)
        )
        # Ml = Zₐ|M
        Ml = Za + M
        # e = Hv(Ml)，将e转成整数，Hv是输出v长度的哈希函数
        e = int.from_bytes(utility.generate_hash(Ml))
        while r == 0 or r + k == self.n or s == 0:
            # 随机选择k属于[1, n-1]
            k = random.randint(1, self.n - 1)
            # C1 = kG
            C1 = ec.scalar_multiply(self.G, k, self.a, self.p)
            # r = (e + x1) mod n，若r=0或r+k=n，则重新生成k
            r = (e + C1[0]) % self.n
            # s = ( (1 + d) ^ -1 * ( k - r * d )) mod n，若s=0，则重新生成k
            s = (ec.mod_inverse(1 + self.d, self.n) * (k - r * self.d)) % self.n
        return [r, s]

    def verification(self, Mp, rp, sp, Pb,):
        # 如果r`和s`不满足满足取模范围，则不是合法签名
        if not (1 <= rp <= self.n - 1 and 1 <= sp <= self.n - 1):
            return 0
        # 计算Zₐ`
        Zap = utility.generate_hash(
            len(Mp).to_bytes(16) + Mp + self.a.to_bytes(32) + self.b.to_bytes(32) + self.G[0].to_bytes(32) +
            self.G[1].to_bytes(32) + Pb[0].to_bytes(32) + Pb[1].to_bytes(32)
        )
        # Ml` = Za`|M`
        Mlp = Zap + Mp
        # e` = Hv(Ml`)
        ep = int.from_bytes(utility.generate_hash(Mlp))
        # t = (r` + s`) mod n
        t = (rp + sp) % self.n
        if t == 0:
            return 1
        # (x1`, y1`) = s`G + tP
        [x1p, _] = ec.point_add(
            ec.scalar_multiply(self.G, sp, self.a, self.p),
            ec.scalar_multiply(Pb, t, self.a, self.p),
            self.p
        )
        R = (ep + x1p) % self.n
        if R != rp:
            return 2
        else:
            return 3
