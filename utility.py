from hashlib import sha3_256
from math import ceil


# 生成哈希这里应该用sm3算法的，可以装一下gmssl-python库直接使用，我没装上。。。
def generate_hash(msg):
    return sha3_256(msg).digest()


def KDF(Z, Klen):
    # 32位计数器
    ct = 0x00000001
    Ha = []
    K = b''
    for i in range(ceil(Klen / 256)):
        Ha.append(generate_hash(Z + ct.to_bytes(1, byteorder='big')))
        ct += 1
    if Klen % 256 == 0:
        Hai = Ha[ceil(Klen / 256) - 1]
    else:
        Hai = Ha[ceil(Klen / 256) - 1][0:Klen - 256 * (Klen // 256)]
    for i in range(ceil(Klen / 256) - 1):
        K += Ha[i]
    K += Hai
    return K
