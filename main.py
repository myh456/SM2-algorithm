from sm2 import SM2

if __name__ == '__main__':
    sm2 = SM2()
    Pb = sm2.subkey()
    print('密钥已生成')

    print('明文16进制', b'hello'.hex())
    C = sm2.enc(b'hello', Pb)
    if C == 0:
        print('无效公钥')
        exit(0)
    print('密文16进制:', C.hex())
    M = sm2.dec(C)
    if M == 0:
        print('C1为无穷远点')
        exit(0)
    elif M == 1:
        print('C1不满足椭圆曲线')
        exit(0)
    elif M == 3:
        print('密文被篡改')
        exit(0)
    print('明文16进制:', M.hex())

    s = sm2.signature(M, Pb)
    info = sm2.verification(M, s[0], s[1], Pb)
    if info == 0:
        print('非法签名')
    elif info == 1:
        print('签名信息有误')
    elif info == 2:
        print('签名错误')
    else:
        print('签名验证成功')

