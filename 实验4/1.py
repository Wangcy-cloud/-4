import gmpy2

def factor(n):
    """通过寻找平方差分解n的质因数p和q"""
    a = gmpy2.iroot(n, 2)[0]
    while True:
        a += 1
        b_squared = a * a - n
        if gmpy2.is_square(b_squared):
            b, _ = gmpy2.iroot(b_squared, 2)
            return (a - b, a + b)

def hex_to_char(hex_str):
    """十六进制字符串转UTF-8字符"""
    return bytes.fromhex(hex_str).decode('utf-8')

# 读取加密数据并解密
with open("Frame10") as f:
    data = f.read()
    n = int(data[:256], 16)
    e = int(data[256:512], 16)
    c = int(data[512:], 16)

p, q = factor(n)
print(f"p={hex(p)}")
print(f"q={hex(q)}")

phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
print(f"d={hex(d)}")

m = gmpy2.powmod(c, d, n)
print(f"m={hex(m)}")

plaintext = hex(m)[-16:]
print(hex_to_char(plaintext))