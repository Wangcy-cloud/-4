import gmpy2

def gcd(a, b):
    """计算最大公约数"""
    while b != 0:
        a, b = b, a % b
    return a

def hex_to_char(hex_str):
    """十六进制字符串转UTF-8字符"""
    try:
        # 确保十六进制字符串长度为偶数
        hex_str = hex_str.strip()
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"转换错误: {e}")
        return ""

def read_frame(filename):
    """读取Frame文件"""
    try:
        with open(filename) as f:
            data = f.read().strip()
            if len(data) < 768:
                raise ValueError(f"文件数据长度不足: {len(data)}")
            return (int(data[:256], 16), 
                    int(data[256:512], 16), 
                    int(data[512:768], 16))
    except Exception as e:
        print(f"读取文件 {filename} 错误: {e}")
        return None, None, None

def decrypt(p, n, e, c):
    """使用已知素数p解密数据"""
    if n % p != 0:
        raise ValueError("p 不是 n 的因子")
    
    q = n // p
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    m = pow(c, d, n)
    return hex(m)

def main():
    # 读取两个Frame的加密数据
    n1, e1, c1 = read_frame("Frame1")
    n2, e2, c2 = read_frame("Frame18")
    
    if None in [n1, e1, c1, n2, e2, c2]:
        return
    
    print(f"n1 位数: {len(str(n1))}")
    print(f"n2 位数: {len(str(n2))}")
    
    # 找到公共素数p
    p = gcd(n1, n2)
    print(f"找到公共素数 p: {p > 1}")
    
    if p == 1:
        print("错误: 没有找到公共素数")
        return
    
    print(f"p 位数: {len(str(p))}")
    
    # 验证p确实是因子
    print(f"n1 % p == 0: {n1 % p == 0}")
    print(f"n2 % p == 0: {n2 % p == 0}")
    
    # 解密第一个Frame
    try:
        cipher1 = decrypt(p, n1, e1, c1)
        print(f"\nFrame1 解密结果:")
        print(f"十六进制: {cipher1}")
        hex_str1 = cipher1[2:]  # 去掉0x前缀
        if len(hex_str1) >= 16:
            text1 = hex_to_char(hex_str1[-16:])
            print(f"最后16字符解码: {text1}")
    except Exception as e:
        print(f"Frame1 解密失败: {e}")
    
    # 解密第二个Frame
    try:
        cipher2 = decrypt(p, n2, e2, c2)
        print(f"\nFrame18 解密结果:")
        print(f"十六进制: {cipher2}")
        hex_str2 = cipher2[2:]  # 去掉0x前缀
        if len(hex_str2) >= 16:
            text2 = hex_to_char(hex_str2[-16:])
            print(f"最后16字符解码: {text2}")
    except Exception as e:
        print(f"Frame18 解密失败: {e}")

if __name__ == "__main__":
    main()
