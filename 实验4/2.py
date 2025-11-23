from random import randint
import sympy
from rsa.common import inverse
import os


def create_test_file(filename="secret2.txt", content="123456789"):
    """创建测试文件"""
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            f.write(content)
        print(f"已创建测试文件 {filename}，内容为: {content}")
    return filename


def generate_strong_prime(m):
    """
    Generate strong prime p = 2q + 1 where both p and q are prime
    p must be larger than the message m
    """
    # 确保素数p比明文m大
    m_digits = len(str(m))
    
    # 生成比明文大得多的素数
    lower_bound = 10 ** (m_digits + 10)  # 比明文多10位
    upper_bound = 10 ** (m_digits + 20)  # 比明文多20位
    
    print(f"明文位数: {m_digits}")
    print(f"生成素数范围: 10^{m_digits + 10} 到 10^{m_digits + 20}")
    
    max_attempts = 100
    attempts = 0
    
    while attempts < max_attempts:
        q = sympy.randprime(lower_bound, upper_bound)
        p = 2 * q + 1
        
        if sympy.isprime(p) and p > m:
            print(f"成功生成强素数 (尝试次数: {attempts + 1})")
            return p, q
        
        attempts += 1
    
    # 如果找不到合适的强素数，使用普通大素数
    print("未找到合适的强素数，使用普通大素数")
    p = sympy.randprime(lower_bound, upper_bound)
    while p <= m:
        p = sympy.randprime(lower_bound, upper_bound)
    return p, None


def modular_exponentiation(base, exponent, modulus):
    """
    Fast modular exponentiation using square-and-multiply algorithm
    """
    if modulus == 1:
        return 0
    
    result = 1
    base = base % modulus
    
    while exponent > 0:
        # 如果当前位是1，乘以base
        if exponent & 1:
            result = (result * base) % modulus
        # 平方base
        base = (base * base) % modulus
        # 移到下一位
        exponent = exponent >> 1
    
    return result


def get_primitive_root(p, q=None):
    """
    Generate primitive root modulo p
    """
    if q is None:
        # 如果不是强素数，使用更通用的方法找原根
        factors = sympy.factorint(p - 1)
        attempts = 0
        max_attempts = 1000
        
        while attempts < max_attempts:
            g = randint(2, p - 2)
            is_primitive = True
            
            # 检查对于p-1的每个质因子prime，g^((p-1)/prime) ≠ 1 (mod p)
            for prime in factors:
                exponent = (p - 1) // prime
                if modular_exponentiation(g, exponent, p) == 1:
                    is_primitive = False
                    break
            
            if is_primitive:
                return g
            attempts += 1
        
        # 如果随机找不到，尝试小数字
        for g in range(2, min(1000, p - 1)):
            is_primitive = True
            for prime in factors:
                exponent = (p - 1) // prime
                if modular_exponentiation(g, exponent, p) == 1:
                    is_primitive = False
                    break
            if is_primitive:
                return g
        
        raise ValueError("无法找到原根")
    else:
        # 强素数的情况
        while True:
            g = randint(2, p - 2)
            # 检查g是否是原根：g^2 ≠ 1 (mod p) 且 g^q ≠ 1 (mod p)
            if (modular_exponentiation(g, 2, p) != 1 and 
                modular_exponentiation(g, q, p) != 1):
                return g


def extended_gcd(a, b):
    """
    Extended Euclidean algorithm
    Returns (gcd, x, y) such that ax + by = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y


def mod_inverse(a, m):
    """
    Calculate modular inverse using extended Euclidean algorithm
    """
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError(f"Modular inverse doesn't exist for {a} mod {m}")
    return x % m


def encrypt(p, g, y, m):
    """
    ElGamal encryption algorithm
    """
    # 确保明文在有效范围内
    if m >= p:
        raise ValueError(f"Message {m} is too large for modulus {p}")
    
    # 选择随机k，需要与p-1互质
    while True:
        k = randint(2, p - 2)
        gcd_val, _, _ = extended_gcd(k, p - 1)
        if gcd_val == 1:
            break
    
    c1 = modular_exponentiation(g, k, p)
    c2 = (m * modular_exponentiation(y, k, p)) % p
    return c1, c2


def decrypt(c1, c2, p, private_key):
    """
    ElGamal decryption algorithm
    """
    # 计算共享秘密
    shared_secret = modular_exponentiation(c1, private_key, p)
    # 计算共享秘密的模逆
    inverse_shared_secret = mod_inverse(shared_secret, p)
    # 恢复明文
    m = (c2 * inverse_shared_secret) % p
    return m


def main():
    """主函数"""
    try:
        # 确保测试文件存在
        filename = create_test_file()
        
        # 读取明文
        with open(filename, "r") as file:
            m = int(file.read().strip())
        
        print(f"读取的明文: {m}")
        print(f"明文位数: {len(str(m))}")
        
        # 生成密码学参数
        print("生成强素数...")
        p, q = generate_strong_prime(m)
        print(f"生成的素数 p 的位数: {len(str(p))}")
        print(f"p > m: {p > m}")
        
        print("寻找原根...")
        g = get_primitive_root(p, q)
        print(f"原根找到: g")
        
        # 生成密钥对
        private_key = randint(2, p - 2)
        public_key = modular_exponentiation(g, private_key, p)
        print(f"密钥对生成完成")
        
        # 加密
        print("加密中...")
        c1, c2 = encrypt(p, g, public_key, m)
        print(f"加密完成")
        
        # 解密
        print("解密中...")
        decrypted_m = decrypt(c1, c2, p, private_key)
        print(f"解密完成")
        
        # 验证
        if m == decrypted_m:
            print("✅ 加密解密成功！明文一致")
        else:
            print("❌ 加密解密失败！明文不一致")
            print(f"原始明文: {m}")
            print(f"解密明文: {decrypted_m}")
        
        return m, p, g, public_key, c1, c2, private_key, decrypted_m
        
    except FileNotFoundError:
        print(f"错误：文件 {filename} 未找到")
        return None
    except ValueError as e:
        print(f"错误：数据格式错误 - {e}")
        return None
    except Exception as e:
        print(f"错误：{e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == '__main__':
    print("=" * 50)
    print("ElGamal加密系统")
    print("=" * 50)
    
    result = main()
    
    if result:
        m, p, g, y, c1, c2, a, decrypt_m = result
        print("\n" + "=" * 50)
        print("加密解密成功！详细参数：")
        print("=" * 50)
        print(f"明文 m: {m}")
        print(f"素数 p: {p}")
        print(f"原根 g: {g}")
        print(f"公钥 g^a: {y}")
        print(f"私钥 a: {a}")
        print(f"密文 c1: {c1}")
        print(f"密文 c2: {c2}")
        print(f"解密结果: {decrypt_m}")
        print(f"验证结果: {'成功' if m == decrypt_m else '失败'}")