from random import randint
import sympy
from rsa.common import inverse


def generate_strong_prime_num(m):
    """
    Generate large prime numbers
    """
    q = sympy.randprime(10 **(len(str(m)) + 1), 10** (len(str(m)) + 2))
    p = 2 * q + 1
    while not sympy.isprime(q) and sympy.isprime(q):
        q = sympy.randprime(10 ** 100, 10 ** 200)
        p = 2 * q + 1
    return p, q


def modular_exponentiation(a, p, m):
    """
    Fast modular exponentiation, a^p(mod m)
    """
    binary_p = bin(p)
    reversed_binary_p = binary_p[len(binary_p):1:-1]

    # Result of the operation
    result = 1
    # Base corresponding to each binary bit
    bn = a
    for n in range(len(reversed_binary_p)):
        result = result * bn ** int(reversed_binary_p[n]) % m
        bn = bn ** 2 % m

    return result


def get_primitive_root(p, q):
    """
    Generate primitive root
    """
    g = randint(2, p - 2)
    # Since the strong prime is 2q+1, to find the primitive root of p, it is necessary to ensure that the results are not 1 when exponentiated to 2 and q modulo p
    while not(modular_exponentiation(g, 2, p) != 1 and modular_exponentiation(g, q, p) != 1):
        g = randint(2, p - 2)
    return g


def gcd(a, b):
    """
    Calculate greatest common divisor using Euclidean algorithm
    """
    if a < b:
        temp = a
        a = b
        b = temp

    if a % b == 0:
        return b

    return gcd(b, a % b)


def encrypt(p, g, y, m):
    """
    Encryption algorithm
    """
    k = randint(2, p - 2)
    while gcd(k, p - 1) != 1:
        k = randint(2, p - 2)

    c1 = modular_exponentiation(g, k, p)
    c2 = (m * modular_exponentiation(y, k, p)) % p
    return c1, c2


def decrypt(c1, c2, p, a):
    """
    Decryption algorithm
    """
    v = modular_exponentiation(c1, a, p)
    inverse_v = inverse(v, p)
    m = c2 * inverse_v % p
    return m


def main():
    m = 0
    with open("secret2.txt") as secret1:
        for line in secret1:
            m = int(line)
    secret1.close()

    p, q = generate_strong_prime_num(m)
    g = get_primitive_root(p, q)
    a = randint(2, p - 2)
    y = modular_exponentiation(g, a, p)
    c1, c2 = encrypt(p, g, y, m)
    decrypt_m = decrypt(c1, c2, p, a)

    if m == decrypt_m:
        print("Plaintext is consistent after encryption and decryption")
    else:
        print("Plaintext is inconsistent after encryption and decryption")
    return m, p, g, y, c1, c2, a, decrypt_m


if __name__ == '__main__':
    print("Read plaintext is：%d\n\np = %d\n\ng = %d\n\ng^a = %d\n\nCiphertext(c1, c2) = (%d,\n%d)\n\nk = %d\n\nRecovered plaintext m is：%d" % main())