import math
import random

M89 = 2 ** 89 - 1           

def mod_pow(a, x, p):
    result = 1
    a %= p
    while x > 0:
        if x & 1:
            result = (result * a) % p
        a = (a * a) % p
        x >>= 1
    return result


SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n, k=40):
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:                    
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False                
    return True                         


def gen_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1   
        if is_prime(n):
            return n


def largest_primes_below(limit, count=10):
    found = []
    n = limit - 1 if limit % 2 == 0 else limit - 2   
    while len(found) < count:
        if is_prime(n):
            found.append(n)
        n -= 2
    return found


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def demo():
    print("=== 1a. So nguyen to ngau nhien ===")
    for b in (8, 16, 64):
        p = gen_prime(b)
        print(f"{b:>2} bit: {p}  (bit_length = {p.bit_length()})")

    print("\n=== 1b. 10 so nguyen to lon nhat nho hon 2^89 - 1 ===")
    print("2^89 - 1 la nguyen to?", is_prime(M89))
    for i, p in enumerate(largest_primes_below(M89), 1):
        print(f"{i:>2}. {p}")

    print("\n=== 2. GCD cua 2 so rat lon ===")
    a, b = random.getrandbits(4096), random.getrandbits(4096)
    print("gcd(a, b) (4096 bit) =", gcd(a, b))
    c = gen_prime(256)
    x, y = c * random.getrandbits(1024), c * random.getrandbits(1024)
    g = gcd(x, y)
    print("Co uoc chung c (256 bit):", g % c == 0, "| bit_length(gcd) =", g.bit_length())

    print("\n=== 3. Luy thua module ===")
    print("7^40 mod 19 =", mod_pow(7, 40, 19))
    print("3^(10^50) mod 1000003 =", mod_pow(3, 10 ** 50, 1000003))

    print("\n=== 1c. Kiem tra so bat ky < 2^89 - 1 ===")
    s = input("Nhap mot so nguyen (Enter de bo qua): ").strip()
    if s:
        n = int(s)
        if n >= M89:
            print("So phai nho hon 2^89 - 1")
        else:
            print(n, "la nguyen to" if is_prime(n) else "KHONG phai nguyen to")
    print()


def run_tests():
    assert mod_pow(7, 40, 19) == 7
    assert mod_pow(2, 10, 1000) == 24
    assert mod_pow(5, 0, 13) == 1
    assert mod_pow(3, 10 ** 50, 1000003) == pow(3, 10 ** 50, 1000003)
    for _ in range(200):
        a, x, p = random.randrange(1, 10 ** 6), random.randrange(0, 10 ** 30), random.randrange(2, 10 ** 9)
        assert mod_pow(a, x, p) == pow(a, x, p)

    for p in (2, 3, 5, 97, 7919, 104729, 2 ** 31 - 1, 2 ** 61 - 1, M89):
        assert is_prime(p), f"{p} phai la nguyen to"
    for c in (0, 1, 4, 100, 7917, 2 ** 67 - 1):          
        assert not is_prime(c), f"{c} phai la hop so"
    for carm in (561, 1105, 1729, 41041, 825265):         
        assert not is_prime(carm), f"{carm} (Carmichael) phai la hop so"
    def trial(n):
        return n > 1 and all(n % i for i in range(2, int(n ** 0.5) + 1))
    for n in range(5000):
        assert is_prime(n) == trial(n), n

    for b in (8, 16, 64):
        for _ in range(5):
            p = gen_prime(b)
            assert p.bit_length() == b and is_prime(p)

    top = largest_primes_below(M89)
    assert len(top) == 10 and top == sorted(top, reverse=True)
    assert all(p < M89 and is_prime(p) for p in top)
    assert not any(is_prime(n) for n in range(top[0] + 1, M89)) if M89 - top[0] < 10 ** 5 else True
    assert sum(is_prime(n) for n in range(top[-1], M89, 1)) == 10 if M89 - top[-1] < 10 ** 5 else True

    assert gcd(48, 18) == 6
    assert gcd(0, 5) == 5 and gcd(5, 0) == 5
    assert gcd(17, 13) == 1
    assert gcd(2 ** 89 - 1, 2 ** 61 - 1) == 1
    for _ in range(100):
        a, b = random.getrandbits(4096), random.getrandbits(4096)
        assert gcd(a, b) == math.gcd(a, b)
    c = gen_prime(256)
    x, y = c * random.getrandbits(1024), c * random.getrandbits(1024)
    assert gcd(x, y) % c == 0

    print("[PASS] Tat ca testcase dat")


if __name__ == "__main__":
    demo()
    run_tests()