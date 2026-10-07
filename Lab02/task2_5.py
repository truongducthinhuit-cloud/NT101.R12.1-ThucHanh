import time
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes

data = get_random_bytes(10 * 1024 * 1024)  # 10 MB (bội của 8 và 16)

def bench(name, cipher):
    t = time.perf_counter()
    cipher.encrypt(data)
    print(f"{name}: {time.perf_counter() - t:.3f} s")

bench("DES      ", DES.new(get_random_bytes(8), DES.MODE_ECB))
bench("3DES     ", DES3.new(DES3.adjust_key_parity(get_random_bytes(24)), DES3.MODE_ECB))
bench("AES-128  ", AES.new(get_random_bytes(16), AES.MODE_ECB))
bench("AES-256  ", AES.new(get_random_bytes(32), AES.MODE_ECB))