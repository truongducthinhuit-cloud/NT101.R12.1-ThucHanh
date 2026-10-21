
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BS = 16                      
BYTE_INDEX = 25             
MODES = ["ECB", "CBC", "CFB", "OFB"]


def make_cipher(mode, key, iv):
    if mode == "ECB":
        return AES.new(key, AES.MODE_ECB)
    if mode == "CBC":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    if mode == "CFB":   
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    if mode == "OFB":
        return AES.new(key, AES.MODE_OFB, iv=iv)
    raise ValueError(mode)


def diff_blocks(a, b):
    """Tra ve danh sach (chi so khoi, so bit sai) cua cac khoi khac nhau."""
    result = []
    for i in range(0, len(a), BS):
        x, y = a[i:i + BS], b[i:i + BS]
        if x != y:
            bits = bin(int.from_bytes(x, "big") ^ int.from_bytes(y, "big")).count("1")
            result.append((i // BS, bits))
    return result


def run_experiment(mode, key, iv, data):
    ct = bytearray(make_cipher(mode, key, iv).encrypt(data))
    ct[BYTE_INDEX] ^= 0x01                                  
    pt2 = make_cipher(mode, key, iv).decrypt(bytes(ct))
    return diff_blocks(data, pt2)


def demo():
    key = os.urandom(16)                                    
    iv = os.urandom(16)
    data = pad(os.urandom(1000), BS)                        
    print(f"Do dai du lieu sau padding: {len(data)} byte ({len(data) // BS} khoi)")
    print(f"Dao 1 bit tai byte thu {BYTE_INDEX + 1} cua ban ma (khoi so {BYTE_INDEX // BS})\n")
    for mode in MODES:
        bad = run_experiment(mode, key, iv, data)
        print(f"{mode}: {len(bad)} khoi hong")
        for blk, bits in bad:
            print(f"    khoi {blk}: sai {bits}/128 bit")
    print()


def run_tests(trials=50):
    """Kiem thu: lap nhieu lan voi khoa/IV/du lieu ngau nhien."""
    for _ in range(trials):
        key, iv = os.urandom(16), os.urandom(16)
        data = pad(os.urandom(1000), BS)

        ecb = run_experiment("ECB", key, iv, data)
        assert [b for b, _ in ecb] == [1] and ecb[0][1] > 0, f"ECB sai: {ecb}"

        cbc = run_experiment("CBC", key, iv, data)
        assert [b for b, _ in cbc] == [1, 2], f"CBC sai: {cbc}"
        assert cbc[1][1] == 1, f"CBC khoi 2 phai sai dung 1 bit: {cbc}"

        cfb = run_experiment("CFB", key, iv, data)
        assert [b for b, _ in cfb] == [1, 2], f"CFB sai: {cfb}"
        assert cfb[0][1] == 1, f"CFB khoi 1 phai sai dung 1 bit: {cfb}"

        ofb = run_experiment("OFB", key, iv, data)
        assert ofb == [(1, 1)], f"OFB sai: {ofb}"

    print(f"[PASS] Tat ca testcase dat ({trials} lan lap ngau nhien)")


if __name__ == "__main__":
    demo()
    run_tests()