"""Lab 03, nhiệm vụ 2.1. RSA giáo khoa, chỉ dùng thư viện chuẩn Python.

Ví dụ: python task21.py keys / number / text / decrypt / random / all
Quy ước: UTF-8, số nguyên little-endian, khối bản mã có độ dài cố định.
RSA không padding này chỉ dùng để học, không dùng bảo vệ dữ liệu thật.
"""
import argparse
import base64
import math
from pathlib import Path
import secrets
import sys
import time

PARAMETERS = [
    (11, 17, 7),
    (20079993872842322116151219, 676717145751736242170789, 17),
    (int('F7E75FDC469067FFDC4E847C51F452DF', 16),
     int('E85CED54AF57E53E092113E62F436F4F', 16), int('0D88C3', 16)),
]
GIVEN = [
    ('Base64', 'raUcesUlOkx/8ZhgodMoo0Uu18sC20yXlQFevSu7W/FDxIy0YRHMyXcHdD9PBvIT2aUft5fCQEGomiVVPv4I'),
    ('HEX', 'C87F570FC4F699CEC24020C6F54221ABAB2CE0C3'),
    ('Base64', 'Z2BUSkJcg0w4XEpgm0JcMExEQmBlVH6dYEpNTHpMHptMQ7NgTHlgQrNMQ2BKTQ=='),
    ('BIN', '001010000001010011111111101101110010111011001010111011000110011'
            '110111111001111110110100011001111001100001001010001010100111101'
            '010100110011101110111011110101101100000100'),
]
MESSAGE = 'The University of Information Technology'


def probable_prime(n, rounds=40):
    """Miller-Rabin với cơ sở ngẫu nhiên; sai số <= 4**(-rounds)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    r, t = 0, n - 1
    while t % 2 == 0:
        r, t = r + 1, t // 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, t, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if probable_prime(n):
            return n


def make_key(p=None, q=None, e=None, bits=2048):
    """Nhận đủ p,q hoặc tự sinh cả hai; e mặc định là 65537."""
    if (p is None) != (q is None):
        raise ValueError('Cung cấp đồng thời p và q, hoặc bỏ cả hai.')
    e = 65537 if e is None else e
    if p is None:
        if bits < 512 or e <= 1 or e % 2 == 0:
            raise ValueError('Khóa tự sinh: bits >= 512 và e lẻ > 1.')
        if e >= (1 << (bits - 1)):
            raise ValueError('e quá lớn so với kích thước khóa được chọn.')
        while True:
            p, q = random_prime(bits // 2), random_prime(bits - bits // 2)
            phi = (p - 1) * (q - 1)
            if p != q and (p * q).bit_length() == bits and math.gcd(e, phi) == 1 and e < phi:
                break
    elif p == q or not probable_prime(p) or not probable_prime(q):
        raise ValueError('p và q phải là hai số nguyên tố khác nhau.')
    n, phi = p * q, (p - 1) * (q - 1)
    if not 1 < e < phi or math.gcd(e, phi) != 1:
        raise ValueError('Cần 1 < e < phi(n) và gcd(e, phi(n)) = 1.')
    return dict(p=p, q=q, n=n, phi=phi, e=e, d=pow(e, -1, phi))


def rsa_number(value, exponent, modulus):
    if not 0 <= value < modulus:
        raise ValueError('Mỗi khối phải nằm trong khoảng [0, n-1].')
    return pow(value, exponent, modulus)


def sizes(n):
    # k là kích thước khối bản mã. b bảo đảm 256**b <= n.
    # Riêng khóa 1 quá nhỏ cho byte bất kỳ: dùng từng byte và kiểm tra < n.
    return max(1, (n.bit_length() - 1) // 8), (n.bit_length() + 7) // 8


def encrypt_text(text, key):
    raw = text.encode('utf-8')
    b, k = sizes(key['n'])
    blocks = []
    for start in range(0, len(raw), b):
        m = int.from_bytes(raw[start:start + b], 'little')
        c = rsa_number(m, key['e'], key['n'])
        blocks.append(c.to_bytes(k, 'little'))
    return b''.join(blocks), len(raw)


def decrypt_text(cipher, original_length, key):
    b, k = sizes(key['n'])
    if len(cipher) % k or len(cipher) // k != (original_length + b - 1) // b:
        raise ValueError('Độ dài bản mã không khớp với số khối.')
    result = bytearray()
    for start in range(0, len(cipher), k):
        c = int.from_bytes(cipher[start:start + k], 'little')
        m = rsa_number(c, key['d'], key['n'])
        width = min(b, original_length - len(result))
        result.extend(m.to_bytes(width, 'little'))
    return result.decode('utf-8')


def decode_given(kind, value):
    if kind == 'Base64':
        return base64.b64decode(value, validate=True)
    if kind == 'HEX':
        return bytes.fromhex(value)
    # BIN là chuỗi bit của dãy byte, giữ cả các số 0 ở đầu.
    if len(value) % 8:
        raise ValueError('Chuỗi bit phải có độ dài là bội của 8.')
    return bytes(int(value[i:i+8], 2) for i in range(0, len(value), 8))


def candidate_plaintext(raw, key):
    """Thử định dạng của đề; khối cuối có thể bỏ byte 00 cao nhất.

    Đề không cho độ dài gốc. Giả sử văn bản ASCII không chứa NUL cuối.
    Các khối không phải cuối phục hồi đúng b byte; khối cuối dài tối thiểu.
    """
    b, k = sizes(key['n'])
    result = bytearray()
    block_sizes = []
    roundtrip = True
    for start in range(0, len(raw), k):
        part = raw[start:start+k]
        c = int.from_bytes(part, 'little')
        m = rsa_number(c, key['d'], key['n'])
        width = b if start+k < len(raw) else max(1, (m.bit_length()+7)//8)
        if width > b:
            raise ValueError('Khối bản rõ quá dài.')
        result.extend(m.to_bytes(width, 'little'))
        roundtrip &= rsa_number(m, key['e'], key['n']).to_bytes(len(part), 'little') == part
        block_sizes.append(len(part))
    if not result or not all(32 <= x < 127 for x in result):
        raise ValueError('Không tạo thành văn bản ASCII đọc được.')
    return result.decode('ascii'), block_sizes, roundtrip


def demo(part, bits=2048):
    keys = [make_key(*params) for params in PARAMETERS]
    if part in ('keys', 'all'):
        print('2.1.1 - TẠO BA CẶP KHÓA')
        for i, key in enumerate(keys, 1):
            print(f'\nKhóa {i}:')
            for name in ('n', 'phi', 'e', 'd'):
                print(f'{name} = {key[name]}')
            print('PU = (e, n); PR = (d, n)')
            print('Số bit n =', key['n'].bit_length())
            print('(e*d) mod phi =', key['e']*key['d'] % key['phi'])
    if part in ('number', 'all'):
        key, m = keys[0], 5
        c = rsa_number(m, key['e'], key['n'])
        s = rsa_number(m, key['d'], key['n'])
        print('\n2.1.2 - BẢN RÕ M = 5, KHÓA 1')
        print('Bảo mật: M =', m, '-> C =', c, '-> M =', rsa_number(c, key['d'], key['n']))
        print('Xác thực theo mô hình đề: M =', m, '-> S =', s, '-> M =', rsa_number(s, key['e'], key['n']))
    if part in ('text', 'all'):
        print('\n2.1.3 - MÃ HÓA CHUỖI, XUẤT BASE64')
        print('Bản rõ:', MESSAGE)
        for i, key in enumerate(keys, 1):
            cipher, length = encrypt_text(MESSAGE, key)
            recovered = decrypt_text(cipher, length, key)
            print(f'\nKhóa {i}; khối rõ/mã (byte) = {sizes(key["n"])}; độ dài gốc = {length}')
            print('Base64 =', base64.b64encode(cipher).decode())
            print('Giải mã =', recovered)
            print('Khôi phục đúng =', recovered == MESSAGE)
    if part in ('decrypt', 'all'):
        print('\n2.1.4 - GIẢI BỐN BẢN MÃ CHO SẴN')
        for index, (kind, value) in enumerate(GIVEN, 1):
            raw = decode_given(kind, value)
            print(f'\nBản mã {index}; {kind}; {len(raw)} byte')
            found = False
            for ki, key in enumerate(keys, 1):
                try:
                    plain, widths, same = candidate_plaintext(raw, key)
                except (ValueError, OverflowError, UnicodeDecodeError):
                    continue
                found = True
                print(f'Khóa {ki}; little-endian; khối mã = {widths}')
                print('Bản rõ =', plain)
                print('Mã hóa lại trùng bản mã =', same)
            if not found:
                print('Không có ứng viên phù hợp với quy ước đã thử.')
    if part in ('random', 'all'):
        print(f'\nBỔ SUNG - SINH KHÓA NGẪU NHIÊN {bits} BIT', flush=True)
        start = time.perf_counter()
        key = make_key(bits=bits)
        for name in ('n', 'e', 'd'):
            print(f'{name} = {key[name]}')
        print('Số bit n =', key['n'].bit_length())
        print('(e*d) mod phi =', key['e']*key['d'] % key['phi'])
        sample = 'Thực hành RSA - An toàn mạng máy tính'
        cipher, length = encrypt_text(sample, key)
        print('Bản rõ =', sample)
        print('Base64 =', base64.b64encode(cipher).decode())
        print('Giải mã =', decrypt_text(cipher, length, key))
        print('Khôi phục đúng =', decrypt_text(cipher, length, key) == sample)
        print(f'Thời gian sinh khóa và thử: {time.perf_counter()-start:.2f} giây')


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('part', choices=['keys', 'number', 'text', 'decrypt', 'random', 'all'], nargs='?', default='all')
    parser.add_argument('--bits', type=int, default=2048)
    args = parser.parse_args()
    demo(args.part, args.bits)
