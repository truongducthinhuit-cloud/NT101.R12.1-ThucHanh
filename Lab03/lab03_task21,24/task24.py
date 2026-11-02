"""Lab 03, nhiệm vụ 2.4: trích xuất X.509, tự xác minh RSA/SHA-256.

Chỉ cần Python chuẩn và OpenSSL. Không gọi hàm verify của thư viện RSA.
Lệnh: python task24.py fetch --host www.amazon.com
      python task24.py inspect
      python task24.py verify
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

BASE = Path(__file__).resolve().parent
CERTS = BASE / 'certs'
SHA256_RSA_OID = bytes.fromhex('2a864886f70d01010b')
DIGEST_INFO_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')


def openssl_path():
    native_git = Path(r'C:\Program Files\Git\mingw64\bin\openssl.exe')
    found = str(native_git) if native_git.exists() else shutil.which('openssl')
    if not found:
        raise RuntimeError('Không tìm thấy OpenSSL. Dùng Git for Windows hoặc Colab.')
    return found


def openssl(*args, data=None, timeout=30, require_success=True):
    result = subprocess.run([openssl_path(), *map(str, args)], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if require_success and result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace').strip())
    return result


def tlv(data, offset):
    """Đọc một trường DER đơn giản: trả tag, đầu nội dung, cuối trường."""
    if offset + 2 > len(data):
        raise ValueError('DER bị thiếu dữ liệu.')
    tag, length, pos = data[offset], data[offset+1], offset+2
    if tag & 31 == 31:
        raise ValueError('Không hỗ trợ tag ASN.1 nhiều byte trong ví dụ này.')
    if length & 128:
        count = length & 127
        if not count or count > 4 or pos+count > len(data):
            raise ValueError('Độ dài DER không hợp lệ.')
        length = int.from_bytes(data[pos:pos+count], 'big')
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError('Trường DER vượt quá kích thước tệp.')
    return tag, pos, end


def fields(data, start, end):
    result = []
    while start < end:
        tag, content, next_offset = tlv(data, start)
        if next_offset > end:
            raise ValueError('Trường con vượt quá trường cha.')
        result.append((start, tag, content, next_offset))
        start = next_offset
    if start != end:
        raise ValueError('DER không hợp lệ.')
    return result


def certificate_parts(pem):
    match = re.search(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', pem, re.S)
    if not match:
        raise ValueError('Không tìm thấy chứng chỉ PEM.')
    der = base64.b64decode(re.sub(rb'\s+', b'', match.group(1)), validate=True)
    tag, start, end = tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError('Chứng chỉ không phải một SEQUENCE DER hợp lệ.')
    children = fields(der, start, end)
    if len(children) != 3:
        raise ValueError('Certificate phải có ba trường.')
    tbs, algorithm, signature = children
    if (tbs[1], algorithm[1], signature[1]) != (0x30, 0x30, 0x03):
        raise ValueError('Cấu trúc chứng chỉ không hợp lệ.')
    alg_children = fields(der, algorithm[2], algorithm[3])
    oid = alg_children[0]
    if oid[1] != 0x06 or der[oid[2]:oid[3]] != SHA256_RSA_OID:
        raise ValueError('Cần chứng chỉ sha256WithRSAEncryption (PKCS#1 v1.5). Hãy chọn website khác.')
    tbs_children = fields(der, tbs[2], tbs[3])
    inner_algorithm = tbs_children[2 if tbs_children[0][1] == 0xa0 else 1]
    if der[inner_algorithm[0]:inner_algorithm[3]] != der[algorithm[0]:algorithm[3]]:
        raise ValueError('Thuật toán chữ ký bên trong và bên ngoài không khớp.')
    if der[signature[2]] != 0:
        raise ValueError('BIT STRING chữ ký phải có 0 bit không sử dụng.')
    return dict(der=der, tbs=der[tbs[0]:tbs[3]],
                signature=der[signature[2]+1:signature[3]],
                offset=tbs[0], header=tbs[2]-tbs[0], content_length=tbs[3]-tbs[2])


def distinguished_name(pem, field):
    value = openssl('x509', '-noout', '-nameopt', 'RFC2253', '-'+field, data=pem).stdout.decode().strip()
    return value.split('=', 1)[1].strip()


def issuer_key(pem):
    modulus = openssl('x509', '-noout', '-modulus', data=pem).stdout.decode().strip()
    if not re.fullmatch(r'Modulus=[0-9A-Fa-f]+', modulus):
        raise ValueError('Khóa công khai của CA không phải RSA.')
    public_pem = openssl('x509', '-noout', '-pubkey', data=pem).stdout
    key_text = openssl('pkey', '-pubin', '-text', '-noout', data=public_pem).stdout.decode()
    exponent = re.search(r'Exponent:\s*(\d+)', key_text, re.I)
    if not exponent:
        raise ValueError('Không đọc được số mũ e của khóa CA.')
    return int(modulus.split('=')[1], 16), int(exponent.group(1)), public_pem


def fetch(host):
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
        raise ValueError('Chỉ nhập tên miền, không có https:// hoặc đường dẫn.')
    command = ['s_client', '-connect', host+':443', '-servername', host, '-showcerts']
    response = openssl(*command, data=b'', require_success=False)
    chain = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', response.stdout, re.S)
    if not chain:
        raise RuntimeError('Không tải được chứng chỉ. Kiểm tra Internet/DNS.\n' + response.stderr.decode(errors='replace'))
    leaf = chain[0]+b'\n'
    certificate_parts(leaf)  # Từ chối ECDSA/PSS trước khi ghi đè dữ liệu.
    issuer = distinguished_name(leaf, 'issuer')
    matches = [c+b'\n' for c in chain[1:] if distinguished_name(c, 'subject') == issuer]
    if not matches:
        raise ValueError('Máy chủ chưa gửi chứng chỉ CA phù hợp. Hãy chọn website khác.')
    selected = None
    for candidate in matches:
        try:
            n, e, _ = issuer_key(candidate)
            part = certificate_parts(leaf)
            if check_signature(part['signature'], part['tbs'], n, e)[0]:
                selected = candidate
                break
        except (ValueError, RuntimeError):
            continue
    if selected is None:
        raise ValueError('Không tìm được CA RSA xác minh được chữ ký máy chủ.')
    CERTS.mkdir(exist_ok=True)
    (CERTS/'chain.txt').write_bytes(response.stdout + b'\n' + response.stderr)
    (CERTS/'c0.pem').write_bytes(leaf)
    (CERTS/'c1.pem').write_bytes(selected)
    info = dict(host=host, fetched_at_utc=datetime.now(timezone.utc).isoformat(),
                command='openssl '+' '.join(command), chain_certificates=len(chain))
    (CERTS/'download.json').write_text(json.dumps(info, indent=2), encoding='utf-8')
    print('Website:', host)
    print('Số chứng chỉ máy chủ gửi:', len(chain))
    print('c0 subject:', distinguished_name(leaf, 'subject'))
    print('c0 issuer :', issuer)
    print('c1 subject:', distinguished_name(selected, 'subject'))
    print('Thuật toán chữ ký: sha256WithRSAEncryption')
    print('Đã lưu c0.pem, c1.pem, chain.txt và download.json vào', CERTS)


def inspect():
    leaf, issuer = (CERTS/'c0.pem').read_bytes(), (CERTS/'c1.pem').read_bytes()
    part = certificate_parts(leaf)
    n, e, public_pem = issuer_key(issuer)
    for name, data in [('c0.der', part['der']), ('c0_body.bin', part['tbs']),
                       ('signature.bin', part['signature']), ('ca_public.pem', public_pem)]:
        (CERTS/name).write_bytes(data)
    (CERTS/'signature.hex').write_text(part['signature'].hex(), encoding='ascii')
    asn1 = openssl('asn1parse', '-i', '-in', CERTS/'c0.pem').stdout
    (CERTS/'asn1.txt').write_bytes(asn1)
    for stem in ('c0', 'c1'):
        (CERTS/(stem+'_text.txt')).write_bytes(openssl('x509', '-in', CERTS/(stem+'.pem'), '-text', '-noout').stdout)
    # Trích bằng OpenSSL, rồi so với bộ đọc DER để phát hiện sai offset/phạm vi.
    openssl('asn1parse', '-in', CERTS/'c0.pem', '-strparse', str(part['offset']),
            '-out', CERTS/'c0_body_openssl.bin', '-noout')
    same = (CERTS/'c0_body_openssl.bin').read_bytes() == part['tbs']
    if not same:
        raise ValueError('Phần TBS do OpenSSL trích không khớp bộ đọc DER.')
    info = dict(n=str(n), n_hex=format(n, 'X'), e=e, n_bits=n.bit_length(),
                tbs_offset=part['offset'], tbs_header=part['header'],
                tbs_content_length=part['content_length'], tbs_length=len(part['tbs']),
                signature_length=len(part['signature']), sha256=hashlib.sha256(part['tbs']).hexdigest())
    (CERTS/'extracted.json').write_text(json.dumps(info, indent=2), encoding='utf-8')
    print('c0 subject:', distinguished_name(leaf, 'subject'))
    print('c0 issuer :', distinguished_name(leaf, 'issuer'))
    print('c1 subject:', distinguished_name(issuer, 'subject'))
    print('\nKHÓA CÔNG KHAI CỦA CA')
    print('n (HEX) =', format(n, 'X'))
    print('e =', e, '; số bit n =', n.bit_length())
    print('\nCHỮ KÝ CỦA CA TRÊN c0 (HEX)')
    print(part['signature'].hex())
    print('Độ dài chữ ký =', len(part['signature']), 'byte')
    print('\nPHẦN TBSCertificate')
    print('Offset =', part['offset'], '; hl =', part['header'], '; l =', part['content_length'])
    print('Độ dài TBS = hl + l =', len(part['tbs']), 'byte')
    print('TBS từ OpenSSL khớp bộ đọc DER =', same)
    print('SHA-256(TBS) =', info['sha256'])
    print('Các tệp đã lưu trong', CERTS)


def check_signature(signature, tbs, n, e):
    k = (n.bit_length()+7)//8
    s = int.from_bytes(signature, 'big')
    if len(signature) != k or s >= n:
        return False, b'', b''
    # Phép RSA xác minh yêu cầu của bài lab.
    recovered = pow(s, e, n).to_bytes(k, 'big')
    digest_info = DIGEST_INFO_PREFIX + hashlib.sha256(tbs).digest()
    padding_length = k - len(digest_info) - 3
    if padding_length < 8:
        return False, recovered, b''
    expected = b'\x00\x01' + b'\xff'*padding_length + b'\x00' + digest_info
    return hmac.compare_digest(recovered, expected), recovered, expected


def verify():
    leaf, issuer = (CERTS/'c0.pem').read_bytes(), (CERTS/'c1.pem').read_bytes()
    part = certificate_parts(leaf)
    n, e, _ = issuer_key(issuer)
    names_match = distinguished_name(leaf, 'issuer') == distinguished_name(issuer, 'subject')
    valid, recovered, expected = check_signature(part['signature'], part['tbs'], n, e)
    modified = bytearray(part['tbs'])
    modified[-1] ^= 1
    tampered_valid, _, _ = check_signature(part['signature'], bytes(modified), n, e)
    print('Thuật toán: sha256WithRSAEncryption / PKCS#1 v1.5')
    print('c0.issuer == c1.subject:', names_match)
    print('Số bit khóa công khai CA:', n.bit_length())
    print('EM = S^e mod n, độ dài:', len(recovered), 'byte')
    print('Đầu EM:', recovered[:16].hex())
    print('SHA-256 tính từ TBS:', hashlib.sha256(part['tbs']).hexdigest())
    print('32 byte cuối EM   :', recovered[-32:].hex())
    print('Khớp TOÀN BỘ padding + DigestInfo + hash:', valid)
    print('CHỮ KÝ HỢP LỆ:', valid and names_match)
    print('Sau khi đổi 1 bit của TBS, chữ ký hợp lệ:', tampered_valid)
    print('Phạm vi: kiểm tra chữ ký; chưa kiểm tra đầy đủ chuỗi tin cậy, tên miền, thời hạn và thu hồi.')
    (CERTS/'verification.json').write_text(json.dumps(dict(signature_valid=valid,
        issuer_name_matches=names_match, tampered_signature_valid=tampered_valid,
        sha256=hashlib.sha256(part['tbs']).hexdigest(), recovered_em=recovered.hex(),
        expected_em=expected.hex()), indent=2), encoding='utf-8')
    if not valid or not names_match or tampered_valid:
        raise ValueError('Kiểm tra không đạt.')


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'inspect', 'verify'])
    parser.add_argument('--host', default='www.amazon.com')
    args = parser.parse_args()
    try:
        if args.action == 'fetch':
            fetch(args.host)
        elif args.action == 'inspect':
            inspect()
        else:
            verify()
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print('LỖI:', exc)
        sys.exit(1)
