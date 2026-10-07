from Crypto.Cipher import DES
# Hàm hỗ trợ đếm số bit khác nhau
def count_diff_bits(cipher1, cipher2):
    bin1 = bin(int.from_bytes(cipher1, 'big'))[2:].zfill(64)
    bin2 = bin(int.from_bytes(cipher2, 'big'))[2:].zfill(64)
    return sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
def avalanche_test(key):
    p1 = b'STAYHOME'
    p2 = b'STAYHOMA' 
    # TODO 1:
    cipher = DES.new(key, DES.MODE_ECB)
    c1 = cipher.encrypt(p1)
    c2 = cipher.encrypt(p2)
    # TODO 2: 
    diff_bits = count_diff_bits(c1, c2)
    # TODO 3:
    percent = (diff_bits / 64) * 100    
    # In kết quả chi tiết phục vụ báo cáo
    print(f"--- Kiểm tra với Key: {key.decode()} ---")
    print(f"  + Bản mã C1 (Hex): {c1.hex()}")
    print(f"  + Bản mã C2 (Hex): {c2.hex()}")
    print(f"  + Số bit khác nhau: {diff_bits} / 64 bits")
    print(f"  + Tỷ lệ phần trăm thay đổi: {percent:.2f}%\n")
avalanche_test(b'87654321')
mssv_list = [
    b'24521708',  
    b'24521664'
]

for mssv in mssv_list:
    avalanche_test(mssv)