def F(right, subkey):
    return (right ^ subkey) & 0x0F

def feistel_round(L_in, R_in, subkey):
    # LE_i = RE_{i-1}
    L_out = R_in
    # RE_i = LE_{i-1} XOR F(RE_{i-1}, K_i)
    R_out = L_in ^ F(R_in, subkey)
    
    return L_out, R_out

def track_avalanche(msg, key):
    L, R = (msg >> 4) & 0x0F, msg & 0x0F
    subkeys = [key & 0x0F, (key >> 4) & 0x0F, (key + 1) & 0x0F, (key + 2) & 0x0F]
    
    print(f"Khởi tạo: L={format(L, '04b')}, R={format(R, '04b')}")
    for i in range(4):
        L, R = feistel_round(L, R, subkeys[i])
        print(f"Vòng {i+1}: L={format(L, '04b')}, R={format(R, '04b')}")
    return (L << 4) | R

# Chạy thử với 2 bản rõ khác nhau 1 bit (0xAB và 0xAC)
print("--- Mã hóa M1 (0xAB) ---")
track_avalanche(0xAB, 0x12)
print("\n--- Mã hóa M2 (0xAC) ---")
track_avalanche(0xAC, 0x12)
