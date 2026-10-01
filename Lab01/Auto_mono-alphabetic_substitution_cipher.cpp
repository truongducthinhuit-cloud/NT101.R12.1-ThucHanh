#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <cmath>

using namespace std;

// Chuẩn hóa dữ liệu: Chỉ giữ lại chữ cái in hoa
string normalize_text(const string& text) {
    string norm = "";
    for (char c : text) {
        if (isalpha(c)) norm += toupper(c);
    }
    return norm;
}

// HÀM FITNESS NÂNG CẤP 2 LỚP: Tần suất đơn (Unigram) + Cụm từ (N-gram)
double calculate_fitness(const string& norm_text) {
    double score = 0;
    double len = norm_text.length();
    if (len == 0) return 0;

    // 1. Đếm tần suất xuất hiện của từng chữ cái trong đoạn văn bản hiện tại
    int counts[26] = { 0 };
    for (char c : norm_text) counts[c - 'A']++;

    // Tần suất chuẩn của 26 chữ cái tiếng Anh (tính theo %)
    double expected_freq[26] = { 8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074 };

    // Tính tổng sai số (Penalty). Sai số càng thấp, văn bản càng giống tiếng Anh.
    double penalty = 0;
    for (int i = 0; i < 26; i++) {
        double actual = (counts[i] / len) * 100.0;
        penalty += abs(actual - expected_freq[i]);
    }
    score -= penalty * 3.0; // Trừ điểm nếu sai số phân bố cao

    // 2. Chấm điểm cộng dựa trên các cụm từ phổ biến (N-grams)
    const vector<string> TRIGRAMS = { "THE","AND","ING","ENT","ION","HER","FOR","THA","NTH","INT","ERE","TIO","TER","EST","ERS","ATI","HAT","ATE","ALL","ETH","PRO" };
    const vector<string> BIGRAMS = { "TH","HE","IN","ER","AN","RE","ON","AT","EN","ND","TI","ES","OR","TE","OF","ED","IS","IT","AL","AR","ST","TO","NT","NG","SE","HA","AS" };

    for (const string& tg : TRIGRAMS) {
        size_t pos = 0;
        while ((pos = norm_text.find(tg, pos)) != string::npos) { score += 4.0; pos++; }
    }
    for (const string& bg : BIGRAMS) {
        size_t pos = 0;
        while ((pos = norm_text.find(bg, pos)) != string::npos) { score += 1.0; pos++; }
    }

    return score;
}

// Giải mã chuỗi dựa trên khóa
string decrypt(const string& cipher, const string& key) {
    string plain = "";
    for (char c : cipher) {
        if (isalpha(c)) plain += key[toupper(c) - 'A'];
        else plain += c;
    }
    return plain;
}

void solve_monoalphabetic(const string& original_ciphertext) {
    string norm_cipher = normalize_text(original_ciphertext);
    string best_global_key = "";
    double best_global_score = -999999;

    random_device rd;
    mt19937 gen(rd());

    int NUM_RESTARTS = 50; 
    for (int restart = 0; restart < NUM_RESTARTS; restart++) {
        string current_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        shuffle(current_key.begin(), current_key.end(), gen);

        string current_plain = decrypt(norm_cipher, current_key);
        double current_score = calculate_fitness(current_plain);

        int no_improve = 0;
        while (no_improve < 2500) {
            string new_key = current_key;
            swap(new_key[gen() % 26], new_key[gen() % 26]); 

            
            if (gen() % 100 < 10) {
                swap(new_key[gen() % 26], new_key[gen() % 26]);
            }

            string new_plain = decrypt(norm_cipher, new_key);
            double new_score = calculate_fitness(new_plain);

            if (new_score > current_score) {
                current_score = new_score;
                current_key = new_key;
                no_improve = 0;
            }
            else {
                no_improve++;
            }
        }

        if (current_score > best_global_score) {
            best_global_score = current_score;
            best_global_key = current_key;
        }
    }

    cout << "\n================ KET QUA ================" << endl;
    cout << "=> Key tim duoc: " << best_global_key << endl;
    cout << "=> Ban ro (Plaintext):\n" << decrypt(original_ciphertext, best_global_key) << "\n";
}

int main() {
    string ciphertext, line;
    cout << "Nhap ciphertext (Nhan Enter 2 lan de bat dau giai ma):\n";

    while (getline(cin, line) && !line.empty()) {
        ciphertext += line + "\n";
    }

    if (ciphertext.empty()) return 0;

    cout << "\nDang ap dung Hill-Climbing Nhanh (1-3 giay), vui long doi..." << endl;
    solve_monoalphabetic(ciphertext);

    return 0;
}