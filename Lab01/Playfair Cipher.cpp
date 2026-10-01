#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

using namespace std;

// Chuẩn hóa chuỗi (chỉ lấy chữ cái in hoa, thay J bằng I)
string prepare_text(const string& text) {
    string res = "";
    for (char c : text) {
        if (isalpha(c)) {
            char u = toupper(c);
            if (u == 'J') u = 'I';
            res += u;
        }
    }
    return res;
}

// Tạo ma trận 5x5 từ khóa
vector<vector<char>> generate_playfair_matrix(string key) {
    key = prepare_text(key);
    string key_processed = "";
    bool visited[26] = { false };
    visited['J' - 'A'] = true; // J được gộp với I

    for (char c : key) {
        if (!visited[c - 'A']) {
            visited[c - 'A'] = true;
            key_processed += c;
        }
    }

    for (char c = 'A'; c <= 'Z'; c++) {
        if (!visited[c - 'A']) {
            visited[c - 'A'] = true;
            key_processed += c;
        }
    }

    vector<vector<char>> matrix(5, vector<char>(5));
    int idx = 0;
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            matrix[i][j] = key_processed[idx++];
        }
    }
    return matrix;
}

// Tìm vị trí của ký tự trong ma trận
void find_position(const vector<vector<char>>& matrix, char c, int& row, int& col) {
    if (c == 'J') c = 'I';
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            if (matrix[i][j] == c) {
                row = i;
                col = j;
                return;
            }
        }
    }
}

// Chuẩn hóa bản rõ thành các cặp ký tự (digraphs)
string prepare_plaintext(string text) {
    text = prepare_text(text);
    string res = "";
    for (size_t i = 0; i < text.length(); i++) {
        res += text[i];
        if (i + 1 < text.length()) {
            if (text[i] == text[i + 1]) {
                res += 'X'; // Chèn 'X' nếu 2 ký tự trùng nhau trong một cặp
            }
            else {
                res += text[i + 1];
                i++;
            }
        }
    }
    if (res.length() % 2 != 0) {
        res += 'X'; // Thêm 'X' nếu số lượng ký tự lẻ
    }
    return res;
}

// Mã hóa Playfair
string playfair_encrypt(string plaintext, const vector<vector<char>>& matrix) {
    plaintext = prepare_plaintext(plaintext);
    string ciphertext = "";

    for (size_t i = 0; i < plaintext.length(); i += 2) {
        char c1 = plaintext[i];
        char c2 = plaintext[i + 1];
        int r1, c1_idx, r2, c2_idx;

        find_position(matrix, c1, r1, c1_idx);
        find_position(matrix, c2, r2, c2_idx);

        if (r1 == r2) { // Cùng hàng
            ciphertext += matrix[r1][(c1_idx + 1) % 5];
            ciphertext += matrix[r2][(c2_idx + 1) % 5];
        }
        else if (c1_idx == c2_idx) { // Cùng cột
            ciphertext += matrix[(r1 + 1) % 5][c1_idx];
            ciphertext += matrix[(r2 + 1) % 5][c2_idx];
        }
        else { // Hình chữ nhật
            ciphertext += matrix[r1][c2_idx];
            ciphertext += matrix[r2][c1_idx];
        }
    }
    return ciphertext;
}

// Giải mã Playfair
string playfair_decrypt(string ciphertext, const vector<vector<char>>& matrix) {
    ciphertext = prepare_text(ciphertext);
    string plaintext = "";

    for (size_t i = 0; i < ciphertext.length(); i += 2) {
        char c1 = ciphertext[i];
        char c2 = ciphertext[i + 1];
        int r1, c1_idx, r2, c2_idx;

        find_position(matrix, c1, r1, c1_idx);
        find_position(matrix, c2, r2, c2_idx);

        if (r1 == r2) { // Cùng hàng
            plaintext += matrix[r1][(c1_idx - 1 + 5) % 5];
            plaintext += matrix[r2][(c2_idx - 1 + 5) % 5];
        }
        else if (c1_idx == c2_idx) { // Cùng cột
            plaintext += matrix[(r1 - 1 + 5) % 5][c1_idx];
            plaintext += matrix[(r2 - 1 + 5) % 5][c2_idx];
        }
        else { // Hình chữ nhật
            plaintext += matrix[r1][c2_idx];
            plaintext += matrix[r2][c1_idx];
        }
    }
    return plaintext;
}

int main() {
    string key, text;
    int choice;

    cout << "=== CHUONG TRINH PLAYFAIR CIPHER ===" << endl;
    cout << "Nhap khoa (Key): ";
    getline(cin, key);

    vector<vector<char>> matrix = generate_playfair_matrix(key);

    cout << "\n--- Ma tran Playfair 5x5 ---" << endl;
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            cout << matrix[i][j] << " ";
        }
        cout << endl;
    }

    cout << "\nChon chuc nang:" << endl;
    cout << "1. Ma hoa (Encrypt)" << endl;
    cout << "2. Giai ma (Decrypt)" << endl;
    cout << "Nhap lua chon (1 hoac 2): ";
    cin >> choice;
    cin.ignore();

    cout << "Nhap van ban: ";
    getline(cin, text);

    if (choice == 1) {
        string cipher = playfair_encrypt(text, matrix);
        cout << "\n=> Ban ma (Ciphertext):\n" << cipher << endl;
    }
    else if (choice == 2) {
        string plain = playfair_decrypt(text, matrix);
        cout << "\n=> Ban ro (Plaintext):\n" << plain << endl;
    }
    else {
        cout << "Lua chon khong hop le!" << endl;
    }

    return 0;
}