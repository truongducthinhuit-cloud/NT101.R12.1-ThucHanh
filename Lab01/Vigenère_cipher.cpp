#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cctype>

using namespace std;

// Chuan hoa khoa: chi giu chu cai, doi thanh chu hoa
string normalizeKey(const string& key) {
    string k = "";
    for (char c : key)
        if (isalpha((unsigned char)c)) k += (char)toupper((unsigned char)c);
    return k;
}

// Ma hoa / giai ma Vigenere (mode = +1: ma hoa, mode = -1: giai ma)
string vigenere(const string& text, const string& key, int mode) {
    string result = "";
    int keyIdx = 0;
    int keyLen = key.length();

    for (size_t i = 0; i < text.length(); i++) {
        char c = text[i];
        if (isalpha((unsigned char)c)) {
            char base = isupper((unsigned char)c) ? 'A' : 'a';
            int shift = key[keyIdx % keyLen] - 'A';
            int x = (c - base + mode * shift + 26) % 26;
            result += (char)(x + base);
            keyIdx++;               // chi tang khi gap chu cai
        }
        else {
            result += c;            // giu nguyen dau cach, dau cau, so
        }
    }
    return result;
}

string readFile(const string& path) {
    ifstream f(path);
    if (!f) return "";
    stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

int main() {
    string key, text, path;
    int choice, source;

    cout << "=== VIGENERE CIPHER ===\n";
    cout << "Nhap khoa (Key): ";
    cin >> key;
    key = normalizeKey(key);
    if (key.empty()) {
        cout << "Khoa khong hop le (phai co it nhat 1 chu cai)!\n";
        return 1;
    }

    cout << "Chon chuc nang (1: Ma hoa, 2: Giai ma): ";
    cin >> choice;

    cout << "Nguon van ban (1: Go truc tiep, 2: Doc tu file): ";
    cin >> source;
    cin.ignore(10000, '\n');

    if (source == 2) {
        cout << "Ten file (vd: input.txt): ";
        getline(cin, path);
        text = readFile(path);
        if (text.empty()) {
            cout << "Khong doc duoc file hoac file rong!\n";
            return 1;
        }
        cout << "Da doc " << text.length() << " ky tu tu file.\n";
    }
    else {
        cout << "Nhap van ban: ";
        getline(cin, text);
    }

    string out;
    if (choice == 1)      out = vigenere(text, key, +1);
    else if (choice == 2) out = vigenere(text, key, -1);
    else { cout << "Lua chon khong hop le!\n"; return 1; }

    cout << (choice == 1 ? "\n[KET QUA MA HOA]:\n" : "\n[KET QUA GIAI MA]:\n")
        << out << endl;

    ofstream fo("output.txt");
    fo << out;
    cout << "\n(Da luu ket qua vao output.txt)\n";
    return 0;
}