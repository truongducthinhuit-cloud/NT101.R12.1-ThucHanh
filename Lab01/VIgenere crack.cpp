#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cctype>
#include <cmath>
using namespace std;

// Tan suat xuat hien cua 26 chu cai trong tieng Anh (%)
const double EN[26] = { 8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,
                       0.153,0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,
                       6.327,9.056,2.758,0.978,2.360,0.150,1.974,0.074 };

// BUOC 1: chuan hoa - chi giu chu cai, doi thanh chu HOA
string normalize(const string& s) {
    string r;
    for (unsigned char c : s) if (isalpha(c)) r += toupper(c);
    return r;
}

// BUOC 2: Index of Coincidence cua mot chuoi
double ic(const string& s) {
    int f[26] = { 0 }, n = s.size();
    if (n < 2) return 0;
    for (char c : s) f[c - 'A']++;
    double sum = 0;
    for (int i = 0; i < 26; i++) sum += f[i] * (f[i] - 1);
    return sum / (n * (n - 1.0));
}

// IC trung binh khi tach chuoi thanh L cot
double avgIC(const string& s, int L) {
    double total = 0;
    for (int i = 0; i < L; i++) {
        string col;
        for (size_t j = i; j < s.size(); j += L) col += s[j];
        total += ic(col);
    }
    return total / L;
}

// BUOC 3: chon do dai khoa = L NHO NHAT co IC trung binh >= 0.06
// (tieng Anh ~0.065, ngau nhien ~0.038). Neu khong co thi lay L co IC lon nhat.
int guessKeyLen(const string& s, int maxL) {
    int best = 1; double bestIC = 0;
    for (int L = 1; L <= maxL; L++) {
        double v = avgIC(s, L);
        cout << "  L = " << L << "  IC = " << v << "\n";
        if (v >= 0.06) return L;
        if (v > bestIC) { bestIC = v; best = L; }
    }
    return best;
}

// BUOC 4: voi moi cot, thu 26 phep dich, chon phep dich co chi-binh-phuong nho nhat
char guessKeyChar(const string& col) {
    int bestShift = 0; double bestChi = 1e18;
    for (int k = 0; k < 26; k++) {
        int f[26] = { 0 };
        for (char c : col) f[(c - 'A' - k + 26) % 26]++;
        double chi = 0, n = col.size();
        for (int i = 0; i < 26; i++) {
            double e = n * EN[i] / 100.0;
            chi += (f[i] - e) * (f[i] - e) / e;
        }
        if (chi < bestChi) { bestChi = chi; bestShift = k; }
    }
    return 'A' + bestShift;
}

// Giai ma, giu nguyen dau cach / dau cau cua van ban goc
string decrypt(const string& text, const string& key) {
    string r; int j = 0;
    for (unsigned char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            r += (char)((c - base - (key[j % key.size()] - 'A') + 26) % 26 + base);
            j++;
        }
        else r += c;
    }
    return r;
}

int main() {
    int mode;
    string text;
    cout << "=== PHA MA VIGENERE (khong biet khoa) ===\n";
    cout << "1: Nhap truc tiep, 2: Doc tu file: ";
    cin >> mode; cin.ignore(10000, '\n');

    if (mode == 2) {
        string path; cout << "Ten file: "; getline(cin, path);
        ifstream f(path); stringstream ss; ss << f.rdbuf(); text = ss.str();
    }
    else {
        cout << "Nhap ciphertext: "; getline(cin, text);
    }

    string c = normalize(text);
    if (c.size() < 30) { cout << "Ciphertext qua ngan!\n"; return 1; }
    cout << "So chu cai sau chuan hoa: " << c.size() << "\n";

    cout << "Phan tich Index of Coincidence:\n";
    int L = guessKeyLen(c, 20);

    string key;
    for (int i = 0; i < L; i++) {
        string col;
        for (size_t j = i; j < c.size(); j += L) col += c[j];
        key += guessKeyChar(col);
    }

    cout << "\nDo dai khoa: " << L << "\nKhoa tim duoc: " << key << "\n";
    cout << "\n[BAN RO]:\n" << decrypt(text, key) << "\n";
    return 0;
}