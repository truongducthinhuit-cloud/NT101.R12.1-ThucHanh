#include <iostream>
#include <string>

using namespace std;

//Ham ma hoa Caesar
string encryptCaesar(string text, int key) {
    string result = "";
    key = key % 26;
    if (key < 0) key += 26;

    for (int i = 0; i < text.length(); i++) {
        char c = text[i];
        if (isupper(c)) {
            result += char(int(c + key - 'A') % 26 + 'A');
        }
        else if (islower(c)) {
            result += char(int(c + key - 'a') % 26 + 'a');
        }
        else {
            result += c;
        }
    }
    return result;
}

//Ham giai ma Caesar 
string decryptCaesar(string text, int key) {
    return encryptCaesar(text, 26 - (key % 26));
}

//Ham Brute-force tim ban duy nhat
void bruteForceCaesar(string ciphertext) {
    int bestKey = 0;
    int maxScore = -1;
    string bestPlaintext = "";

    for (int k = 1; k < 26; k++) {
        string decrypted = decryptCaesar(ciphertext, k);

        int score = 0;
        if (decrypted.find(" the ") != string::npos || decrypted.find("The ") != string::npos) score++;
        if (decrypted.find(" and ") != string::npos) score++;
        if (decrypted.find(" is ") != string::npos || decrypted.find(" are ") != string::npos) score++;
        if (decrypted.find(" in ") != string::npos) score++;
        if (decrypted.find(" a ") != string::npos) score++;

        if (score > maxScore) {
            maxScore = score;
            bestKey = k;
            bestPlaintext = decrypted;
        }
    }

    cout << "\nDa tim thay ban chinh xac nhat:" << endl;
    cout << "-> Khoa k = " << bestKey << endl;
    cout << "-> Van ban:\n" << bestPlaintext << endl;
}

int main() {
    int choice;
    cout << "1. Ma hoa / Giai ma thu cong" << endl;
    cout << "2. Brute-force" << endl;
    cout << "Nhap lua chon(1 hoac 2): ";
    cin >> choice;
    cin.ignore();

    if (choice == 1) {
        string text;
        int key;
        int mode;

        cout << "\nNhap van ban: ";
        getline(cin, text);

        cout << "Nhap khoa k (so nguyen): ";
        cin >> key;

        cout << "Chon che do - (1) Ma hoa, (2) Giai ma: ";
        cin >> mode;

        if (mode == 1) {
            cout << "\nCiphertext: " << encryptCaesar(text, key) << endl;
        }
        else if (mode == 2) {
            cout << "\nPlaintext: " << decryptCaesar(text, key) << endl;
        }
        else {
            cout << "Khong hop le!" << endl;
        }
    }
//brute
    else if (choice == 2) {
        string ciphertext;
        cout << "\nNhap doan ciphertext (luu y copy-paste tren 1 dong lien mach): \n";
        getline(cin, ciphertext);
        bruteForceCaesar(ciphertext);
    }
    else {
        cout << "Lua chon khong hop le!" << endl;
    }

    return 0;
}