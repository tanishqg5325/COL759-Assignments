#include <bits/stdc++.h>
#define pb push_back
#define X first
#define Y second
using namespace std;
typedef pair<int, int> pii;

const int mod = 26;

vector<vector<int>> initializeKey() {
    cout << "Enter the key in one line in row major form (for e.g. 22 3 9 6): \n";
    string line, num; getline(cin, line);
    stringstream ss(line); vector<int> v;
    while(ss >> num) v.push_back(stoi(num));
    int n = sqrt(v.size());
    if(n * n != v.size()) {
        cout << "Key is not square matrix.\n";
        exit(0);
    }
    // key = {{25, 2, 11}, {19, 5, 12}, {21, 22, 6}};
    // key = {{2, 4, 5}, {9, 2, 1}, {3, 17, 7}};
    vector<vector<int>> key(n, vector<int>(n, 0));
    for(int i=0;i<n;i++)
        for(int j=0;j<n;j++)
            key[i][j] = ((v[n*i+j] % mod) + mod) % mod;
    return key;
}

// return (x, y) such that ax+by = 1 mod m
pii extendedEuclid(int a, int b, int m) {
    if(b == 1) return {1, (1 - a + m) % m};
    pii t = extendedEuclid(b, a % b, m);
    int q = a / b;
    return {t.Y, (t.X + m - q * t.Y % m) % m};
}

inline int modInverse(int a, int m) {
    return extendedEuclid(a, m, m).X;
}

vector<int> matrixMultiplication(vector<vector<int>>& key, vector<int>& plainText) {
    int n = key.size();
    vector<int> ans(n, 0);
    for(int i=0;i<n;i++) {
        for(int j=0;j<n;j++) {
            ans[i] += key[i][j] * plainText[j] % mod;
            if(ans[i] >= mod) ans[i] -= mod;
        }
    }
    return ans;
}

vector<vector<int>> computeMatrixInverse(vector<vector<int>> mat, int p) {
    int n = mat.size();
    vector<vector<int>> ans(n, vector<int>(n));
    for(int i=0;i<n;i++) ans[i][i] = 1;
    for(int i=0;i<n;i++) for(int j=0;j<n;j++) mat[i][j] %= p;
    for(int i=0;i<n;i++) {
        int j = i;
        while(j < n && mat[j][i] == 0) j++;
        if(j == n) {
            cout << "Inverse of key matrix doesn't exist.\n";
            exit(0);
        }
        if(j != i) {
            for(int k=0;k<n;k++) {
                swap(mat[i][k], mat[j][k]);
                swap(ans[i][k], ans[j][k]);
            }
        }
        for(int j=0;j<n;j++) {
            if(j == i) continue;
            int m = mat[j][i] * modInverse(mat[i][i], p) % p;
            for(int k=0;k<n;k++) {
                mat[j][k] = (mat[j][k] + p - mat[i][k] * m % p) % p;
                ans[j][k] = (ans[j][k] + p - ans[i][k] * m % p) % p;
            }
        }
    }
    for(int i=0;i<n;i++) {
        int m = modInverse(mat[i][i], p);     
        for(int j=0;j<n;j++)
            ans[i][j] = ans[i][j] * m % p;
    }
    return ans;
}

vector<vector<int>> computeMatrixInverse(vector<vector<int>>& mat) {
    int n = mat.size();
    int m1 = 2, m2 = 13;
    vector<vector<int>> ans1 = computeMatrixInverse(mat, m1);
    vector<vector<int>> ans2 = computeMatrixInverse(mat, m2);
    vector<vector<int>> ans(n, vector<int>(n));
    int N = m1 * m2, N1 = N / m1, N2 = N / m2;
    int z1 = modInverse(N1, m1), z2 = modInverse(N2, m2);
    for(int i=0;i<n;i++)
        for(int j=0;j<n;j++)
            ans[i][j] = (ans1[i][j] * N1 * z1 % N + ans2[i][j] * N2 * z2 % N) % N;
    return ans;
}

string encrypt(string plainText, vector<vector<int>>& key) {
    int n = key.size(), l = plainText.size(), i = 0;
    string cipherText = string(l, ' '); 
    vector<int> block(n), res, pos(n);
    while(i < l) {
        while(i < l && plainText[i] == ' ') i++;
        if(i == l) break;
        pos[0] = i;
        block[0] = plainText[i] - 'a';
        for(int j=1;j<n;j++) {
            i++;
            while(i < l && plainText[i] == ' ') i++;
            if(i < l) {
                pos[j] = i;
                block[j] = plainText[i] - 'a';
            }
            else {
                // do something to complete the block: append z to plaintext
                cipherText += string(n-j, ' ');
                for(;j<n;j++) {block[j] = 'z' - 'a'; pos[j] = i++;}
            }
        }
        res = matrixMultiplication(key, block);
        for(int j=0;j<n;j++) cipherText[pos[j]] = res[j] + 'a';
        i++;
    }
    return cipherText;
}

string decrypt(string cipherText, vector<vector<int>>& key) {
    vector<vector<int>> inverse_key = computeMatrixInverse(key);
    return encrypt(cipherText, inverse_key);
}

int main() {
    vector<vector<int>> key = initializeKey();
    vector<vector<int>> inverse_key = computeMatrixInverse(key);
    int choice; string filename; ifstream input_file; ofstream output_file;
    string plainText, cipherText, line; 
    cout << "Hill Cipher\n";
    cout << "1. Encryption\n";
    cout << "2. Decryption\n\n";
    cout << "Enter your choice: ";
    cin >> choice;
    switch(choice) {
        case 1:
            cout << "Enter the file name containing plaintext: ";
            cin >> filename; input_file.open(filename);
            if(input_file.fail()) {
                cout << "Such a file doesn't exist.\n";
                exit(0);
            }
            plainText = "";
            while(getline(input_file, line)) plainText += line + " ";
            plainText.pop_back(); input_file.close();
            cout << "Enter the file name to which to write ciphertext: ";
            cin >> filename; output_file.open(filename);
            output_file << encrypt(plainText, key) << "\n";
            output_file.close();
            cout << "Ciphertext has been written to " << filename << "\n";
            break;
        case 2:
            cout << "Enter the file name containing ciphertext: ";
            cin >> filename; input_file.open(filename);
            if(input_file.fail()) {
                cout << "Such a file doesn't exist.\n";
                exit(0);
            }
            cipherText = "";
            while(getline(input_file, line)) cipherText += line + " ";
            cipherText.pop_back(); input_file.close();
            cout << "Enter the file name to which to write plaintext: ";
            cin >> filename; output_file.open(filename);
            output_file << decrypt(cipherText, key) << "\n";
            output_file.close();
            cout << "Plaintext has been written to " << filename << "\n";
            break;
        default:
            cout << "Wrong Choice\n";
    }
    return 0;
}
