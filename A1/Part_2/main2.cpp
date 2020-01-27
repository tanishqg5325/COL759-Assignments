#include <bits/stdc++.h>
#define X first
#define Y second
using namespace std;
typedef pair<int, int> pii;
typedef vector<vector<int>> Matrix;

const int mod = 26;
vector<string> digrams = {"th", "er", "on", "an", "re", "he", "in", "ed", "nd", "ha",
                        "at", "en", "es", "of", "or", "nt", "ea", "ti", "to", "it",
                        "st", "io", "le", "is", "ou", "ar", "as", "de", "rt", "ve"};

vector<string> trigrams = {"the", "and", "tha", "ent", "imp", "ion", "tio", "for", "nde", "has",
                        "nce", "edt", "tis", "oft", "sth", "nth", "men", "ere", "ing", "ckl", 
                        "rea", "her", "his"};

string cipherText;
int keyLength;

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

Matrix computeMatrixInverse(Matrix mat, int p) {
    int n = mat.size();
    Matrix ans(n, vector<int>(n));
    for(int i=0;i<n;i++) ans[i][i] = 1;
    for(int i=0;i<n;i++) for(int j=0;j<n;j++) mat[i][j] %= p;
    for(int i=0;i<n;i++) {
        int j = i;
        while(j < n && mat[j][i] == 0) j++;
        if(j == n) {
            // Inverse doesn't exist
            return {};
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

Matrix computeMatrixInverse(Matrix& mat) {
    int n = mat.size();
    int m1 = 2, m2 = 13;
    Matrix ans1 = computeMatrixInverse(mat, m1);
    if(ans1.empty()) return {};
    Matrix ans2 = computeMatrixInverse(mat, m2);
    if(ans2.empty()) return {};
    Matrix ans(n, vector<int>(n));
    int N = m1 * m2, N1 = N / m1, N2 = N / m2;
    int z1 = modInverse(N1, m1), z2 = modInverse(N2, m2);
    for(int i=0;i<n;i++)
        for(int j=0;j<n;j++)
            ans[i][j] = (ans1[i][j] * N1 * z1 % N + ans2[i][j] * N2 * z2 % N) % N;
    return ans;
}

string removeSpaces(string& str) {
    string ans = "";
    for(int i=0;i<str.size();i++)
        if(str[i] != ' ')
            ans += str[i];
    return ans;
}

vector<string> mostFrequentGrams(string cipherText, int keyLength, int howMany) {
    cipherText = removeSpaces(cipherText);
    int n = cipherText.size();
    map<string, int> freq;
    for(int i=0;i+keyLength<=n;i+=keyLength) {
        freq[cipherText.substr(i, keyLength)]++;
    }
    vector<pair<int, string>> v;
    for(auto& i : freq) {
        v.emplace_back(i.Y, i.X);
    }
    sort(v.begin(), v.end(), greater<pair<int, string>>());
    int k = min((int)v.size(), howMany);
    vector<string> ans(k);
    for(int i=0;i<k;i++) ans[i] = v[i].Y;
    return ans;
}

double indexOfCoincidence(string& plainText) {
    int freq[26]{}, n = 0;
    for(int i=0;i<plainText.size();i++)
        if(plainText[i] >= 'a' && plainText[i] <= 'z') {
            freq[plainText[i]-'a']++;
            n++;
        }
    double ic = 0;
    for(int i=0;i<26;i++) ic += freq[i] * (freq[i] - 1);
    ic /= (n * (n - 1)); 
    return ic;
}

vector<int> matrixVectorMultiplication(Matrix& key, vector<int>& plainText) {
    int n = key.size();
    vector<int> ans(n, 0);
    for(int i=0;i<n;i++)
        for(int j=0;j<n;j++) {
            ans[i] += key[i][j] * plainText[j] % mod;
            if(ans[i] >= mod) ans[i] -= mod;
        }
    return ans;
}

string encrypt(string& plainText, Matrix& key) {
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
        res = matrixVectorMultiplication(key, block);
        for(int j=0;j<n;j++) cipherText[pos[j]] = res[j] + 'a';
        i++;
    }
    return cipherText;
}

string decrypt(Matrix& key) {
    Matrix inverse_key = computeMatrixInverse(key);
    return encrypt(cipherText, inverse_key);
}

Matrix squareMatrixMultiplication(Matrix& m1, Matrix& m2) {
    int n = m1.size();
    Matrix ans(n, vector<int>(n));
    for(int i=0;i<n;i++) {
        for(int j=0;j<n;j++) {
            for(int k=0;k<n;k++) {
                ans[i][j] += m1[i][k] * m2[k][j] % mod;
                if(ans[i][j] >= mod) ans[i][j] -= mod;
            }
        }
    }
    return ans;
}

void displayMatrix(Matrix& m) {
    int n = m.size();
    for(int i=0;i<n;i++) {
        for(int j=0;j<n;j++) cout << m[i][j] << "\t";
        cout << "\n";
    }
}

inline Matrix convertStringtoMatrix(vector<string>& v) {
    int n = v.size();
    Matrix ans(n, vector<int>(n));
    for(int i=0;i<n;i++)
        for(int j=0;j<n;j++)
            ans[i][j] = v[j][i] - 'a';
    return ans;
}

Matrix computeKey(vector<string>& plainText, Matrix& cipherTextMatrix) {
    int n = plainText.size();
    Matrix plainTextMatrix = convertStringtoMatrix(plainText);
    Matrix plainTextMatrixInverse = computeMatrixInverse(plainTextMatrix);
    if(plainTextMatrixInverse.empty()) return {};
    return squareMatrixMultiplication(cipherTextMatrix, plainTextMatrixInverse);
}

pair<string, Matrix> func(Matrix& cipherTextMatrix) {
    vector<string> frequentPlainTexts(keyLength);
    Matrix key(keyLength, vector<int>(keyLength));
    if(keyLength == 2) {
        int l = digrams.size();
        for(int i=0;i<l;i++) {
            frequentPlainTexts[0] = digrams[i];
            for(int j=0;j<l;j++) {
                if(i == j) continue;
                frequentPlainTexts[1] = digrams[j];
                key = computeKey(frequentPlainTexts, cipherTextMatrix);
                if(key.empty()) continue;
                string recoveredPlainText = decrypt(key);
                if(abs(indexOfCoincidence(recoveredPlainText) - 0.068) < 0.005)
                    return {recoveredPlainText, key};
            }
        }
    }
    else {
        int l = trigrams.size();
        for(int i=0;i<l;i++) {
            frequentPlainTexts[0] = trigrams[i];
            for(int j=0;j<l;j++) {
                if(i == j) continue;
                frequentPlainTexts[1] = trigrams[j];
                for(int k=0;k<l;k++) {
                    if(j == k || k == i) continue;
                    frequentPlainTexts[2]  = trigrams[k];
                    key = computeKey(frequentPlainTexts, cipherTextMatrix);
                    if(key.empty()) continue;
                    string recoveredPlainText = decrypt(key);
                    if(abs(indexOfCoincidence(recoveredPlainText) - 0.068) < 0.005)
                        return {recoveredPlainText, key};
                }
            }
        }
    }
    return {};
}

pair<string, Matrix> cryptAnalysis() {
    vector<string> frequentCipherTexts = mostFrequentGrams(cipherText, keyLength, 7);
    Matrix cipherTextMatrix(keyLength, vector<int>(keyLength));
    vector<string> cipherTexts(keyLength);
    int n = frequentCipherTexts.size();
    pair<string, Matrix> ans;
    if(keyLength == 2) {
        for(int i=0;i<n-1;i++) {
            cipherTexts[0] = frequentCipherTexts[i];
            for(int j=i+1;j<n;j++) {
                cipherTexts[1] = frequentCipherTexts[j];
                cipherTextMatrix = convertStringtoMatrix(cipherTexts);
                if(computeMatrixInverse(cipherTextMatrix).empty()) continue;
                ans = func(cipherTextMatrix);
                if(!ans.Y.empty()) return ans;
            }
        }
    }
    else {
        for(int i=0;i<n-2;i++) {
            cipherTexts[0] = frequentCipherTexts[i];
            for(int j=i+1;j<n-1;j++) {
                cipherTexts[1] = frequentCipherTexts[j];
                for(int k=j+1;k<n;k++) {
                    cipherTexts[2] = frequentCipherTexts[k];
                    cipherTextMatrix = convertStringtoMatrix(cipherTexts);
                    if(computeMatrixInverse(cipherTextMatrix).empty()) continue;
                    ans = func(cipherTextMatrix);
                    if(!ans.Y.empty()) return ans;
                }
            }
        }
    }
    return {};
}

int main() {
    string line; cin >> keyLength;
    assert(keyLength == 2 || keyLength == 3);
    while(getline(cin, line)) cipherText += line + " ";
    pair<string, Matrix> res = cryptAnalysis();
    if(res.X == "") cout << "CryptAnalysis failed. \n";
    else {
        cout << res.X << "\n";
        displayMatrix(res.Y);
    }
    return 0;
}
