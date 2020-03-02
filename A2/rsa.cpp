#include <bits/stdc++.h>
#include <gmpxx.h>

using namespace std;

gmp_randstate_t state;

/*/------------------Functions to generate Primes and Strong Primes-------------------/*/

mpz_class generate_prime(int bit_length) {
    mpz_class p;
    mpz_urandomb(p.get_mpz_t(), state, bit_length);
    while(mpz_probab_prime_p(p.get_mpz_t(), 50) == 0)
        mpz_urandomb(p.get_mpz_t(), state, bit_length);
    return p;
}

mpz_class generateStrongPrime(int bit_length) {
    mpz_class r, s, t, i, j, p0, p, e;
    s = generate_prime(bit_length); t = generate_prime(bit_length);
    mpz_urandomb(i.get_mpz_t(), state, bit_length);
    r = 2 * i * t + 1;
    while(mpz_probab_prime_p(r.get_mpz_t(), 50) == 0) r += 2 * t;
    e = r - 2;
    mpz_powm(p0.get_mpz_t(), s.get_mpz_t(), e.get_mpz_t(), r.get_mpz_t());
    p0 = 2 * p0 * s - 1;
    mpz_urandomb(j.get_mpz_t(), state, bit_length);
    p = p0 + 2 * j * r * s;
    while(mpz_probab_prime_p(p.get_mpz_t(), 50) == 0) p += 2 * r * s;
    // p nearly of size 4 * bit_length
    return p;
}

/*/-------------------Encryption and Decryption using Vignere Cipher------------------/*/

string encryptVignere(string plainText, string key) {
    string cipherText = ""; int m_size = plainText.size(), k_size = key.size();
    char c;
    for(int i=0;i<m_size;i++) {
        c = (plainText[i] - 'a' + key[i % k_size] - 'a') % 26 + 'a';
        cipherText += c;
    }
    return cipherText;
}

string decryptVignere(string cipherText, string key) {
    string plainText = ""; int c_size = cipherText.size(), k_size = key.size();
    char c;
    for(int i=0;i<c_size;i++) {
        c = (cipherText[i] - key[i % k_size] + 26) % 26 + 'a';
        plainText += c;
    }
    return plainText;
}

/*/-------------------------------Helper Functions------------------------------------/*/

int getBlockSize(mpz_class n) {
    int r = 0;
    mpz_class ans = 1;
    while(ans < n) {ans *= 26; r++;}
    return r-1;
}

string preProcess(string message, int blockSize) {
    int pos = -1;
    for(int i=message.size()-1;i>=0;i--)
        if(message[i] != 'x')
            {pos = i; break;}
    int new_n = ((pos + blockSize) / blockSize) * blockSize;
    return message.substr(0, new_n);
}

/*/------------------------------Public Key Class-----------------------------------/*/

class publicKey {
    mpz_class n, e;
public:
    publicKey() {}
    publicKey(mpz_class n, mpz_class e) : n(n), e(e) {}
    mpz_class get_n() const {return n;}
    mpz_class get_e() const {return e;}
    string encrypt(string, int) const;
    mpz_class encrypt(mpz_class) const;
};

string publicKey::encrypt(string plainText, int a) const {
    int blockSize = getBlockSize(n);
    if(a == 1) plainText = preProcess(plainText, blockSize+a);
    string cipherText = "";
    for(int i=0;i<plainText.size();i+=blockSize+a) {
        mpz_class M = 0, tmp;
        for(int j=i;j<i+blockSize+a;j++) {
            M *= 26;
            if(j < plainText.size()) M += plainText[j] - 'a';
            else M += 'x' - 'a';
        }
        mpz_powm(M.get_mpz_t(), M.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
        for(int j=0;j<blockSize+1-a;j++) {
            tmp = M % 26;
            cipherText += 'a' + mpz_get_ui(tmp.get_mpz_t());
            M /= 26;
        }
    }
    return cipherText;
}

mpz_class publicKey::encrypt(mpz_class m) const {
    mpz_class ans;
    mpz_powm(ans.get_mpz_t(), m.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
    return ans;
}

/*/------------------------------Secret Key Class-----------------------------------/*/

class secretKey {
    mpz_class p, q, d;
public:
    secretKey() {}
    secretKey(mpz_class p, mpz_class q, mpz_class d) : p(p), q(q), d(d) {}
    mpz_class powerCRT(mpz_class) const;
    string decrypt(string, int) const;
    mpz_class decrypt(mpz_class m) const {return powerCRT(m);}
};

mpz_class secretKey::powerCRT(mpz_class m) const {
    mpz_class mp = m % p, mq = m % q;
    mpz_powm(mp.get_mpz_t(), mp.get_mpz_t(), d.get_mpz_t(), p.get_mpz_t());
    mpz_powm(mq.get_mpz_t(), mq.get_mpz_t(), d.get_mpz_t(), q.get_mpz_t());
    mpz_class p_1, q_1;
    mpz_invert(p_1.get_mpz_t(), p.get_mpz_t(), q.get_mpz_t());
    mpz_invert(q_1.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t());
    return (mp * q * q_1 + mq * p * p_1) % (p * q);
}

string secretKey::decrypt(string cipherText, int a) const {
    mpz_class n = p * q;
    int blockSize = getBlockSize(n);
    string plainText = "";
    for(int i=0;i<cipherText.size();i+=blockSize+a) {
        mpz_class M = 0, pow_26 = 1, tmp;
        for(int j=i;j<i+blockSize+a;j++) {
            if(j < cipherText.size()) M += pow_26 * (cipherText[j] - 'a');
            else M += pow_26 * ('x' - 'a');
            pow_26 *= 26;
        }
        M = powerCRT(M);
        string rev = "";
        for(int j=0;j<blockSize+1-a;j++) {
            tmp = M % 26;
            rev += 'a' + mpz_get_ui(tmp.get_mpz_t());
            M /= 26;
        }
        reverse(rev.begin(), rev.end());
        plainText += rev;
    }
    return plainText;
}

/*/---------------------------Function to generate Key--------------------------------/*/

pair<publicKey, secretKey> generateKey(int bit_length) {
    mpz_class p = generateStrongPrime(bit_length), q = generateStrongPrime(bit_length);
    mpz_class threshold;
    mpz_ui_pow_ui(threshold.get_mpz_t(), 2, 4 * bit_length);
    while(abs(p - q) < threshold) q = generateStrongPrime(bit_length);
    mpz_class n = p * q, phi_n = (p - 1) * (q - 1), d, e;
    // n has size nearly 8 * bit_length
    mpz_urandomb(e.get_mpz_t(), state, bit_length);
    while(gcd(e, phi_n) != 1) mpz_urandomb(e.get_mpz_t(), state, bit_length);
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi_n.get_mpz_t());
    return {publicKey(n, e), secretKey(p, q, d)};
}

/*/---------------------Certification Authority and User Class-----------------------/*/

class CertificationAuthority;

class User {
    int id;         // identity of user
    secretKey sk;   // secret key
public:
    User(int);
    int getID() const {return id;};
    string encrypt(string, string, int) const;
    string decrypt(string, int) const;
};

class CertificateAuthority {
    map<int, publicKey> table;
    publicKey pk;
    secretKey sk;
public:
    CertificateAuthority();
    publicKey getPublicKey() const {return pk;};
    secretKey registerUser(User u);
    publicKey getPublicKeyOfUser(int);
} *CA;

User::User(int id) {
    this->id = id;
    this->sk = CA->registerUser(*this);
}

string number_to_string(int n) {
    string ans = "";
    while(n) {
        ans += 'a' + (n % 10);
        n /= 10;
    }
    reverse(ans.begin(), ans.end());
    return ans;
}

int string_to_number(string s) {
    int ans = 0;
    for(char c : s)
        ans = ans * 10 + (c - 'a');
    return ans;
}

string User::encrypt(string message, string vignereKey, int b_id) const {
    publicKey pkCA = CA->getPublicKey();
    publicKey pkb = CA->getPublicKeyOfUser(b_id);
    publicKey pkb_actual(pkCA.encrypt(pkb.get_n()), pkCA.encrypt(pkb.get_e()));
    message = number_to_string(vignereKey.size()) + 'x' + number_to_string(message.size()) + 'x' + vignereKey + encryptVignere(message, vignereKey);
    return pkb_actual.encrypt(sk.decrypt(message, 0), 0);
}

string User::decrypt(string message, int a_id) const {
    publicKey pkCA = CA->getPublicKey();
    publicKey pka = CA->getPublicKeyOfUser(a_id);
    publicKey pka_actual(pkCA.encrypt(pka.get_n()), pkCA.encrypt(pka.get_e()));
    message = pka_actual.encrypt(sk.decrypt(message, 1), 1);
    int pos = -1, new_pos = -1;
    for(int i=0;i<message.size();i++)
        if(message[i] == 'x') {pos = i; break;}
    int vignereKeyLength = string_to_number(message.substr(0, pos));
    for(int i=pos+1;i<message.size();i++)
        if(message[i] == 'x') {new_pos = i; break;}
    int messageLength = string_to_number(message.substr(pos+1, new_pos-pos-1));
    string vignereKey = message.substr(new_pos+1, vignereKeyLength);
    message = message.substr(new_pos+vignereKeyLength+1, messageLength);
    return decryptVignere(message, vignereKey);
}

CertificateAuthority::CertificateAuthority() {
    pair<publicKey, secretKey> key = generateKey(200);
    this->pk = key.first;
    this->sk = key.second;
}

secretKey CertificateAuthority::registerUser(User u) {
    if(table.find(u.getID()) != table.end()) {
        throw "This ID is already with another user !";
        exit(0);
    }
    else {
        pair<publicKey, secretKey> key = generateKey(128);
        table[u.getID()] = publicKey(sk.decrypt(key.first.get_n()), sk.decrypt(key.first.get_e()));
        return key.second;
    }
}

publicKey CertificateAuthority::getPublicKeyOfUser(int id) {
    if(table.find(id) == table.end()) {
        throw "No such user !";
        exit(0);
    }
    else return table[id];
}

int main() {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(0));
    CA = new CertificateAuthority();
    User a(123), b(256);
    string vignereKey = "afeshadfkaklnljabjdsvhkjdfhsjgvbsduofvvlbdfsn";
    string msg; cin >> msg;
    string c = a.encrypt(msg, vignereKey, b.getID());
    cout << b.decrypt(c, a.getID()) << "\n";
    c = b.encrypt(msg, vignereKey, a.getID());
    cout<< a.decrypt(c, b.getID()) << "\n";
    return 0;
}
