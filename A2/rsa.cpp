#include <bits/stdc++.h>
#include <gmpxx.h>

/*
 * TODO:
 * integrate vignere cipher
 * CA
 * Larger Primes
 */

using namespace std;

gmp_randstate_t state;

mpz_class generate_prime(int bit_length) {
    mpz_class p;
    mpz_urandomb(p.get_mpz_t(), state, bit_length);
    while(mpz_probab_prime_p(p.get_mpz_t(), 50) == 0)
        mpz_urandomb(p.get_mpz_t(), state, bit_length);
    return p;
}

mpz_class generateStrongPrime() {
    mpz_class r, s, t, i, j, p0, p, e;
    s = generate_prime(100); t = generate_prime(100);
    mpz_urandomb(i.get_mpz_t(), state, 50);
    r = 2 * i * t + 1;
    while(mpz_probab_prime_p(r.get_mpz_t(), 50) == 0) r += 2 * t;
    e = r - 2;
    mpz_powm(p0.get_mpz_t(), s.get_mpz_t(), e.get_mpz_t(), r.get_mpz_t());
    p0 = 2 * p0 * s - 1;
    mpz_urandomb(j.get_mpz_t(), state, 50);
    p = p0 + 2 * j * r * s;
    while(mpz_probab_prime_p(p.get_mpz_t(), 50) == 0) p += 2 * r * s;
    return p;
}

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

class publicKey {
    mpz_class n, e;
public:
    publicKey() {}
    publicKey(mpz_class n, mpz_class e) {
        this->n = n;
        this->e = e;
    }
    mpz_class get_n() const {return n;}
    mpz_class get_e() const {return e;}
    string encrypt(string) const;
};

class secretKey {
    mpz_class p, q, d;
public:
    secretKey() {}
    secretKey(mpz_class p, mpz_class q, mpz_class d) {
        this->p = p;
        this->q = q;
        this->d = d;
    }
    mpz_class get_p() const {return p;}
    mpz_class get_q() const {return q;}
    mpz_class get_d() const {return d;}
    mpz_class powerCRT(mpz_class) const;
    string decrypt(string) const;
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

int getBlockSize(mpz_class n) {
    int r = 0;
    mpz_class ans = 1;
    while(ans < n) {ans *= 26; r++;}
    return r-2;
}

string publicKey::encrypt(string plainText) const {
    int blockSize = getBlockSize(n);
    string cipherText = "";
    for(int i=0;i<plainText.size();i+=blockSize) {
        mpz_class M = 0, tmp;
        for(int j=i;j<i+blockSize;j++) {
            M *= 26;
            if(j < plainText.size()) M += plainText[j] - 'a';
            else M += 'x' - 'a';
        }
        assert(M < n);
        mpz_powm(M.get_mpz_t(), M.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
        for(int j=0;j<=blockSize;j++) {
            tmp = M % 26;
            cipherText += 'a' + mpz_get_ui(tmp.get_mpz_t());
            M /= 26;
        }
    }
    return cipherText;
}

string secretKey::decrypt(string cipherText) const {
    mpz_class n = p * q;
    int blockSize = getBlockSize(n) + 1;
    string plainText = "";
    for(int i=0;i<cipherText.size();i+=blockSize) {
        mpz_class M = 0, pow_26 = 1, tmp;
        for(int j=i;j<i+blockSize;j++) {
            if(j < cipherText.size()) M += pow_26 * (cipherText[j] - 'a');
            else M += pow_26 * ('x' - 'a');
            pow_26 *= 26;
        }
        assert(M < n);
        M = powerCRT(M);
        string rev = "";
        for(int j=0;j<blockSize-1;j++) {
            tmp = M % 26;
            rev += 'a' + mpz_get_ui(tmp.get_mpz_t());
            M /= 26;
        }
        reverse(rev.begin(), rev.end());
        plainText += rev;
    }
    return plainText;
}

class User {
    int id;         // identity of user
    publicKey pk;   // public key
    secretKey sk;   // secret key
    pair<publicKey, secretKey> generateKey();
public:
    User(int);
    int getID() const;
    publicKey getPublicKey() const;
    string encrypt(string, User) const;
    string decrypt(string, User) const; 
};


class CertificateAuthority {
    map<int, publicKey> table;
public:
    void registerUser(User u);
    publicKey getPublicKeyOfUser(int);
} CA;


void CertificateAuthority::registerUser(User u) {
    if(table.find(u.getID()) != table.end()) {
        throw "This ID is already with another user !";
    }
    else {
        table[u.getID()] = u.getPublicKey();
    }
}

publicKey CertificateAuthority::getPublicKeyOfUser(int id) {
    if(table.find(id) == table.end()) {
        throw "No such user !";
    }
    else {
        return table[id];
    }
}

pair<publicKey, secretKey> User::generateKey() {
    mpz_class p = generateStrongPrime(), q = generateStrongPrime();
    // insert a while loop till abs(p-q) < threshold
    mpz_class n = p * q, phi_n = (p - 1) * (q - 1), d, e;
    mpz_urandomb(e.get_mpz_t(), state, 50);
    while(gcd(e, phi_n) != 1) mpz_urandomb(e.get_mpz_t(), state, 50);
    mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi_n.get_mpz_t());
    return {publicKey(n, e), secretKey(p, q, d)};
}

User::User(int id) {
    this->id = id;
    pair<publicKey, secretKey> key = generateKey();
    this->pk = key.first;
    this->sk = key.second;
    CA.registerUser(*this);
}

int User::getID() const {return id;}

publicKey User::getPublicKey() const {return pk;}

string User::encrypt(string message, User b) const {
    return b.getPublicKey().encrypt(sk.decrypt(message));
    // return b.getPublicKey().encrypt(message);
}

string User::decrypt(string message, User a) const {
    return a.getPublicKey().encrypt(sk.decrypt(message));
    // return sk.decrypt(message);
}

int main() {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, 0);
    User a(123), b(256);
    // publicKey pka(55, 3); secretKey ska(11, 5, 27);
    // publicKey pkb(35, 5); secretKey skb(5, 7, 5);
    // a.pk = pka; a.sk = ska;
    // b.pk = pkb; b.sk = skb; 
    string c = a.encrypt("tanishqissuperhot", b);
    cout<<b.decrypt(c, a)<<"\n";
    return 0;
}
