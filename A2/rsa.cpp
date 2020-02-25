#include <bits/stdc++.h>
#include <gmpxx.h>

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
    while(mpz_probab_prime_p(r.get_mpz_t(), 50) == 0) r += t<<1;
    e = r-2;
    mpz_powm (p0.get_mpz_t(), s.get_mpz_t(), e.get_mpz_t(), r.get_mpz_t());
    p0 = 2 * p0 * s - 1;
    mpz_urandomb(j.get_mpz_t(), state, 50);
    p = p0 + 2 * j * r * s;
    while(mpz_probab_prime_p(p.get_mpz_t(), 50) == 0) p += (r * s)<<1;
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
    mpz_class power(mpz_class) const;
};

mpz_class secretKey::power(mpz_class m) const {
    mpz_class mp = m % p, mq = m % q;
    mpz_powm(mp.get_mpz_t(), mp.get_mpz_t(), d.get_mpz_t(), p.get_mpz_t());
    mpz_powm(mq.get_mpz_t(), mq.get_mpz_t(), d.get_mpz_t(), q.get_mpz_t());
    mpz_class p_1, q_1;
    mpz_invert(p_1.get_mpz_t(), p.get_mpz_t(), q.get_mpz_t());
    mpz_invert(q_1.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t());
    return (mp * q * q_1 + mq * p * p_1) % (p * q);
}

class User {
    int id;         // identity of user
    publicKey pk;   // public key
    secretKey sk;   // secret key

    pair<publicKey, secretKey> generateKey();
public:
    User(int);
    int getID();
    publicKey getPublicKey();
    string encrypt(string, User);
    string decrypt(string, User); 
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

int User::getID() {return id;}

publicKey User::getPublicKey() {return pk;}



// string User::encrypt(string m, User b) {

// }

int main() {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(0));
    // mpz_class p = generate_prime(100);
    // // cout<<p<<endl;
    // mpz_class p0 = generateStrongPrime();
    // // cout<<p0<<"\n";
    // // cout<<p0.get_str().size()<<"\n";
    // publicKey k(p, p0);
    // cout<<p<<"\n";
    // cout<<k.get_n()<<"\n";
    // cout<<p0<<"\n";
    // cout<<k.get_e()<<"\n";
    User a(123), b(256);
    publicKey pka = a.getPublicKey(), pkb = b.getPublicKey();
    // cout<<pka.get_n()<<"\n";
    // cout<<pka.get_e()<<"\n";
    // cout<<pkb.get_n()<<"\n";
    // cout<<pkb.get_e()<<"\n";
    return 0;
}
