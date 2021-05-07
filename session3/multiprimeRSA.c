#include <openssl/bn.h>
#include <string.h>

void dump_buf(const char *text, unsigned char *buf, int buf_size) {
    printf("%s", text);
    for (int i=0; i<=buf_size; i++) {
        printf("%02x:", buf[i]);
    }
    printf("]\n");
}

int main (int argc, const char *argv[]) {

    if (argc != 2) {
        printf("Usage: multiprimeRSA <(numeric) message>\n");
        exit(0);
    }
    BN_CTX *ctx = BN_CTX_new();

    // find three primes
    BIGNUM *ret1 = BN_new();
    BIGNUM *ret2 = BN_new();
    BIGNUM *ret3 = BN_new();

    int size = 256;
    BN_generate_prime_ex(ret1, size, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(ret2, size, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(ret3, size, 1, NULL, NULL, NULL);

    // find modulus a.k.a. the first part of the public key
    BIGNUM *m = BN_new();
    BN_mul(m, ret1, ret2, ctx);
    BN_mul(m, m, ret3, ctx);

    // find LCM
    // first find primes - 1
    const BIGNUM *one = BN_value_one();
    BIGNUM *f1 = BN_new();
    BIGNUM *f2 = BN_new();
    BIGNUM *f3 = BN_new();
    BN_sub(f1, ret1, one);
    BN_sub(f2, ret2, one);
    BN_sub(f3, ret3, one);

    // find f1 x f2 x f3
    BIGNUM *prod = BN_new();
    BN_mul(prod, f1, f2, ctx);
    BN_mul(prod, prod, f3, ctx);

    // find gcd
    BIGNUM *gcd = BN_new();
    BN_gcd(gcd, f1, f2, ctx);
    BN_gcd(gcd, gcd, f3, ctx);

    // now find LCM
    BIGNUM *lambda = BN_new();
    BN_div(lambda, NULL, prod, gcd, ctx);

    // set exponent a.k.a. the second part of the public key
    BIGNUM *e = BN_new();
    const char *exp_string = "3";
    BN_dec2bn(&e, exp_string);

    // find modular inverse of e modulo lambda (basically the private key)
    BIGNUM *d = BN_new();
    BN_mod_inverse(d, e, lambda, ctx);

    // encrypt
    BIGNUM *encrypted = BN_new();
    BIGNUM *message = BN_new(); // content will be 100
    const char *message_str = argv[1];
    printf("Cleartext message: [%s]\n", message_str);
    BN_dec2bn(&message, message_str);
    BN_mod_exp(encrypted, message, e, m, ctx);

    // decrypt
    char *encrypted_str = BN_bn2hex(encrypted);
    dump_buf("Ciphertext message: [", (unsigned char *) encrypted_str, strlen(encrypted_str));
    BN_mod_exp(encrypted, encrypted, d, m, ctx);
    char *result = BN_bn2dec(encrypted);
    printf("Decrypted message: [%s]\n", result);

}
