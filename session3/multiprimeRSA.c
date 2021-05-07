#include <openssl/bn.h>

void dump_buf(const char *text, unsigned char *buf, int buf_size) {
    printf("%s", text);
    for (int i=0; i<=buf_size; i++) {
        printf("%02x:", buf[i]);
    }
    printf("\n");
}


int main (void) {
    BN_CTX *ctx = BN_CTX_new();
    
    // find three primes
    BIGNUM *ret1 = NULL;
    BIGNUM *ret2 = NULL;
    BIGNUM *ret3 = NULL;

    BN_generate_prime_ex(ret1, 1024, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(ret2, 1024, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(ret3, 1024, 1, NULL, NULL, NULL);

    // find modulus
    BIGNUM *m = NULL;
    BN_mul(m, ret1, ret2, ctx);
    BN_mul(m, m, ret3, ctx);

    // find LCM
    // first find primes - 1
    const BIGNUM *one = BN_value_one();
    BIGNUM *f1 = NULL;
    BIGNUM *f2 = NULL;
    BIGNUM *f3 = NULL;
    BN_sub(f1, ret1, one);
    BN_sub(f2, ret2, one);
    BN_sub(f3, ret3, one);

    // find f1 x f2 x f3
    BIGNUM *prod = NULL;
    BN_mul(prod, f1, f2, ctx);
    BN_mul(prod, prod, f3, ctx);
    
    // find gcd
    BIGNUM *gcd = NULL;
    BN_gcd(gcd, f1, f2, ctx);
    BN_gcd(gcd, gcd, f3, ctx);

    // find LCM
    BIGNUM *lambda = NULL;
    BN_div(lambda, NULL, prod, gcd, ctx);
    
    // set exponent
    BIGNUM **e = NULL;
    const char *exp_string = "3";
    BN_dec2bn(e, exp_string);

    // find modular inverse of e modulo lambda
    BIGNUM *d = NULL;
    BN_mod_inverse(d, *e, lambda, ctx);

    // encrypt
    BIGNUM *encrypted = NULL;
    BIGNUM **message = NULL; // content will be 100
    const char *message_str = "100";
    BN_dec2bn(message, message_str);
    BN_mod_exp(encrypted, *message, *e, m, ctx);

    // decrypt
    BN_mod_exp(encrypted, *message, d, m, ctx);
    char *result = BN_bn2dec(encrypted);
    printf("%s\n", result);
    
    
}
