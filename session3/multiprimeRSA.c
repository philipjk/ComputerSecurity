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
    BIGNUM *ret1;
    BIGNUM *ret2;
    BIGNUM *ret3;

    BN_generate_prime_ex(ret1, 1024, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(ret2, 1024, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(ret3, 1024, 1, NULL, NULL, NULL);

    // find modulus
    BIGNUM *m;
    BN_mul(m, ret1, ret2, ctx);
    BN_mul(m, m, ret3, ctx);

    // find LCM
    // first find primes - 1
    BIGNUM *one = BIG_value_one();
    BIGNUM *lambda;
    BIGNUM *f1;
    BIGNUM *f2;
    BIGNUM *f3;

    

    
}
