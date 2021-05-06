#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <assert.h>
#include <string.h>


void dump_buf(const char *text, unsigned char *buf, int buf_size) {
    printf("%s", text);
    for (int i=0; i<=buf_size; i++) {
        printf("%02x:", buf[i]);
    }
    printf("\n");
}

int main(int argc, const char *argv[]) {
    if (argc != 4) {
        printf("Usage: encrypt <key_fname> <message> <out_fname>\n");
        exit(0);
    }
    const char *key_fname = argv[1];
    const char *msg = argv[2];
    const char *out_fname = argv[3];

    FILE *fp = fopen(key_fname, "r");
    assert(fp != NULL);
    RSA *pk = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    assert(pk != NULL);
    fclose(fp);

    printf("Size of private key: %d bytes = %d bits\n", RSA_size(pk), RSA_bits(pk));

    const int key_size = RSA_size(pk);
    unsigned char *buf = (unsigned char *) msg; 
    assert(buf != NULL);

    unsigned char *buf2 = calloc(key_size, 1);
    assert(buf2 != NULL);

    int msg_len = strlen(msg) + 1; // for the null string terminator
    assert(msg_len <= key_size);

    dump_buf("plaintext (hex): ", buf, key_size);

    printf("encrypting message...\n");
    // if we were not using padding, then we would allocate key_size unsigned chars to 
    // pointer buf and use key_size instead of msg_len
    assert(RSA_public_encrypt(msg_len, buf, buf2, pk, RSA_PKCS1_PADDING) == key_size);
    dump_buf("encrypted (hex): ", buf2, key_size);
    
    FILE *d = fopen(out_fname, "wb");
    assert(d!= NULL);
    fwrite(buf2, 1, key_size, d);
    fclose(d);
    
    return 0;
}
