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
    if (argc != 3) {
        printf("Usage: decrypt <key_fname> <msg_fname>");
    }
    FILE *fp = fopen(argv[1], "r");
    assert(fp != NULL);
    RSA *sk = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    assert(sk != NULL);
    fclose(fp);

    printf("Size of public key: %d bytes = %d bits\n", RSA_size(sk), RSA_bits(sk));

    const int key_size = RSA_size(sk);
    unsigned char *buf = calloc(key_size, 1);
    assert(buf != NULL);

    unsigned char *buf2 = calloc(key_size, 1);
    assert(buf2 != NULL);
    
    FILE *en = fopen(argv[2], "rb");
    fread(buf, 1, key_size, en);
    fclose(en);

    printf("decrypting message...\n");
    // if we used no padding, then the returned length would be key_size
    // because we would hvave encrypted a message as large as a block, which
    // is key_size
    int len = RSA_private_decrypt(key_size, buf, buf2, sk, RSA_PKCS1_PADDING);
    assert(len > 0);
    dump_buf("decrypted (hex): ", buf2, key_size);
    /*
    FILE *d = fopen("ciphered.txt", "w");
    assert(d!= NULL);
    fprintf(d, buf2);
    fclose(d);
    */
}
