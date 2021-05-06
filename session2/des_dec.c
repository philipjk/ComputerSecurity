#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/des.h>
#include <openssl/rand.h>

int BUF_SZ = 1024;

void dump_buf(char *pretext, char *buf, int length) {
    printf("%s", pretext);
    for (int i=0; i < length; i++)
        printf("%02x:", buf[i]);
    printf("\n");
}

int main(int argc, const char * argv[]) {
    int block_sz = 8;
    
    // read key file
    printf("Reading key file\n");
    DES_cblock sk;
    FILE *key_fp;
    key_fp = fopen("symkey.bin", "r");
    fread(&sk, 1, block_sz, key_fp);
    fclose(key_fp);

    // read ciphered text file
    printf("Reading cipherd file\n");
    char *c_buf = malloc(BUF_SZ);
    FILE *cip_fp;
    cip_fp = fopen("ciphered.txt", "r");
    fread(c_buf, 1, BUF_SZ, cip_fp);
    fclose(cip_fp);

    // prepare key schedule
    DES_key_schedule key_sched;
    DES_key_sched((const_DES_cblock*) sk, &key_sched);

    // decrypt
    char *d_buf = malloc(BUF_SZ);
    printf("decrypting\n");
    // ECB
    /*
    for (int i=0; i < BUF_SZ; i += 8) {
        DES_ecb_encrypt((const_DES_cblock *) (c_buf + i), (DES_cblock* ) (d_buf + i),
                         &key_sched,  DES_DECRYPT);
    }
    */
    // CFB
    DES_cblock iv = {0,1,2,3,4,5,6,7};
    DES_cfb_encrypt((unsigned char *) c_buf, (unsigned char *)d_buf,
                     1, BUF_SZ, &key_sched,
                     &iv, DES_DECRYPT);
    int index = (int) (strchr(d_buf, '\0') - d_buf);
    dump_buf("Deciphered: ", (char *) d_buf, index);
}
