#include <math.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

int BUF_SZ = 1024;

void dump_buf(char *pretext, unsigned char *buf, int length) {
    printf("%s", pretext);
    for (int i=0; i < length; i++) 
        printf("%02x:", buf[i]);
    printf("\n");
}

int main(int argc, const char *argv[]) {

    unsigned char *seed = calloc(5, 1); 
    RAND_bytes(seed, 5); // why? what size?

    DES_cblock sk;
    DES_random_key(&sk);
    assert(sk != NULL);

    DES_key_schedule key_sched; // what is this
    DES_key_sched((const_DES_cblock *) sk, &key_sched);
    
    int block_sz = 8;
    char plaintext[BUF_SZ];
    strcpy(plaintext, "*Bart Simpson writing on the blackboard*: I will practice C programming");
    unsigned char output[BUF_SZ];

    dump_buf("plain text block: ", (unsigned char *)plaintext, strlen(plaintext));

    // encrypt

    /* ECB
    for (int i=0; i<strlen(plaintext); i+=block_sz) {
        DES_ecb_encrypt((const_DES_cblock *) (plaintext + i),(DES_cblock *) (output + i),
                         &key_sched, DES_ENCRYPT);
    }
    */
    // CFB
    DES_cblock iv = {0,1,2,3,4,5,6,7};
    // DES_cblock ivi;
    // RAND_bytes(iv, 8);
    DES_cfb_encrypt((const unsigned char *) plaintext, output,
                     1, strlen(plaintext), 
                     &key_sched, &iv,
                     DES_ENCRYPT);
    dump_buf("ciphered text block: ", (unsigned char *) output, strlen(plaintext));
    
    // save key
    printf("Writing bin key \n");
    FILE *kp;
    kp = fopen("symkey.bin", "w");
    assert(kp != NULL);
    fwrite(&sk, 1, 8, kp);
    fclose(kp);

    // write ciphered text
    printf("Writing ciphered text\n");
    FILE *cp;
    cp = fopen("ciphered.txt", "w");
    fwrite(&output, 1, BUF_SZ , cp);
    fclose(cp);

}
