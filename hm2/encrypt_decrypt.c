#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define bit 128

#define SMALL "./small"
#define MEDIUM "./medium"
#define BIG "./big"

#define DATA "./data" 

#define BLOCK_LEN 4096

int encrypt(const char *fin, const char *fout, const unsigned char *key,
            const EVP_CIPHER *chiper) {
    FILE *in = fopen(fin, "rb");
    FILE *out = fopen(fout, "wb");
    clock_t start, stop;
    if (in == NULL || out == NULL) {
        perror("error opening files\n");
        return (-1);
    }
    struct stat st;
    stat(fin, &st);
    size_t filesize = st.st_size;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char in_buffer[BLOCK_LEN];
    unsigned char out_buffer[BLOCK_LEN + EVP_MAX_BLOCK_LENGTH]; // it could add some padding
    unsigned char iv[bit] = {0};
    int out_len = 0;
    int read = 0;
    int ret, in_len;
    start = clock();
    EVP_EncryptInit_ex(ctx, chiper, NULL, key, iv);
    while(1){
        in_len = fread(in_buffer, 1, BLOCK_LEN, in); 
        if(in_len <= 0) break;
        ret = EVP_EncryptUpdate(ctx, out_buffer, &out_len, in_buffer, in_len);
        if(ret < 0){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }  
      fwrite(out_buffer, 1, out_len, out);
  }
  
    ret = EVP_EncryptFinal_ex(ctx, out_buffer, &out_len);
    if(ret < 0){
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    fwrite(out_buffer, 1, out_len, out);
    stop = clock();
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    EVP_cleanup();
    return stop - start;
}
int decrypt(const char *fin, const char *fout, const unsigned char *key,
            const EVP_CIPHER *chiper) {
    FILE *in = fopen(fin, "rb");
    FILE *out = fopen(fout, "wb");
    clock_t start, stop;
    if (in == NULL || out == NULL) {
        perror("error opening files\n");
        return (-1);
    }
    struct stat st;
    stat(fin, &st);
    size_t filesize = st.st_size;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char in_buffer[BLOCK_LEN];
    unsigned char out_buffer[BLOCK_LEN + EVP_MAX_BLOCK_LENGTH]; // it could add some padding
    unsigned char iv[bit] = {0};
    int out_len = 0;
    int read = 0;
    int ret, in_len;
    start = clock();
    EVP_DecryptInit_ex(ctx, chiper, NULL, key, iv);
    while(1){
        in_len = fread(in_buffer, 1, BLOCK_LEN, in); 
        if(in_len <= 0) break;
        ret = EVP_DecryptUpdate(ctx, out_buffer, &out_len, in_buffer, in_len);
        if(ret < 0){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }  
        fwrite(out_buffer, 1, out_len, out);
    }
  
    ret = EVP_DecryptFinal_ex(ctx, out_buffer, &out_len);
    if(ret < 0){
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    fwrite(out_buffer, 1, out_len, out);
    stop = clock();
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    EVP_cleanup();
    return stop - start;
}
int main() {
    FILE *small = fopen(SMALL, "wb");
    fseek(small, 16, SEEK_SET);
    fputc('0', small);
    fclose(small);

    FILE *medium = fopen(MEDIUM, "wb");
    fseek(medium, 20000, SEEK_SET);
    fputc('0', medium);
    fclose(medium);

    FILE *big = fopen(BIG, "wb");
    fseek(big, 2000000, SEEK_SET);
    fputc('0', big);
    fclose(big);
    
    FILE* data =  fopen(DATA, "w");
    fprintf(data, "algo,time,size,encrypt/decrypt\n");
    unsigned char key[16];
    int t;
    for(int i = 0; i < 100; i++){
        RAND_bytes(key, 16);
        /*Three encryption-decryption rounds with small file size*/
        t = encrypt("./small", "./decrypt_out", key, EVP_aes_128_cbc());
        fprintf(data, "aes,%d,s,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_aes_128_cbc());
        fprintf(data, "aes,%d,s,d\n", t);

        t = encrypt("./small", "./decrypt_out", key, EVP_camellia_128_cbc());
        fprintf(data, "camellia,%d,s,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_camellia_128_cbc());
        fprintf(data, "camellia,%d,s,d\n", t);

        t = encrypt("./small", "./decrypt_out", key, EVP_sm4_cbc());
        fprintf(data, "sm4,%d,s,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_sm4_cbc());
        fprintf(data, "sm4,%d,s,d\n", t);

        /*Three encryption-decryption rounds with medium file*/
        t = encrypt("./medium", "./decrypt_out", key, EVP_aes_128_cbc());
        fprintf(data, "aes,%d,m,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_aes_128_cbc());
        fprintf(data, "aes,%d,m,d\n", t);

        t = encrypt("./medium", "./decrypt_out", key, EVP_camellia_128_cbc());
        fprintf(data, "camellia,%d,m,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_camellia_128_cbc());
        fprintf(data, "camellia,%d,m,d\n", t); 
        
        t = encrypt("./medium", "./decrypt_out", key, EVP_sm4_cbc());
        fprintf(data, "sm4,%d,m,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_sm4_cbc());
        fprintf(data, "sm4,%d,m,d\n", t);



        t = encrypt("./big", "./decrypt_out", key, EVP_aes_128_cbc());
        fprintf(data, "aes,%d,b,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_aes_128_cbc());
        fprintf(data, "aes,%d,b,d\n", t);

        t = encrypt("./big", "./decrypt_out", key, EVP_camellia_128_cbc());
        fprintf(data, "camellia,%d,b,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_camellia_128_cbc());
        fprintf(data, "camellia,%d,b,d\n", t);

        t = encrypt("./big", "./decrypt_out", key, EVP_sm4_cbc());
        fprintf(data, "sm4,%d,b,e\n", t); 
        t = decrypt("./decrypt_out", "./encrypt_out", key, EVP_sm4_cbc());
        fprintf(data, "sm4,%d,b,d\n", t);

    }
    fclose(data);
    return 0;
}
