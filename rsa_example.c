#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA *loadKeyFromFile(const char *filename, int is_public) {
    FILE *key_file = fopen(filename, "rb");
    if (!key_file) {
        perror("Unable to open key file");
        return NULL;
    }
    
    RSA *rsa_key = is_public ? PEM_read_RSA_PUBKEY(key_file, NULL, NULL, NULL) :
                               PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    
    if (!rsa_key) {
        handleErrors();
    }
    return rsa_key;
}

unsigned char* encryptMessage(RSA *public_key, const char *message, int *encrypted_length) {
    int rsa_len = RSA_size(public_key);
    unsigned char *ciphertext = malloc(rsa_len);
    
    *encrypted_length = RSA_public_encrypt(strlen(message), (unsigned char*)message, ciphertext, public_key, RSA_PKCS1_OAEP_PADDING);
    if (*encrypted_length == -1) {
        handleErrors();
    }
    
    return ciphertext;
}

char* decryptMessage(RSA *private_key, const unsigned char *ciphertext, int cipher_length) {
    int rsa_len = RSA_size(private_key);
    unsigned char *plaintext = malloc(rsa_len + 1);
    
    int decrypted_length = RSA_private_decrypt(cipher_length, ciphertext, plaintext, private_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        handleErrors();
    }

    plaintext[decrypted_length] = '\0'; // 添加字符串结束符
    return (char*)plaintext;
}

int main() {
    const char *public_key_file = "public_key.pem";
    const char *private_key_file = "private_key.pem";

    RSA *public_key = loadKeyFromFile(public_key_file, 1);
    RSA *private_key = loadKeyFromFile(private_key_file, 0);

    char message[256];
    printf("请输入要加密的消息: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = 0; // 移除换行符

    int encrypted_length;
    unsigned char *encrypted_message = encryptMessage(public_key, message, &encrypted_length);
    
    printf("加密后的消息 (十六进制): ");
    for (int i = 0; i < encrypted_length; i++) {
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");

    char *decrypted_message = decryptMessage(private_key, encrypted_message, encrypted_length);
    printf("解密后的消息: %s\n", decrypted_message);

    free(encrypted_message);
    free(decrypted_message);
    RSA_free(public_key);
    RSA_free(private_key);
    
    return 0;
}

