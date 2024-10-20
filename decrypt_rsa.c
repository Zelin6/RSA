#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

void handle_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA *load_private_key(const char *filename) {
    FILE *key_file = fopen(filename, "r");
    if (!key_file) {
        perror("无法打开密钥文件");
        return NULL;
    }
    
    RSA *rsa_private_key = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    
    if (!rsa_private_key) {
        handle_error();
    }
    return rsa_private_key;
}

void decrypt_message(RSA *private_key, const char *ciphertext_hex) {
    size_t ciphertext_len = strlen(ciphertext_hex) / 2;
    unsigned char *ciphertext = malloc(ciphertext_len);
    for (size_t i = 0; i < ciphertext_len; i++) {
        sscanf(ciphertext_hex + 2*i, "%2hhx", &ciphertext[i]);
    }
    
    unsigned char *plaintext = malloc(RSA_size(private_key));
    int decrypted_length = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, private_key, RSA_PKCS1_OAEP_PADDING);
    
    if (decrypted_length == -1) {
        handle_error();
    }
    
    printf("解密后的消息: %.*s\n", decrypted_length, plaintext);

    free(ciphertext);
    free(plaintext);
}

int main() {
    const char *private_key_file = "private_key.pem";
    
    RSA *private_key = load_private_key(private_key_file);
    if (!private_key) {
        return EXIT_FAILURE;
    }

    char ciphertext_hex[4096];
    printf("请输入加密后的数据（十六进制编码）: ");
    scanf("%s", ciphertext_hex);

    decrypt_message(private_key, ciphertext_hex);
    
    RSA_free(private_key);
    return EXIT_SUCCESS;
}

