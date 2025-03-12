#include "encryption.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>

/* Derive a key using Argon2id. Returns 0 on success. */
int derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    int ret = argon2_hash(
        ARGON2_T_COST,           /* time cost */
        ARGON2_M_COST,           /* memory cost (KiB) */
        ARGON2_PARALLELISM,      /* parallelism */
        password, strlen(password),
        salt, SALT_LEN,
        key, KEY_LEN,
        NULL, 0,               /* no encoded output */
        Argon2_id, ARGON2_VERSION_13);
    return ret;  /* 0 on success */
}

int encrypt_data(const uint8_t *plaintext, int plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t **ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total_len = 0;
    /* Allocate worst-case output buffer */
    *ciphertext = malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (!*ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        goto err;
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1)
        goto err;
    total_len = len;
    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1)
        goto err;
    total_len += len;
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    free(*ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int decrypt_data(const uint8_t *ciphertext, int ciphertext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total_len = 0;
    /* Allocate a buffer for plaintext and an extra byte for a null terminator */
    *plaintext = malloc(ciphertext_len + 1);
    if (!*plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        goto err;
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1)
        goto err;
    total_len = len;
    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1)
        goto err;
    total_len += len;
    /* Null-terminate the output so that text can be printed safely.
       (When decrypting a file, your file‑writing code should use decrypted_len.) */
    (*plaintext)[total_len] = '\0';
    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    free(*plaintext);
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
