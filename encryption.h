#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#ifndef ARGON2_T_COST
#define ARGON2_T_COST 3
#endif

#ifndef ARGON2_M_COST
#define ARGON2_M_COST 4096  // Memory cost in KiB
#endif

#ifndef ARGON2_PARALLELISM
#define ARGON2_PARALLELISM 1
#endif

#include <stdint.h>

/* Constants for key derivation and encryption */
#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32

/* 
 * derive_key
 * Derives a 256-bit key using Argon2id.
 * Returns 0 on success, nonzero on failure.
 */
int derive_key(const char *password, const uint8_t *salt, uint8_t *key);

/*
 * encrypt_data
 * Encrypts plaintext (of length plaintext_len) using AES-256-CBC with PKCS7 padding.
 * On success, *ciphertext is allocated (caller must free it) and ciphertext_len is set.
 * Returns 0 on success, nonzero on failure.
 */
int encrypt_data(const uint8_t *plaintext, int plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t **ciphertext, int *ciphertext_len);

/*
 * decrypt_data
 * Decrypts ciphertext (of length ciphertext_len) using AES-256-CBC with PKCS7 padding.
 * On success, *plaintext is allocated (caller must free it) and plaintext_len is set.
 * Returns 0 on success, nonzero on failure.
 */
int decrypt_data(const uint8_t *ciphertext, int ciphertext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t **plaintext, int *plaintext_len);

#endif  /* ENCRYPTION_H */
