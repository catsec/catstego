#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <jpeglib.h>
#include "encryption.h"
#include "fileio.h"
#include "stego.h"



#define HEADER_SIZE (4 + 16 + 16)  // 4-byte payload bit-length, IV, and salt

/* Function to print usage information */
void print_usage(const char *progname) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  Encode mode:\n");
    fprintf(stderr, "    %s -e|--encode -i|--input <cover.jpg> -t|--text <secret text or secret file> -p|--password <password> -o|--output <new_cover.jpg> [--delete|-D]\n", progname);
    fprintf(stderr, "  Decode mode:\n");
    fprintf(stderr, "    %s -d|--decode -i|--input <stego.jpg> -p|--password <password> [-o|--output <output file>]\n", progname);
}

/* Forward declarations */
int encode_mode(const char *cover_path, const char *secret_arg, const char *password, const char *output_path, int delete_flag);
int decode_mode(const char *stego_path, const char *password, const char *output_path);

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    int encode = 0, decode = 0, delete_flag = 0;
    const char *input = NULL, *text = NULL, *password = NULL, *output = NULL;

    /* Parse command-line arguments */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-e") == 0) || (strcmp(argv[i], "--encode") == 0))
            encode = 1;
        else if ((strcmp(argv[i], "-d") == 0) || (strcmp(argv[i], "--decode") == 0))
            decode = 1;
        else if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "--input") == 0)) {
            if (++i < argc) input = argv[i];
            else { fprintf(stderr, "Error: --input requires a value.\n"); return 1; }
        } else if ((strcmp(argv[i], "-t") == 0) || (strcmp(argv[i], "--text") == 0)) {
            if (++i < argc) text = argv[i];
            else { fprintf(stderr, "Error: --text requires a value.\n"); return 1; }
        } else if ((strcmp(argv[i], "-p") == 0) || (strcmp(argv[i], "--password") == 0)) {
            if (++i < argc) password = argv[i];
            else { fprintf(stderr, "Error: --password requires a value.\n"); return 1; }
        } else if ((strcmp(argv[i], "-o") == 0) || (strcmp(argv[i], "--output") == 0)) {
            if (++i < argc) output = argv[i];
            else { fprintf(stderr, "Error: --output requires a value.\n"); return 1; }
        } else if ((strcmp(argv[i], "--delete") == 0) || (strcmp(argv[i], "-D") == 0))
            delete_flag = 1;
        else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (encode && decode) {
        fprintf(stderr, "Error: Specify either encode or decode mode, not both.\n");
        return 1;
    }

    if (encode) {
        if (!input || !text || !password || !output) {
            fprintf(stderr, "Error: Encode mode requires --input, --text, --password, and --output.\n");
            print_usage(argv[0]);
            return 1;
        }
        return encode_mode(input, text, password, output, delete_flag);
    } else if (decode) {
        if (!input || !password) {
            fprintf(stderr, "Error: Decode mode requires --input and --password.\n");
            print_usage(argv[0]);
            return 1;
        }
        return decode_mode(input, password, output);
    } else {
        fprintf(stderr, "Error: Must specify either encode (-e) or decode (-d) mode.\n");
        print_usage(argv[0]);
        return 1;
    }
}

/* encode_mode:
 * - Reads the cover JPEG.
 * - Determines if secret_arg is a file or literal text.
 * - Encrypts the payload (with a header that includes ciphertext bit-length, IV, and salt).
 * - Embeds the payload into the JPEG.
 * - Optionally deletes the original cover image.
 */
int encode_mode(const char *cover_path, const char *secret_arg, const char *password, const char *output_path, int delete_flag) {
    int ret = 0;
    uint8_t *secret_data = NULL;
    long secret_len = 0;
    char *payload_string = NULL;
    int payload_string_len = 0;

    if (file_exists(secret_arg)) {
        if (read_file(secret_arg, &secret_data, &secret_len) != 0) {
            fprintf(stderr, "Error: Failed to read secret file '%s'.\n", secret_arg);
            return -1;
        }
        const char *filename = strrchr(secret_arg, '/');
        if (!filename) filename = secret_arg; else filename++;
        payload_string_len = strlen(filename) + 1 + secret_len;
        payload_string = malloc(payload_string_len + 1);
        if (!payload_string) { free(secret_data); return -1; }
        snprintf(payload_string, payload_string_len + 1, "%s/", filename);
        memcpy(payload_string + strlen(filename) + 1, secret_data, secret_len);
        free(secret_data);
    } else {
        payload_string_len = 1 + strlen(secret_arg);
        payload_string = malloc(payload_string_len + 1);
        if (!payload_string) return -1;
        snprintf(payload_string, payload_string_len + 1, "/%s", secret_arg);
    }

    /* Encrypt the payload.
     * Generate random salt and IV.
     */
    uint8_t salt[SALT_LEN], iv[IV_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1) {
        fprintf(stderr, "Error: Failed to generate random salt/IV.\n");
        free(payload_string);
        return -1;
    }

    uint8_t key[KEY_LEN];
    if (derive_key(password, salt, key) != 0) {
        fprintf(stderr, "Error: Key derivation failed.\n");
        free(payload_string);
        return -1;
    }

    uint8_t *encrypted = NULL;
    int encrypted_len = 0;
    if (encrypt_data((uint8_t *)payload_string, payload_string_len, key, iv, &encrypted, &encrypted_len) != 0) {
        fprintf(stderr, "Error: Encryption failed.\n");
        free(payload_string);
        return -1;
    }
    free(payload_string);

    /* Call the new embed function:
       Pass the encrypted payload (ciphertext), its length, plus the IV and salt.
    */
    ret = embed_stego_payload_in_jpeg(cover_path, encrypted, encrypted_len, iv, salt, output_path);
    free(encrypted);
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to embed stego payload into JPEG.\n");
        return -1;
    }

    printf("Data encoded successfully into '%s'.\n", output_path);
    if (delete_flag) {
        if (remove(cover_path) == 0)
            printf("Original cover image '%s' deleted.\n", cover_path);
        else
            fprintf(stderr, "Warning: Failed to delete original cover image '%s'.\n", cover_path);
    }
    return 0;
}

/* decode_mode:
 * - Reads the stego JPEG.
 * - Extracts the payload from the DCT coefficients.
 * - Parses the header to retrieve ciphertext bit-length, IV, and salt.
 * - Derives the key and decrypts the payload.
 * - If the payload starts with '/', it is treated as text; otherwise, it's assumed to include a filename.
 */
int decode_mode(const char *stego_path, const char *password, const char *output_path) {
    uint8_t *stego_payload = NULL;
    int stego_payload_len = 0;
    if (extract_stego_payload_from_jpeg(stego_path, &stego_payload, &stego_payload_len) != 0) {
        fprintf(stderr, "Error: Failed to extract stego payload from JPEG '%s'.\n", stego_path);
        return -1;
    }
    if (stego_payload_len < HEADER_SIZE) {
        fprintf(stderr, "Error: Stego payload too short.\n");
        free(stego_payload);
        return -1;
    }

    uint32_t payload_bit_length = stego_payload[0] | (stego_payload[1] << 8) | (stego_payload[2] << 16) | (stego_payload[3] << 24);
    int expected_encrypted_len = payload_bit_length / 8;
    uint8_t iv[IV_LEN], salt[SALT_LEN];
    memcpy(iv, stego_payload + 4, IV_LEN);
    memcpy(salt, stego_payload + 4 + IV_LEN, SALT_LEN);
    uint8_t *encrypted = stego_payload + HEADER_SIZE;
    int encrypted_len = stego_payload_len - HEADER_SIZE;
    if (encrypted_len != expected_encrypted_len)
        fprintf(stderr, "Warning: Encrypted payload length (%d bytes) does not match header expectation (%d bytes).\n", encrypted_len, expected_encrypted_len);

    uint8_t key[KEY_LEN];
    if (derive_key(password, salt, key) != 0) {
        fprintf(stderr, "Error: Key derivation failed.\n");
        free(stego_payload);
        return -1;
    }

    uint8_t *decrypted = NULL;
    int decrypted_len = 0;
    if (decrypt_data(encrypted, encrypted_len, key, iv, &decrypted, &decrypted_len) != 0) {
        fprintf(stderr, "Error: Decryption failed.\n");
        free(stego_payload);
        return -1;
    }
    free(stego_payload);

    if (decrypted_len < 1) {
        fprintf(stderr, "Error: Decrypted data is empty.\n");
        free(decrypted);
        return -1;
    }
    if (decrypted[0] == '/') {
        char *secret_text = (char *)decrypted + 1;
        if (output_path) {
            if (write_file(output_path, (uint8_t *)secret_text, decrypted_len - 1) != 0) {
                fprintf(stderr, "Error: Failed to write output file '%s'.\n", output_path);
                free(decrypted);
                return -1;
            }
            printf("Secret text extracted to '%s'.\n", output_path);
        } else {
            printf("Extracted secret text:\n%s\n", secret_text);
        }
    } else {
        char *sep = memchr(decrypted, '/', decrypted_len);
        if (!sep) {
            fprintf(stderr, "Error: Invalid payload format.\n");
            free(decrypted);
            return -1;
        }
        int fname_len = sep - (char *)decrypted;
        char filename[256];
        if (fname_len >= 256) fname_len = 255;
        memcpy(filename, decrypted, fname_len);
        filename[fname_len] = '\0';
        char *secret_data = sep + 1;
        int secret_data_len = decrypted_len - fname_len - 1;
        if (output_path) {
            if (write_file(output_path, (uint8_t *)secret_data, secret_data_len) != 0) {
                fprintf(stderr, "Error: Failed to write output file '%s'.\n", output_path);
                free(decrypted);
                return -1;
            }
            printf("Secret extracted to '%s'.\n", output_path);
        } else {
            if (write_file(filename, (uint8_t *)secret_data, secret_data_len) != 0) {
                fprintf(stderr, "Error: Failed to write output file '%s'.\n", filename);
                free(decrypted);
                return -1;
            }
            printf("Secret extracted to '%s'.\n", filename);
        }
    }
    free(decrypted);
    return 0;
}
