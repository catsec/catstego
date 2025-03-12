#ifndef STEGO_H
#define STEGO_H

#include <stdint.h>

int embed_stego_payload_in_jpeg(const char *jpeg_in_path,
                                  const uint8_t *ciphertext,
                                  int ciphertext_len,
                                  const uint8_t *iv,      /* 16 bytes */
                                  const uint8_t *salt,    /* 16 bytes */
                                  const char *jpeg_out_path);

int extract_stego_payload_from_jpeg(const char *jpeg_in_path,
                                    uint8_t **payload_out,
                                    int *payload_out_len);

#endif // STEGO_H
