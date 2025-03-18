#ifndef STEGO_H
#define STEGO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * embed_payload_in_jpeg_memory:
 *   Embeds an already–encrypted payload into a JPEG image (in memory).
 *   Parameters:
 *     payload       : pointer to encrypted payload.
 *     payload_len   : length (in bytes) of the payload.
 *     iv            : pointer to a 16-byte IV.
 *     salt          : pointer to a 16-byte salt.
 *     jpeg_in_data  : pointer to input JPEG data in memory.
 *     jpeg_in_size  : size (in bytes) of the input JPEG.
 *     jpeg_out_data : pointer to output buffer (allocated within).
 *     jpeg_out_size : pointer to the size (in bytes) of the output JPEG.
 *     error         : caller–provided buffer for error messages (UTF-8).
 *     error_buf_size: size of the error buffer.
 *   Returns 0 on success, -1 on error.
 */
int embed_payload_in_jpeg_memory(const uint8_t *payload, int payload_len,
                                   const uint8_t *iv, const uint8_t *salt,
                                   const uint8_t *jpeg_in_data, long jpeg_in_size,
                                   uint8_t **jpeg_out_data, long *jpeg_out_size,
                                   char *error, int error_buf_size);

/*
 * extract_payload_from_jpeg_memory:
 *   Extracts an embedded payload from a JPEG image (in memory).
 *   Parameters:
 *     jpeg_data    : pointer to JPEG data in memory.
 *     jpeg_size    : size (in bytes) of the JPEG data.
 *     payload_out     : pointer to output payload (allocated within).
 *     payload_out_len : pointer to length (in bytes) of the output payload.
 *     iv_out          : 16-byte buffer (provided by caller) for extracted IV.
 *     salt_out        : 16-byte buffer (provided by caller) for extracted salt.
 *     error         : caller–provided buffer for error messages (UTF-8).
 *     error_buf_size: size of the error buffer.
 *   Returns 0 on success, -1 on error.
 */
int extract_payload_from_jpeg_memory(const uint8_t *jpeg_data, long jpeg_size,
                                      uint8_t **payload_out, int *payload_out_len,
                                      uint8_t *iv_out, uint8_t *salt_out,
                                      char *error, int error_buf_size);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_H */
