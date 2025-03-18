/* stego.c – Library functions for embedding/extracting a stego payload in JPEG data.
   This file has no dependencies other than jpeglib and standard C libraries.
   It performs only the JPEG embedding and extracting.
   Encryption, password/key derivation, file reading, and user argument parsing are done in catstego.c.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <jpeglib.h>
#include <jerror.h>
#include "stego.h"

#define HEADER_SIZE 36  // 4-byte payload bit-length, 16-byte IV, 16-byte salt

/* --- Helper Functions --- */

/* is_candidate:
   Returns true if a DCT coefficient is suitable for embedding (based on (abs(coefficient) & 0x7C)).
*/
static inline int is_candidate(int coeff) {
    return ((abs(coeff) & 0x7C) > 0);
}

/* embed_bit:
   Embeds a single bit into a coefficient's least-significant bit.
   If the modified coefficient would not satisfy the candidate condition, a safe default is used.
*/
static int embed_bit(int coeff, int bit) {
    int sign = (coeff < 0) ? -1 : 1;
    int abs_val = abs(coeff);
    int new_abs = (abs_val & ~1) | bit;
    if ((new_abs & 0x7C) == 0) {
        new_abs = (bit == 0 ? 2 : 3);
    }
    return sign * new_abs;
}

/* bytes_to_bits:
   Converts an array of bytes to an array of bits (MSB first).
*/
static void bytes_to_bits(const uint8_t *data, int data_len, uint8_t **bits, int *bits_len) {
    int total = data_len * 8;
    *bits = malloc(total);
    if (!*bits) {
        *bits_len = 0;
        return;
    }
    for (int i = 0; i < data_len; i++) {
        for (int j = 0; j < 8; j++) {
            (*bits)[i * 8 + j] = (data[i] >> (7 - j)) & 1;
        }
    }
    *bits_len = total;
}

/* bits_to_bytes:
   Converts an array of bits (MSB first) back to bytes.
*/
static void bits_to_bytes(const uint8_t *bits, int bits_len, uint8_t **data, int *data_len) {
    int len = bits_len / 8;
    *data = malloc(len);
    if (!*data) {
        *data_len = 0;
        return;
    }
    for (int i = 0; i < len; i++) {
        uint8_t byte = 0;
        for (int j = 0; j < 8; j++) {
            byte = (byte << 1) | bits[i * 8 + j];
        }
        (*data)[i] = byte;
    }
    *data_len = len;
}

/* final_candidate_count:
   Decrements candidate_count until it is not divisible by 251. This guarantees 251 is coprime with the final count.
*/
static int final_candidate_count(int candidate_count) {
    int final_count = candidate_count;
    while (final_count > 0 && (final_count % 251) == 0) {
        final_count--;
    }
    return final_count;
}

/* --- Library Functions --- */

/*
 * embed_payload_in_jpeg_memory:
 *   Inputs:
 *     payload       : pointer to the already–encrypted payload (ciphertext)
 *     payload_len   : length (in bytes) of the payload
 *     iv            : pointer to a 16-byte IV
 *     salt          : pointer to a 16-byte salt
 *     jpeg_in_data  : pointer to JPEG file data in memory
 *     jpeg_in_size  : size (in bytes) of the JPEG data
 *     error         : caller‑provided buffer for error messages (UTF‑8)
 *     error_buf_size: size of the error buffer
 *   Outputs:
 *     jpeg_out_data : pointer (allocated within) to the modified JPEG data with the embedded payload
 *     jpeg_out_size : size (in bytes) of the modified JPEG data
 *   Returns 0 on success, -1 on error.
 */
int embed_payload_in_jpeg_memory(const uint8_t *payload, int payload_len,
                                   const uint8_t *iv, const uint8_t *salt,
                                   const uint8_t *jpeg_in_data, long jpeg_in_size,
                                   uint8_t **jpeg_out_data, long *jpeg_out_size,
                                   char *error, int error_buf_size)
{
    /* Build stego_payload = header || payload.
       The header consists of:
         - 4 bytes: payload bit-length (little-endian)
         - 16 bytes: IV
         - 16 bytes: salt
    */
    int stego_payload_len = HEADER_SIZE + payload_len;
    uint8_t *stego_payload = malloc(stego_payload_len);
    if (!stego_payload) {
        if (error) snprintf(error, error_buf_size, "Memory allocation for stego payload failed.");
        return -1;
    }
    uint32_t payload_bit_length = payload_len * 8;
    stego_payload[0] = payload_bit_length & 0xFF;
    stego_payload[1] = (payload_bit_length >> 8) & 0xFF;
    stego_payload[2] = (payload_bit_length >> 16) & 0xFF;
    stego_payload[3] = (payload_bit_length >> 24) & 0xFF;
    memcpy(stego_payload + 4, iv, 16);
    memcpy(stego_payload + 20, salt, 16);
    memcpy(stego_payload + HEADER_SIZE, payload, payload_len);
    
    /* Convert the full stego_payload into a bit stream */
    uint8_t *payload_bits = NULL;
    int payload_bits_len = 0;
    bytes_to_bits(stego_payload, stego_payload_len, &payload_bits, &payload_bits_len);
    free(stego_payload);
    if (payload_bits_len == 0) {
        if (error) snprintf(error, error_buf_size, "Conversion of stego payload to bits failed.");
        return -1;
    }
    
    /* Decompress the JPEG from memory */
    struct jpeg_decompress_struct dinfo;
    struct jpeg_error_mgr jerr;
    dinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&dinfo);
    jpeg_mem_src(&dinfo, (unsigned char *)jpeg_in_data, jpeg_in_size);
    if (jpeg_read_header(&dinfo, TRUE) != JPEG_HEADER_OK) {
        if (error) snprintf(error, error_buf_size, "Failed to read JPEG header.");
        jpeg_destroy_decompress(&dinfo);
        free(payload_bits);
        return -1;
    }
    jvirt_barray_ptr *coef_arrays = jpeg_read_coefficients(&dinfo);
    if (!coef_arrays) {
        if (error) snprintf(error, error_buf_size, "Failed to read JPEG coefficients.");
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(payload_bits);
        return -1;
    }
    
    /* Build candidate list from DCT coefficients */
    int candidate_count = 0;
    for (int comp = 0; comp < dinfo.num_components; comp++) {
        jpeg_component_info *comp_info = &dinfo.comp_info[comp];
        int w = comp_info->width_in_blocks, h = comp_info->height_in_blocks;
        for (int row = 0; row < h; row++) {
            JBLOCKARRAY buffer = (*dinfo.mem->access_virt_barray)
                ((j_common_ptr)&dinfo, coef_arrays[comp], row, 1, TRUE);
            JBLOCKROW row_ptr = buffer[0];
            for (int col = 0; col < w; col++) {
                JCOEF *block = row_ptr[col];
                for (int i = 1; i < DCTSIZE2; i++) {
                    if (is_candidate(block[i]))
                        candidate_count++;
                }
            }
        }
    }
    int final_count = final_candidate_count(candidate_count);
    if (final_count < payload_bits_len) {
        if (error) snprintf(error, error_buf_size, "Not enough candidate coefficients (%d) to embed %d bits.", final_count, payload_bits_len);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(payload_bits);
        return -1;
    }
    
    JCOEF **candidates = malloc(candidate_count * sizeof(JCOEF *));
    if (!candidates) {
        if (error) snprintf(error, error_buf_size, "Memory allocation for candidate list failed.");
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(payload_bits);
        return -1;
    }
    int idx = 0;
    for (int comp = 0; comp < dinfo.num_components; comp++) {
        jpeg_component_info *comp_info = &dinfo.comp_info[comp];
        int w = comp_info->width_in_blocks, h = comp_info->height_in_blocks;
        for (int row = 0; row < h; row++) {
            JBLOCKARRAY buffer = (*dinfo.mem->access_virt_barray)
                ((j_common_ptr)&dinfo, coef_arrays[comp], row, 1, TRUE);
            JBLOCKROW row_ptr = buffer[0];
            for (int col = 0; col < w; col++) {
                JCOEF *block = row_ptr[col];
                for (int i = 1; i < DCTSIZE2; i++) {
                    if (is_candidate(block[i]))
                        candidates[idx++] = &block[i];
                }
            }
        }
    }
    if (idx != candidate_count) {
        if (error) snprintf(error, error_buf_size, "Candidate count mismatch: expected %d, got %d", candidate_count, idx);
        free(candidates);
        free(payload_bits);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    
    /* Embed each payload bit into the candidate coefficients */
    for (int j = 0; j < payload_bits_len; j++) {
        int pos = (j * 251) % final_count;
        *candidates[pos] = embed_bit(*candidates[pos], payload_bits[j]);
    }
    free(payload_bits);
    
    /* Compress the modified JPEG to memory */
    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr cjerr;
    cinfo.err = jpeg_std_error(&cjerr);
    jpeg_create_compress(&cinfo);
    unsigned char *outbuffer = NULL;
    unsigned long outsize = 0;
    jpeg_mem_dest(&cinfo, &outbuffer, &outsize);
    jpeg_copy_critical_parameters(&dinfo, &cinfo);
    jpeg_write_coefficients(&cinfo, coef_arrays);
    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
    
    /* Set output data */
    *jpeg_out_data = malloc(outsize);
    if (!*jpeg_out_data) {
        if (error) snprintf(error, error_buf_size, "Memory allocation for output JPEG failed.");
        free(candidates);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(outbuffer);
        return -1;
    }
    memcpy(*jpeg_out_data, outbuffer, outsize);
    *jpeg_out_size = outsize;
    free(outbuffer);
    
    jpeg_finish_decompress(&dinfo);
    jpeg_destroy_decompress(&dinfo);
    free(candidates);
    return 0;
}

/*
 * extract_payload_from_jpeg_memory:
 *   Inputs:
 *     jpeg_data    : pointer to JPEG file data in memory (with embedded payload)
 *     jpeg_size    : size (in bytes) of the JPEG data
 *     error        : caller‑provided buffer for error messages (UTF‑8)
 *     error_buf_size: size of the error buffer
 *   Outputs:
 *     payload_out     : pointer (allocated within) to the extracted payload (still encrypted)
 *     payload_out_len : length (in bytes) of the extracted payload
 *     iv_out          : a 16-byte buffer (provided by the caller) where the extracted IV is stored
 *     salt_out        : a 16-byte buffer (provided by the caller) where the extracted salt is stored
 *   Returns 0 on success, -1 on error.
 */
int extract_payload_from_jpeg_memory(const uint8_t *jpeg_data, long jpeg_size,
                                      uint8_t **payload_out, int *payload_out_len,
                                      uint8_t *iv_out, uint8_t *salt_out,
                                      char *error, int error_buf_size)
{
    struct jpeg_decompress_struct dinfo;
    struct jpeg_error_mgr jerr;
    dinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&dinfo);
    jpeg_mem_src(&dinfo, (unsigned char *)jpeg_data, jpeg_size);
    if (jpeg_read_header(&dinfo, TRUE) != JPEG_HEADER_OK) {
        if (error) snprintf(error, error_buf_size, "Failed to read JPEG header.");
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    jvirt_barray_ptr *coef_arrays = jpeg_read_coefficients(&dinfo);
    if (!coef_arrays) {
        if (error) snprintf(error, error_buf_size, "Failed to read JPEG coefficients.");
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    
    /* Build candidate list from DCT coefficients */
    int candidate_count = 0;
    for (int comp = 0; comp < dinfo.num_components; comp++) {
        jpeg_component_info *comp_info = &dinfo.comp_info[comp];
        int w = comp_info->width_in_blocks, h = comp_info->height_in_blocks;
        for (int row = 0; row < h; row++) {
            JBLOCKARRAY buffer = (*dinfo.mem->access_virt_barray)
              ((j_common_ptr)&dinfo, coef_arrays[comp], row, 1, TRUE);
            JBLOCKROW row_ptr = buffer[0];
            for (int col = 0; col < w; col++) {
                JCOEF *block = row_ptr[col];
                for (int i = 1; i < DCTSIZE2; i++) {
                    if (is_candidate(block[i]))
                        candidate_count++;
                }
            }
        }
    }
    
    JCOEF **candidates = malloc(candidate_count * sizeof(JCOEF *));
    if (!candidates) {
        if (error) snprintf(error, error_buf_size, "Memory allocation for candidate list failed.");
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    int idx = 0;
    for (int comp = 0; comp < dinfo.num_components; comp++) {
        jpeg_component_info *comp_info = &dinfo.comp_info[comp];
        int w = comp_info->width_in_blocks, h = comp_info->height_in_blocks;
        for (int row = 0; row < h; row++) {
            JBLOCKARRAY buffer = (*dinfo.mem->access_virt_barray)
              ((j_common_ptr)&dinfo, coef_arrays[comp], row, 1, TRUE);
            JBLOCKROW row_ptr = buffer[0];
            for (int col = 0; col < w; col++) {
                JCOEF *block = row_ptr[col];
                for (int i = 1; i < DCTSIZE2; i++) {
                    if (is_candidate(block[i]))
                        candidates[idx++] = &block[i];
                }
            }
        }
    }
    if (idx != candidate_count) {
        if (error) snprintf(error, error_buf_size, "Candidate count mismatch in extraction: expected %d, got %d", candidate_count, idx);
        free(candidates);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    
    int final_count = final_candidate_count(candidate_count);
    
    /* Extract header bits (first 32 bits) */
    int header_bits_extracted = 32;
    uint8_t *header_bits_array = malloc(header_bits_extracted);
    if (!header_bits_array) {
        if (error) snprintf(error, error_buf_size, "Memory allocation for header bits failed.");
        free(candidates);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    for (int j = 0; j < header_bits_extracted; j++) {
        int pos = (j * 251) % final_count;
        header_bits_array[j] = *candidates[pos] & 1;
    }
    uint8_t *header_bytes = NULL;
    int header_bytes_len = 0;
    bits_to_bytes(header_bits_array, header_bits_extracted, &header_bytes, &header_bytes_len);
    free(header_bits_array);
    if (header_bytes_len != 4) {
        if (error) snprintf(error, error_buf_size, "Header conversion failed. Expected 4 bytes, got %d bytes.", header_bytes_len);
        free(candidates);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(header_bytes);
        return -1;
    }
    uint32_t payload_bit_length = header_bytes[0] |
        (header_bytes[1] << 8) | (header_bytes[2] << 16) | (header_bytes[3] << 24);
    
    int total_payload_bits = (HEADER_SIZE * 8) + payload_bit_length;
    uint8_t *payload_bits_array = malloc(total_payload_bits);
    if (!payload_bits_array) {
        if (error) snprintf(error, error_buf_size, "Memory allocation for payload bits failed.");
        free(candidates);
        free(header_bytes);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    for (int j = 0; j < total_payload_bits; j++) {
        int pos = (j * 251) % final_count;
        payload_bits_array[j] = *candidates[pos] & 1;
    }
    uint8_t *full_extracted = NULL;
    int full_extracted_len = 0;
    bits_to_bytes(payload_bits_array, total_payload_bits, &full_extracted, &full_extracted_len);
    free(payload_bits_array);
    
    if (full_extracted_len < HEADER_SIZE) {
        if (error) snprintf(error, error_buf_size, "Extracted data too short.");
        free(candidates);
        free(header_bytes);
        free(full_extracted);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    
    /* Extract IV and salt from header */
    memcpy(iv_out, full_extracted + 4, 16);
    memcpy(salt_out, full_extracted + 20, 16);
    
    int extracted_payload_len = full_extracted_len - HEADER_SIZE;
    uint8_t *payload_data = malloc(extracted_payload_len);
    if (!payload_data) {
        if (error) snprintf(error, error_buf_size, "Memory allocation for payload output failed.");
        free(candidates);
        free(header_bytes);
        free(full_extracted);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        return -1;
    }
    memcpy(payload_data, full_extracted + HEADER_SIZE, extracted_payload_len);
    free(full_extracted);
    free(header_bytes);
    *payload_out = payload_data;
    *payload_out_len = extracted_payload_len;
    
    free(candidates);
    jpeg_finish_decompress(&dinfo);
    jpeg_destroy_decompress(&dinfo);
    return 0;
}
