#include "stego.h"
#include "fileio.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <jpeglib.h>
#include <jerror.h>
#include <math.h>

#define HEADER_SIZE 36  // 4-byte ciphertext bit-length, 16-byte IV, 16-byte salt

/* Candidate selection: a DCT coefficient is a candidate if (abs(coefficient) & 0x7C) > 0 */
static inline int is_candidate(int coeff) {
    return ((abs(coeff) & 0x7C) > 0);
}

/* embed_bit: embed a single bit into a coefficient by modifying its LSB.
   If the new value does not satisfy the candidate condition, a safe default is used.
*/
int embed_bit(int coeff, int bit) {
    int sign = (coeff < 0) ? -1 : 1;
    int abs_val = abs(coeff);
    int new_abs = (abs_val & ~1) | bit;
    if ((new_abs & 0x7C) == 0) {
        new_abs = (bit == 0 ? 2 : 3);
    }
    return sign * new_abs;
}

/* bytes_to_bits: converts an array of bytes to an array of bits (MSB first) */
void bytes_to_bits(const uint8_t *data, int data_len, uint8_t **bits, int *bits_len) {
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

/* bits_to_bytes: converts an array of bits (MSB first) back to bytes */
void bits_to_bytes(const uint8_t *bits, int bits_len, uint8_t **data, int *data_len) {
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
   Starting from candidate_count, decrement until the count is not divisible by 251.
   This ensures that 251 is coprime with the final candidate count.
*/
static int final_candidate_count(int candidate_count) {
    int final_count = candidate_count;
    while (final_count > 0 && (final_count % 251) == 0) {
        final_count--;
    }
    return final_count;
}

/*
 * embed_stego_payload_in_jpeg:
 *   - Builds stego_payload = header || ciphertext, where the header (36 bytes) is:
 *         Bytes 0–3: (ciphertext_len * 8) in little-endian,
 *         Bytes 4–19: IV,
 *         Bytes 20–35: salt.
 *   - Converts the payload to a bit stream.
 *   - Builds a candidate list from all DCT coefficients satisfying is_candidate().
 *   - Computes final_count = final_candidate_count(candidate_count) and checks capacity.
 *   - Embeds each payload bit at candidate index:
 *         pos = (j * 251) mod final_count
 *   - Writes out the modified JPEG.
 */
int embed_stego_payload_in_jpeg(const char *jpeg_in_path,
                                  const uint8_t *ciphertext,
                                  int ciphertext_len,
                                  const uint8_t *iv,
                                  const uint8_t *salt,
                                  const char *jpeg_out_path) {
    int stego_payload_len = HEADER_SIZE + ciphertext_len;
    uint8_t *stego_payload = malloc(stego_payload_len);
    if (!stego_payload) {
        fprintf(stderr, "Error: Unable to allocate stego payload.\n");
        return -1;
    }
    uint32_t payload_bit_length = ciphertext_len * 8;
    stego_payload[0] = payload_bit_length & 0xFF;
    stego_payload[1] = (payload_bit_length >> 8) & 0xFF;
    stego_payload[2] = (payload_bit_length >> 16) & 0xFF;
    stego_payload[3] = (payload_bit_length >> 24) & 0xFF;
    memcpy(stego_payload + 4, iv, 16);
    memcpy(stego_payload + 20, salt, 16);
    memcpy(stego_payload + HEADER_SIZE, ciphertext, ciphertext_len);
    
    uint8_t *payload_bits = NULL;
    int payload_bits_len = 0;
    bytes_to_bits(stego_payload, stego_payload_len, &payload_bits, &payload_bits_len);
    free(stego_payload);
    
    struct jpeg_decompress_struct dinfo;
    struct jpeg_error_mgr jerr;
    uint8_t *jpeg_in_data = NULL;
    long jpeg_in_size = 0;
    int ret = 0;
    
    if (read_file(jpeg_in_path, &jpeg_in_data, &jpeg_in_size) != 0) {
        fprintf(stderr, "Error: Failed to read input JPEG file '%s'.\n", jpeg_in_path);
        free(payload_bits);
        return -1;
    }
    
    dinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&dinfo);
    jpeg_mem_src(&dinfo, jpeg_in_data, jpeg_in_size);
    if (jpeg_read_header(&dinfo, TRUE) != JPEG_HEADER_OK) {
        fprintf(stderr, "Error: Failed to read JPEG header from '%s'.\n", jpeg_in_path);
        ret = -1;
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        free(payload_bits);
        return ret;
    }
    
    jvirt_barray_ptr *coef_arrays = jpeg_read_coefficients(&dinfo);
    if (!coef_arrays) {
        fprintf(stderr, "Error: Could not read coefficient arrays.\n");
        ret = -1;
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        free(payload_bits);
        return ret;
    }
    
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
        fprintf(stderr, "Error: Not enough candidate coefficients (%d) to embed %d bits.\n", final_count, payload_bits_len);
        ret = -1;
        free(payload_bits);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
    }
    
    JCOEF **candidates = malloc(candidate_count * sizeof(JCOEF *));
    if (!candidates) {
        ret = -1;
        free(payload_bits);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
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
        fprintf(stderr, "Error: Candidate count mismatch: %d vs %d\n", candidate_count, idx);
        ret = -1;
        free(candidates);
        free(payload_bits);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
    }
    
    for (int j = 0; j < payload_bits_len; j++) {
        int pos = (j * 251) % final_count;
        *candidates[pos] = embed_bit(*candidates[pos], payload_bits[j]);
    }
    free(payload_bits);
    
    {
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
        if (write_file(jpeg_out_path, outbuffer, outsize) != 0) {
            fprintf(stderr, "Error: Failed to write output JPEG file '%s'.\n", jpeg_out_path);
            ret = -1;
        }
        free(outbuffer);
    }
    
    jpeg_finish_decompress(&dinfo);
    jpeg_destroy_decompress(&dinfo);
    free(candidates);
    free(jpeg_in_data);
    return ret;
}

/*
 * extract_stego_payload_from_jpeg:
 *   - Rebuild the candidate list using the same candidate test.
 *   - Compute final_count = final_candidate_count(candidate_count).
 *   - Recover the payload bits by reading:
 *         pos = (j * 251) mod final_count
 *     for j from 0 to total_payload_bits-1.
 *   - First, extract the first 32 bits (4 bytes) to get ciphertext bit-length.
 *   - Then, extract total_payload_bits = (HEADER_SIZE*8 + ciphertext_bit_length) bits.
 *   - Convert the recovered bit stream back to bytes.
 */
int extract_stego_payload_from_jpeg(const char *jpeg_in_path, uint8_t **payload_out, int *payload_out_len) {
    struct jpeg_decompress_struct dinfo;
    struct jpeg_error_mgr jerr;
    uint8_t *jpeg_in_data = NULL;
    long jpeg_in_size = 0;
    int ret = 0;
    
    if (read_file(jpeg_in_path, &jpeg_in_data, &jpeg_in_size) != 0) {
        fprintf(stderr, "Error: Failed to read input JPEG file '%s'.\n", jpeg_in_path);
        return -1;
    }
    
    dinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&dinfo);
    jpeg_mem_src(&dinfo, jpeg_in_data, jpeg_in_size);
    if (jpeg_read_header(&dinfo, TRUE) != JPEG_HEADER_OK) {
        fprintf(stderr, "Error: Failed to read JPEG header from '%s'.\n", jpeg_in_path);
        ret = -1;
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
    }
    jvirt_barray_ptr *coef_arrays = jpeg_read_coefficients(&dinfo);
    if (!coef_arrays) {
        fprintf(stderr, "Error: Could not read coefficient arrays.\n");
        ret = -1;
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
    }
    
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
        ret = -1;
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
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
        fprintf(stderr, "Error: Candidate count mismatch in extraction: %d vs %d\n", candidate_count, idx);
        ret = -1;
        free(candidates);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
    }
    
    int final_count = final_candidate_count(candidate_count);
    
    int header_bits_extracted = 32;
    uint8_t *header_bits_array = malloc(header_bits_extracted);
    if (!header_bits_array) {
        ret = -1;
        free(candidates);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
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
        fprintf(stderr, "Error: Header conversion failed. Expected 4 bytes, got %d bytes.\n", header_bytes_len);
        ret = -1;
        free(candidates);
        free(jpeg_in_data);
        free(header_bytes);
        return ret;
    }
    uint32_t payload_bit_length = header_bytes[0] |
        (header_bytes[1] << 8) | (header_bytes[2] << 16) | (header_bytes[3] << 24);
    printf("Extraction Debug: Payload bit length (from header): %u\n", payload_bit_length);
    
    int total_payload_bits = (HEADER_SIZE * 8) + payload_bit_length;
    uint8_t *payload_bits_array = malloc(total_payload_bits);
    if (!payload_bits_array) {
        ret = -1;
        free(candidates);
        free(header_bytes);
        jpeg_finish_decompress(&dinfo);
        jpeg_destroy_decompress(&dinfo);
        free(jpeg_in_data);
        return ret;
    }
    for (int j = 0; j < total_payload_bits; j++) {
        int pos = (j * 251) % final_count;
        payload_bits_array[j] = *candidates[pos] & 1;
    }
    uint8_t *full_extracted = NULL;
    int full_extracted_len = 0;
    bits_to_bytes(payload_bits_array, total_payload_bits, &full_extracted, &full_extracted_len);
    free(payload_bits_array);
    
    printf("Extraction Debug: Full extracted payload length: %d bytes\n", full_extracted_len);
    int extracted_ciphertext_len = full_extracted_len - HEADER_SIZE;
    if (extracted_ciphertext_len != (int)(payload_bit_length / 8)) {
        fprintf(stderr, "Warning: Encrypted payload length (%d bytes) does not match header expectation (%d bytes).\n",
                extracted_ciphertext_len, payload_bit_length / 8);
        full_extracted_len = HEADER_SIZE + (payload_bit_length / 8);
    }
    
    *payload_out = full_extracted;
    *payload_out_len = full_extracted_len;
    
    free(candidates);
    free(header_bytes);
    
    jpeg_finish_decompress(&dinfo);
    jpeg_destroy_decompress(&dinfo);
    free(jpeg_in_data);
    return ret;
}
