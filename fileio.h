#ifndef FILEIO_H
#define FILEIO_H

#include <stdint.h>

/*
 * file_exists
 * Returns 1 if file exists, 0 otherwise.
 */
int file_exists(const char *path);

/*
 * read_file
 * Reads entire file at path into a dynamically allocated buffer.
 * On success, *data is allocated (caller must free) and *len is set.
 * Returns 0 on success, nonzero on failure.
 */
int read_file(const char *path, uint8_t **data, long *len);

/*
 * write_file
 * Writes data (of length len) to file at path.
 * Returns 0 on success, nonzero on failure.
 */
int write_file(const char *path, const uint8_t *data, long len);

#endif  /* FILEIO_H */
