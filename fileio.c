#include "fileio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

int read_file(const char *path, uint8_t **data, long *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return -1; }
    rewind(f);
    *data = malloc(size);
    if (!*data) { fclose(f); return -1; }
    if (fread(*data, 1, size, f) != (size_t)size) { 
        free(*data); 
        fclose(f); 
        return -1; 
    }
    fclose(f);
    *len = size;
    return 0;
}

int write_file(const char *path, const uint8_t *data, long len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(data, 1, len, f) != (size_t)len) { 
        fclose(f); 
        return -1; 
    }
    fclose(f);
    return 0;
}
