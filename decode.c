#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stego.h"  // This header declares decode_mode()

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s decode <stego.jpg> <password> [output_file]\n", progname);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    /* Positional parameters:
       argv[1] should be "decode" (we assume that because this is decode.c)
       argv[2] : stego image path
       argv[3] : password
       argv[4] (optional): output file path
    */
    const char *stego_path = argv[2];
    const char *password = argv[3];
    const char *output_path = (argc > 4) ? argv[4] : NULL;

    int ret = decode_mode(stego_path, password, output_path);
    return ret;
}
