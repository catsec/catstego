#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stego.h"

static void print_usage(const char *progname) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s encode <cover.jpg> <text_or_secret_file> <password> <output.jpg> [--delete|-D]\n", progname);
}

int main(int argc, char **argv) {
    if (argc < 6) {
        print_usage(argv[0]);
        return 1;
    }

    /* Positional parameters:
       argv[1] should be "encode" (we assume that since this is in encode.c)
       argv[2] : cover image path
       argv[3] : secret text (or secret file name)
       argv[4] : password
       argv[5] : output image path
       argv[6] (optional): "--delete" or "-D" flag
    */
    const char *cover_path = argv[2];
    const char *data_arg = argv[3];
    const char *password = argv[4];
    const char *output_path = argv[5];
    int delete_flag = 0;
    if (argc > 6) {
        if ((strcmp(argv[6], "--delete") == 0) || (strcmp(argv[6], "-D") == 0))
            delete_flag = 1;
    }

    int ret = encode_mode(cover_path, data_arg, password, output_path, delete_flag);
    return ret;
}