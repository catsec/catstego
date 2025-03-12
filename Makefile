CC = gcc
SRC = catstego.c encryption.c fileio.c stego.c

# Targets for each architecture
TARGET_ARM64 = catstego_arm64
TARGET_X86_64 = catstego_x86_64

# Directories for external libraries
OPENSSL_ARM64 = ./external/build/arm64/openssl
ARGON2_ARM64  = ./external/build/arm64/argon2
LIBJPEG_ARM64 = ./external/build/arm64/libjpeg

OPENSSL_X86_64 = ./external/build/x86_64/openssl
ARGON2_X86_64  = ./external/build/x86_64/argon2
LIBJPEG_X86_64 = ./external/build/x86_64/libjpeg

# Include directories for each architecture
INCLUDES_ARM64 = -I$(OPENSSL_ARM64)/include -I$(ARGON2_ARM64)/include -I$(LIBJPEG_ARM64)/include
INCLUDES_X86_64 = -I$(OPENSSL_X86_64)/include -I$(ARGON2_X86_64)/include -I$(LIBJPEG_X86_64)/include

# Library directories for each architecture
LDFLAGS_ARM64 = -s -L$(OPENSSL_ARM64)/lib -L$(ARGON2_ARM64)/lib -L$(LIBJPEG_ARM64)/lib
LDFLAGS_X86_64 = -s -L$(OPENSSL_X86_64)/lib -L$(ARGON2_X86_64)/lib -L$(LIBJPEG_X86_64)/lib

# Libraries for each architecture
LIBS_ARM64 = $(LIBJPEG_ARM64)/lib/libjpeg.a $(OPENSSL_ARM64)/lib/libcrypto.a $(ARGON2_ARM64)/lib/libargon2.a
LIBS_X86_64 = $(LIBJPEG_X86_64)/lib/libjpeg.a $(OPENSSL_X86_64)/lib/libcrypto.a $(ARGON2_X86_64)/lib/libargon2.a

# Object files for each architecture
OBJ_ARM64 = $(SRC:.c=.arm64.o)
OBJ_X86_64 = $(SRC:.c=.x86_64.o)

CFLAGS = -O2 -Wall -std=c99

all: $(TARGET_ARM64) $(TARGET_X86_64)

$(TARGET_ARM64): $(OBJ_ARM64)
	$(CC) $(CFLAGS) $(INCLUDES_ARM64) -arch arm64 -o $(TARGET_ARM64) $(OBJ_ARM64) $(LDFLAGS_ARM64) $(LIBS_ARM64)
	strip $(TARGET_ARM64)

$(TARGET_X86_64): $(OBJ_X86_64)
	$(CC) $(CFLAGS) $(INCLUDES_X86_64) -arch x86_64 -o $(TARGET_X86_64) $(OBJ_X86_64) $(LDFLAGS_X86_64) $(LIBS_X86_64)
	strip $(TARGET_X86_64)

%.arm64.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES_ARM64) -arch arm64 -c $< -o $@

%.x86_64.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES_X86_64) -arch x86_64 -c $< -o $@

clean:
	rm -f $(OBJ_ARM64) $(OBJ_X86_64) $(TARGET_ARM64) $(TARGET_X86_64)
