#!/bin/bash
set -e

# This script sets up the external dependencies by cloning the repositories.
# It creates an "external" folder and clones Argon2, libjpeg-turbo, and OpenSSL.

# Define the external directory.
EXTERNAL_DIR="external"

# Create the external directory if it does not exist.
if [ ! -d "$EXTERNAL_DIR" ]; then
    echo "Creating external directory..."
    mkdir "$EXTERNAL_DIR"
fi

##########################
# Clone Argon2
##########################
ARGON2_DIR="$EXTERNAL_DIR/argon2"
if [ ! -d "$ARGON2_DIR" ]; then
    echo "Cloning Argon2 repository..."
    git clone https://github.com/P-H-C/phc-winner-argon2.git "$ARGON2_DIR"
else
    echo "Argon2 repository already exists. Skipping clone."
fi

##########################
# Clone libjpeg-turbo
##########################
LIBJPEG_DIR="$EXTERNAL_DIR/libjpeg"
if [ ! -d "$LIBJPEG_DIR" ]; then
    echo "Cloning libjpeg-turbo repository..."
    git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git "$LIBJPEG_DIR"
else
    echo "libjpeg-turbo repository already exists. Skipping clone."
fi

##########################
# Clone OpenSSL
##########################
OPENSSL_DIR="$EXTERNAL_DIR/openssl"
if [ ! -d "$OPENSSL_DIR" ]; then
    echo "Cloning OpenSSL repository..."
    git clone https://github.com/openssl/openssl.git "$OPENSSL_DIR"
else
    echo "OpenSSL repository already exists. Skipping clone."
fi

echo "External libraries have been set up in the '$EXTERNAL_DIR' folder."
