#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Function to encode IPv4 address to base64
char* base64_encode(const unsigned char* input, int length) {
    BIO* bmem, * b64;
    BUF_MEM* bptr;
    char* buffer;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buffer = (char*)malloc(bptr->length + 1);
    memcpy(buffer, bptr->data, bptr->length);
    buffer[bptr->length] = 0;

    BIO_free_all(b64);
    return buffer;
}

// Function to obfuscate IPv4 address
char* obfuscate_ipv4(const char* ipv4_str) {
    struct in_addr ipv4_addr;
    unsigned char* bytes;
    char* encoded;

    if (inet_pton(AF_INET, ipv4_str, &ipv4_addr) != 1) {
        return NULL;
    }

    bytes = (unsigned char*)&ipv4_addr;
    encoded = base64_encode(bytes, sizeof(ipv4_addr));

    return encoded;
}

int main() {
    char* ipv4_str = "192.168.1.1";
    char* encoded = obfuscate_ipv4(ipv4_str);

    if (encoded) {
        printf("Obfuscated IPv4: %s\n", encoded);
        free(encoded);
    }
    else {
        printf("Error obfuscating IPv4 address.\n");
    }

    return 0;
}
