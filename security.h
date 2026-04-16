#ifndef SECURITY_H
#define SECURITY_H

#define AES_KEY_SIZE 16

extern unsigned char aes_key[AES_KEY_SIZE];

void aes_encrypt(unsigned char *plaintext, int len, unsigned char *ciphertext);
void aes_decrypt(unsigned char *ciphertext, int len, unsigned char *plaintext);

int authenticate_user(const char *username, const char *password, char *role);
int has_permission(const char *role, const char *command);

#endif