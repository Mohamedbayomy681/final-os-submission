#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include "security.h"

unsigned char aes_key[AES_KEY_SIZE] = "1234567890123456";

void aes_encrypt(unsigned char *plaintext, int len, unsigned char *ciphertext)
{
    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);

    int padded_len = ((len + 15) / 16) * 16;

    for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE)
    {
        unsigned char block[AES_BLOCK_SIZE] = {0};
        memcpy(block, plaintext + i, AES_BLOCK_SIZE);
        AES_encrypt(block, ciphertext + i, &enc_key);
    }
}

void aes_decrypt(unsigned char *ciphertext, int len, unsigned char *plaintext)
{
    AES_KEY dec_key;
    AES_set_decrypt_key(aes_key, 128, &dec_key);

    for (int i = 0; i < len; i += AES_BLOCK_SIZE)
    {
        AES_decrypt(ciphertext + i, plaintext + i, &dec_key);
    }
}

int authenticate_user(const char *username, const char *password, char *role)
{
    FILE *file = fopen("users.txt", "r");
    if (!file) return 0;

    char u[100], p[100], r[50];

    while (fscanf(file, "%[^:]:%[^:]:%s\n", u, p, r) != EOF)
    {
        if (strcmp(username, u) == 0 && strcmp(password, p) == 0)
        {
            strcpy(role, r);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

int has_permission(const char *role, const char *cmd)
{
    if (strcmp(cmd, "ls") == 0 || strcmp(cmd, "cat") == 0)
        return 1;

    if (strcmp(role, "entry") == 0)
        return 0;

    if (strcmp(cmd, "cp") == 0 || strcmp(cmd, "edit") == 0)
        return strcmp(role, "medium") == 0 || strcmp(role, "top") == 0;

    if (strcmp(cmd, "rm") == 0)
        return strcmp(role, "top") == 0;

    return 0;
}