#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

int main()
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    char username[100], password[100], buffer[BUFFER_SIZE];

    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);

    sprintf(buffer, "%s:%s", username, password);
    send(sock, buffer, strlen(buffer), 0);

    int bytes = read(sock, buffer, BUFFER_SIZE);
    buffer[bytes] = '\0';

    if (strcmp(buffer, "AUTH_OK") != 0)
    {
        printf("Auth failed\n");
        return 0;
    }

    printf("Logged in!\n");

    while (1)
    {
        printf("Enter command: ");
        scanf(" %[^\n]", buffer);

        unsigned char enc[BUFFER_SIZE] = {0};

        int len = strlen(buffer);
        int padded_len = ((len + 15) / 16) * 16;

        aes_encrypt((unsigned char *)buffer, len, enc);

        send(sock, enc, padded_len, 0);

        int real_len;
        read(sock, &real_len, sizeof(int));

        bytes = read(sock, buffer, BUFFER_SIZE);

        unsigned char dec[BUFFER_SIZE] = {0};
        aes_decrypt((unsigned char *)buffer, bytes, dec);

        dec[real_len] = '\0';

        printf("Server:\n%s\n", dec);
    }
}
