#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "security.h"

#define PORT 8080
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
} client_info_t;

void execute_command(const char *cmd, char *result)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        strcpy(result, "Command failed\n");
        return;
    }

    fread(result, 1, BUFFER_SIZE, fp);
    pclose(fp);
}

void *handle_client(void *arg)
{
    client_info_t *client = (client_info_t *)arg;
    int sock = client->socket;

    char buffer[BUFFER_SIZE];
    char username[100], password[100], role[50];

    int bytes = read(sock, buffer, BUFFER_SIZE);
    buffer[bytes] = '\0';

    if (sscanf(buffer, "%[^:]:%s", username, password) != 2 ||
        !authenticate_user(username, password, role))
    {
        send(sock, "AUTH_FAIL", 9, 0);
        close(sock);
        free(client);
        pthread_exit(NULL);
    }

    send(sock, "AUTH_OK", 7, 0);

    while (1)
    {
        bytes = read(sock, buffer, BUFFER_SIZE);
        if (bytes <= 0) break;

        unsigned char decrypted[BUFFER_SIZE] = {0};
        aes_decrypt((unsigned char *)buffer, bytes, decrypted);

        char command[50];
        sscanf((char *)decrypted, "%s", command);

        if (!has_permission(role, command))
        {
            char msg[] = "ACCESS_DENIED";
            unsigned char enc[BUFFER_SIZE] = {0};

            int len = strlen(msg);
            int padded_len = ((len + 15) / 16) * 16;

            aes_encrypt((unsigned char *)msg, len, enc);

            send(sock, &len, sizeof(int), 0);
            send(sock, enc, padded_len, 0);

            continue;
        }

        char result[BUFFER_SIZE] = {0};
        execute_command((char *)decrypted, result);

        unsigned char enc[BUFFER_SIZE] = {0};

        int len = strlen(result);
        int padded_len = ((len + 15) / 16) * 16;

        aes_encrypt((unsigned char *)result, len, enc);

        send(sock, &len, sizeof(int), 0);
        send(sock, enc, padded_len, 0);
    }

    close(sock);
    free(client);
    pthread_exit(NULL);
}

int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 10);

    printf("Server running on port %d...\n", PORT);

    while (1)
    {
        client_info_t *client = malloc(sizeof(client_info_t));
        client->socket = accept(server_fd, NULL, NULL);

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, client);
        pthread_detach(tid);
    }
}