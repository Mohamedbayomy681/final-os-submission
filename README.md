# Secure Socket Project

## Description
Client-server application with authentication and AES encryption.

## Features
- User authentication using users.txt
- Role-based access (entry / medium / top)
- Encrypted communication using AES
- Command execution on server

## Files
- client.c
- server.c
- security.c / security.h
- users.txt

## How to run
gcc server.c security.c -o server -lssl -lcrypto -lpthread
gcc client.c security.c -o client -lssl -lcrypto

./server
./client
