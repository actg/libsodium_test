#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sodium.h"
#include "../dll/enc_dec.h"
#include <Winsock2.h>
#include <ws2def.h>
#include <errno.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libsodium.lib")
#pragma comment(lib, "../Release/dll.lib")

#define SOCKET_PORT                (8992)
#define SOCKET_BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size
#define MSG_HEADER_LEN             (4 + 4 + 1 + 2 + 2)

unsigned char key[crypto_stream_chacha20_KEYBYTES] = {
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBB,
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBB,
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBB,
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBA
};

static uint16_t msgCalculateCRC(uint8_t *puchMsg, int usDataLen)
{
    uint16_t wCRCin = 0x0000;
    int16_t wCPoly = 0x1021;
    uint8_t wChar = 0;
    uint8_t i = 0;
    while (usDataLen--) {
        wChar = *(puchMsg++);
        wCRCin ^= (wChar << 8);
        for (i = 0; i < 8; i++) {
            if (wCRCin & 0x8000) {
                wCRCin = (wCRCin << 1) ^ wCPoly;
            } else {
                wCRCin = wCRCin << 1;
            }
        }
    }
    return (wCRCin);
}

int main(int argc, char **argv)
{
    WORD sockVersion;
    WSADATA wsaData;

    SOCKET slisten;
    SOCKET sClient;
    struct sockaddr_in sin;
    struct sockaddr_in remoteAddr;
    int nAddrlen;

    cipher_ctx_t ctx;

    sockVersion = MAKEWORD(2, 2);
    if (WSAStartup(sockVersion, &wsaData) != 0) {
        return 0;
    }

    slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (slisten == INVALID_SOCKET) {
        printf("socket error !");
        return 0;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(SOCKET_PORT);
    sin.sin_addr.S_un.S_addr = INADDR_ANY;
    if (bind(slisten, (LPSOCKADDR)&sin, sizeof(sin)) == SOCKET_ERROR) {
        printf("bind error !");
    }

    if (listen(slisten, 5) == SOCKET_ERROR) {
        printf("listen error !");
        return 0;
    }

    while (1) {
        buffer_t cipher;
        int len = 0;
        size_t total_len = 0;

        nAddrlen = sizeof(remoteAddr);
        sClient = accept(slisten, (SOCKADDR *)&remoteAddr, &nAddrlen);
        stream_ctx_init(&ctx, 0);

		if (sClient == INVALID_SOCKET) {
			printf("accept error !");
			continue;
		}

		system("chcp 65001");
		printf("client ip:%s\n", inet_ntoa(remoteAddr.sin_addr));

        while (1) {
            int msgType = 0;
            int msgLength = 0;
            unsigned char msgVer = 0;
            unsigned short msgSerial = 0;
            unsigned short msgCRC = 0, newCRC = 0;
            int index = 0;

            //read nonce
            if (!ctx.init) {
				printf("read nonce...\n");
                sodium_memzero(&cipher, sizeof(cipher));
                cipher.data = (char *)calloc(ctx.nonce_len, sizeof(char));
                cipher.len = ctx.nonce_len;
                if (!cipher.data) {
                    printf("nonce memory calloc failure\n");
                    exit(-1);
                }

                len = recv(sClient, cipher.data, cipher.len, 0);
                if (len >= ctx.nonce_len) {
                    stream_decrypt(&cipher, &ctx, SOCKET_BUF_SIZE, key);
                } else if (len == SOCKET_ERROR) {
					if (errno == EAGAIN || errno == EWOULDBLOCK)
					{
						continue;
					}
					else {
						printf("Remote recv error\n");
						goto Cleanup;
					}
				}
				else {
					printf("Remote server closed\n");
					goto Cleanup;
				}

                if (cipher.data) {
                    free(cipher.data);
                    cipher.data = NULL;
                }
            }

            //read header
            sodium_memzero(&cipher, sizeof(cipher));
            cipher.data = (char *)calloc(MSG_HEADER_LEN, sizeof(char));
            cipher.len = MSG_HEADER_LEN;
            if (!cipher.data) {
                printf("header memory calloc failure\n");
                exit(-1);
            }

            len = recv(sClient, cipher.data, cipher.len, 0);
            if (len >= MSG_HEADER_LEN) {
                stream_decrypt(&cipher, &ctx, SOCKET_BUF_SIZE, key);

                msgType = BUILD_UINT32(cipher.data[index + 3], cipher.data[index + 2],
                                       cipher.data[index + 1], cipher.data[index]);
                index += 4;

                msgLength = BUILD_UINT32(cipher.data[index + 3], cipher.data[index + 2],
                                         cipher.data[index + 1], cipher.data[index]);
                index += 4;

                msgVer = cipher.data[index++];

                msgSerial = BUILD_UINT16(cipher.data[index + 1], cipher.data[index]);
                index += 2;

                //calculate CRC
                newCRC = msgCalculateCRC(cipher.data, index);
                msgCRC = BUILD_UINT16(cipher.data[index + 1], cipher.data[index]);

                if (cipher.data) {
                    free(cipher.data);
                    cipher.data = NULL;
                }

                if (msgCRC != newCRC) {
                    printf("msgCRC:0x%04X msgCRC:0x%04X compare failure\n", msgCRC, newCRC);
                    break;
                }

                printf("msgType:0x%04X msgLength:%u msgSerial:%u\n", msgType, msgLength, msgSerial);

                if (msgLength > 0 && msgLength < INT_MAX) {
                    total_len = 0;
                    sodium_memzero(&cipher, sizeof(cipher));
                    cipher.data = (char *)calloc(msgLength, sizeof(char));
                    if (!cipher.data) {
                        printf("body memory calloc failure\n");
                        exit(-1);
                    }
                    cipher.len = msgLength;
                    do {
                        len = recv(sClient, cipher.data + total_len, msgLength - total_len, 0);
                        if (len > 0) {
                            total_len += len;
                        } else if (len == SOCKET_ERROR) {
							if (errno == EAGAIN || errno == EWOULDBLOCK)
							{
								continue;
							}
							else {
								printf("Remote recv error\n");
								goto Cleanup;
							}
						}
						else {
							printf("Remote server closed\n");
							goto Cleanup;
						}
                    } while (total_len < msgLength);

                    //decrypt body
                    stream_decrypt(&cipher, &ctx, SOCKET_BUF_SIZE, key);
					cipher.data[cipher.len] = '\0';
					if (msgType == 0x7009)
					{
						printf("%u\n\n", cipher.len);
					}
					else {
						printf("%u %s\n\n", cipher.len, cipher.data);
					}

                    if (cipher.data) {
                        free(cipher.data);
                        cipher.data = NULL;
                    }
                }
            } else if (len == SOCKET_ERROR) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
				{
					continue;
				}
				else {
					printf("Remote recv error\n");
					goto Cleanup;
				}
			}
			else {
				printf("Remote server closed\n");
				goto Cleanup;
			}
        }

Cleanup:
        if (cipher.data) {
            free(cipher.data);
            cipher.data = NULL;
        }
		printf("close client handle\n");
        closesocket(sClient);
    }

    closesocket(slisten);
    WSACleanup();
    system("pause");
    return 0;
}