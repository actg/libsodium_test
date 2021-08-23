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

#define SERVER_ADDRESS             ("192.168.2.178")

#define SOCKET_BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size
#define MSG_HEADER_LEN             (4 + 4 + 1 + 2 + 2)

unsigned char key[crypto_stream_chacha20_KEYBYTES] = {
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBB,
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBB,
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBB,
    0x78, 0x89, 0x34, 0x78, 0x78, 0x23, 0x34, 0xBA
};

static unsigned char *message[10];

static uint16_t msgCalculateCRC(uint8_t *puchMsg, int usDataLen)
{
    uint16_t wCRCin = 0x0000;
    int16_t wCPoly = 0x1021;
    uint8_t wChar = 0;
    uint8_t i = 0;
    while(usDataLen--)
    {
        wChar = *(puchMsg++);
        wCRCin ^= (wChar << 8);
        for(i = 0; i < 8; i++)
        {
            if(wCRCin & 0x8000)
            {
                wCRCin = (wCRCin << 1) ^ wCPoly;
            }
            else
            {
                wCRCin = wCRCin << 1;
            }
        }
    }
    return (wCRCin);
}

// read from file,and send it
int main(int argc, char **argv)
{
	WORD wVersionRequested;
	WSADATA wsaData;
	SOCKET sockClient;
	SOCKADDR_IN addrSrv;
	char recvBuf[100];
	int err;
	buffer_t plain;

	int i=0;
	int len = 0;
	int total_len =0;
	cipher_ctx_t ctx;
	unsigned char msgHeader[4+4+1+2+2];   //type+length+ver+serial+CRC

	int msgType=0x7890;
	int msgLength=0;
	unsigned short msgSerial=0;
	unsigned short CRC=0;
	int messageIndex=0;
	int disableNagle=1;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		return;
	}

	sockClient=socket(AF_INET,SOCK_STREAM,0);
	addrSrv.sin_addr.S_un.S_addr=inet_addr(SERVER_ADDRESS);
	addrSrv.sin_family=AF_INET;
	addrSrv.sin_port=htons(8992);

	setsockopt(sockClient, IPPROTO_TCP, TCP_NODELAY, (const char *)&disableNagle, sizeof(disableNagle));
	connect(sockClient,(SOCKADDR*)&addrSrv,sizeof(SOCKADDR));

    stream_ctx_init(&ctx, 1);

	system("chcp 65001");

	while(messageIndex < sizeof(message)/sizeof(message[0]))
	{
		char buffer[256] = { 0 };
		size_t length = 0;

		sodium_memzero(&plain, sizeof(plain));
		total_len=0;

		sprintf(buffer, "%d.txt", messageIndex +1);
		FILE *fp = fopen(buffer,"rb");
		if (!fp)
		{
			printf("open file %d failure\n", messageIndex +1);
			continue;
		}

		fseek(fp, 0L, SEEK_END);
		length = ftell(fp);
		fseek(fp, 0L, SEEK_SET);
		message[messageIndex]  = (char *)calloc(length, sizeof(char));
		if (!message[messageIndex])
		{
			goto Cleanup;
		}

		fread(message[messageIndex], length, 1, fp);
		fclose(fp);

		// fill type
		msgHeader[0]=BREAK_UINT32(msgType,3);
		msgHeader[1]=BREAK_UINT32(msgType,2);
		msgHeader[2]=BREAK_UINT32(msgType,1);
		msgHeader[3]=BREAK_UINT32(msgType,0);

		// fill length
		msgLength= length;
		msgHeader[4]=BREAK_UINT32(msgLength,3);
		msgHeader[5]=BREAK_UINT32(msgLength,2);
		msgHeader[6]=BREAK_UINT32(msgLength,1);
		msgHeader[7]=BREAK_UINT32(msgLength,0);
		
		// fill ver
		msgHeader[8]=0x01;

		// fill serial
		msgSerial++;
		msgHeader[9]=HI_UINT16(msgSerial);
		msgHeader[10]=LO_UINT16(msgSerial);

		// fill CRC
		CRC=msgCalculateCRC(msgHeader,sizeof(msgHeader)-2);
		msgHeader[11]=HI_UINT16(CRC);
		msgHeader[12]=LO_UINT16(CRC);

		printf("msgLength:%u CRC:0x%04X\n",msgLength, CRC);

		// encrypt header
		plain.data = (char *)calloc(msgLength + sizeof(msgHeader),sizeof(char));
		memcpy(plain.data,msgHeader,sizeof(msgHeader));
		memcpy(plain.data+sizeof(msgHeader),message[messageIndex],msgLength);
		plain.len = msgLength + sizeof(msgHeader);

		// encrypt body
		stream_encrypt(&plain,&ctx,SOCKET_BUF_SIZE,key);
		printf("send cipher_text len:%d\n",plain.len);
	#if 0
		for(i=0;i<plain.len;i++)
		{
			printf("%02X",plain.data[i]&0xFF);
		}
		printf("\n");
	#endif
		while(total_len < plain.len)
		{
			len = send(sockClient, (plain.data +total_len), plain.len-total_len, 0);   //Nonblocking IO
			if(len > 0)
			{
				total_len+=len;
			}
			else if(len == -1)
			{
				if(errno != EAGAIN && errno != EWOULDBLOCK)
				{
					printf("send error\n");
				}
			}
		}

		if (plain.data)
		{
			free(plain.data);
			plain.data = NULL;
		}

		if (message[messageIndex])
			free(message[messageIndex]);

		messageIndex++;
	}
#if 1
	messageIndex = 0;
	while (messageIndex < sizeof(message) / sizeof(message[0]))
	{
		//read header
		int ret = 0;
		int msgType = 0;
		int msgLength = 0;
		unsigned char msgVer = 0;
		unsigned short msgSerial = 0;
		unsigned short msgCRC = 0,newCRC=0;
		int index = 0;
		buffer_t cipher;

		char header[MSG_HEADER_LEN] = { 0 };
		sodium_memzero(&cipher, sizeof(cipher));
		ret=recv(sockClient, header, sizeof(header),0);
		if (ret >= sizeof(header))
		{
			cipher.data = (char *)calloc(sizeof(header), sizeof(char));
			cipher.len = sizeof(header);
			memcpy(cipher.data, header, sizeof(header));
			stream_decrypt(&cipher, &ctx, SOCKET_BUF_SIZE, key);

			msgType = BUILD_UINT32(cipher.data[index + 3], cipher.data[index + 2],
				cipher.data[index + 1], cipher.data[index]);
			index += 4;

			msgLength= BUILD_UINT32(cipher.data[index + 3], cipher.data[index + 2],
				cipher.data[index + 1], cipher.data[index]);
			index += 4;

			msgVer = cipher.data[index++];

			msgSerial = BUILD_UINT16(cipher.data[index + 1], cipher.data[index]);
			index += 2;

			//calculate CRC
			newCRC = msgCalculateCRC(cipher.data, index);

			msgCRC = BUILD_UINT16(cipher.data[index + 1], cipher.data[index]);
			index += 2;

			printf("msgCRC:0x%04X msgCRC:0x%04X\n",msgCRC,newCRC);
			printf("msgType:0x%04X msgLength:%u msgSerial:%u\n", msgType,msgLength,msgSerial);
			free(cipher.data);

			if (msgLength > 0 && msgLength < INT_MAX)
			{
				total_len = 0;
				sodium_memzero(&cipher, sizeof(cipher));
				cipher.data = (char *)calloc(msgLength, sizeof(char));
				cipher.len = msgLength;
				if (cipher.data)
				{
					do {
						len = recv(sockClient, cipher.data + total_len, msgLength-total_len, 0);
						if (len > 0)
						{
							total_len += len;
						}else if(len == SOCKET_ERROR)
						{
							int errcode = WSAGetLastError();
							printf("read failure:%d\n", errcode);
							if (errcode == WSAECONNRESET)
							{
								break;
							}
						}
					} while (total_len < msgLength);

					//decrypt body
					stream_decrypt(&cipher, &ctx, SOCKET_BUF_SIZE, key);
					cipher.data[cipher.len] = '\0';
					printf("%u %s\n",cipher.len,cipher.data);

					free(cipher.data);
				}
			}
		}
		else if (ret == SOCKET_ERROR)
		{
			int errcode = WSAGetLastError();
			printf("read failure:%d\n", errcode);
			if (errcode == WSAECONNRESET)
			{
				break;
			}
		}

		messageIndex++;
	}
#endif
Cleanup:
	Sleep(2000);
	closesocket(sockClient);
	WSACleanup();
    system("pause");
    return 0;
}
