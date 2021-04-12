#include <sys/types.h>
#include <sys/socket.h>	
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <inttypes.h>

#define SIZE 2048	// Size of Buffers
#define QSIZE 100	// Size of Queries

// DNS Header
typedef struct {
	unsigned short ID;		// ID number
	unsigned char RD :1;		// Recursion Desired
	unsigned char TC :1;		// Truncate
	unsigned char AA :1;		// Authoritive Answer
	unsigned char OPCODE :1;	// Purpose of msg
	unsigned char QR :1;		// Query/Response

	unsigned char RCODE :4;		// Response Code
	unsigned char CD :1;		// Checking Disabled
	unsigned char AD :1;		// Authenticated Data
	unsigned char Z :1;		// Reserved
	unsigned char RA :1;		// Recursion Available

	unsigned short QCOUNT;		// Question count
	unsigned short ANCOUNT;		// Answer count
	unsigned short AUCOUNT;		// Authority count
	unsigned short ADCOUNT;		// Resource count
} DNS_HEADER;

// Constant sized fields of query structure
typedef struct {
	char QNAME[QSIZE];
	short unsigned qsize;
	char QTYPE[2];
	char QCLASS[2];
} DNS_QUESTION;

typedef struct {
	unsigned short TTL;
	unsigned short RDLENGTH;
	char RDATA[QSIZE];
} DNS_ANS;


typedef struct DNS_RECORD{
	DNS_QUESTION Q;
	DNS_ANS A;

	struct DNS_RECORD *next;
	struct DNS_RECORD *prev;
} DNS_RECORD;


typedef struct {
	int sock;
	char buf[SIZE];
	struct sockaddr_in clientAddr;
} HL_ARG;


