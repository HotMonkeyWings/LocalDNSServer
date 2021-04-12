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
	char ID[2];			// ID number
	unsigned short RD :1;		// Recursion Desired
	unsigned short TC :1;		// Truncate
	unsigned short AA :1;		// Authoritive Answer
	unsigned short OPCODE :1;	// Purpose of msg
	unsigned short QR :1;		// Query/Response

	unsigned short RCODE :4;	// Response Code
	unsigned short CD :1;		// Checking Disabled
	unsigned short AD :1;		// Authenticated Data
	unsigned short Z :1;		// Reserved
	unsigned short RA :1;		// Recursion Available

	unsigned short QDCOUNT;		// Question Count
	unsigned short ANCOUNT;		// Answer Count
	unsigned short NSCOUNT;		// Name Server Count
	unsigned short ARCOUNT;		// Additional Info Count
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

DNS_RECORD *Cache;
pthread_mutex_t lock_cache;

// Parse the DNS Header from received buffer
void parseHeader(char *buffer, DNS_HEADER *header){
	char temp;

	header->ID[0] = buffer[0];
	header->ID[1] = buffer[1];

	// Taking the 3rd byte and parsing it
	temp = buffer[2];
	header->QR = (temp & 128) >> 7;			
	header->OPCODE = (temp & 120) >> 3;	 
	header->AA = (temp & 4) >> 2;				
	header->TC = (temp & 2) >> 1;
	header->RD = temp & 1;

	// Taking the 4th byte and parsing
	temp = buffer[3];
	header->RA = (temp & 128) >> 7;
	header->Z = (temp & 64) >> 6;
	header->AD = (temp & 32) >> 5;
	header->CD = (temp & 16) >> 4;
	header->RCODE = temp & 15;

	// Taking 5th and 6th byte and parsing Question Entry count
	header->QDCOUNT = buffer[4] << 8;
	header->QDCOUNT += buffer[5];

	// Taking 7th and 8th byte and parsing Answer Entry count
	header->ANCOUNT = buffer[6] << 8;
	header->ANCOUNT += buffer[7];

	// Taking 9th and 10th byte and parsing Name Server count
	header->NSCOUNT = buffer[8] << 8;
	header->NSCOUNT += buffer[9];

	// Taking 11th and 12th byte and parsing Additional Info count
	header->ARCOUNT = buffer[10] << 8;
	header->ARCOUNT += buffer[11];
}

// Parse Question from question buffer
void parseQuestion(char *qs, DNS_QUESTION *q){
	int i = 0;
	while (qs[i])
		i += qs[i] + 1;
	q->qsize = i + 1;

	for (i = 0; i < q->qsize; i++)
		q->QNAME[i] = qs[i];

	q->QTYPE[0] = qs[q->qsize];
	q->QTYPE[1] = qs[q->qsize + 1];
	
	q->QCLASS[0] = qs[q->qsize + 2];
	q->QCLASS[1] = qs[q->qsize + 3];
}

// Parse IPv4 to RDATA
void parseIPv4(char *RDATA, char *ip){
	char *temp;

	// Break string into IP fields
	temp = strtok(ip,".");
	RDATA[0] = atoi(temp);

	temp = strtok(NULL, ".");
	RDATA[1] = atoi(temp);

	temp = strtok(NULL, ".");
	RDATA[2] = atoi(temp);

	temp = strtok(NULL, ".");
	RDATA[3] = atoi(temp);
}

// Parse IPv6 to RDATA
void parseIPv6(char *RDATA, char *ip){
	char *temp;
	char byte[2];
	char *ptr;

	temp = strtok(ip, ":");

	RDATA[0] = strtoumax(temp, &ptr, 16);

	short i = 1;
	for (short i = 1; i < 15; i++){
		temp = strtok(NULL, ":");
		RDATA[i] = strtoumax(temp, &ptr, 16);
	}

	temp = strtok(NULL, "\0");
	RDATA[15] = strtoumax(temp, &ptr, 16);
}

// Check if Cache has the Query Request's Response
int fetchFromCache(DNS_QUESTION *q, DNS_ANS *ans){
	printf("\n\t\t[ CHECKING CACHE ]\n");
	DNS_RECORD *entry = Cache;
	int flag = 0;

	while (entry != NULL){
		if (q->qsize == entry->Q.qsize){
			if (q->QTYPE[0] == entry->Q.QTYPE[0] && q->QTYPE[1] == entry->Q.QTYPE[1]){
				short matching = 1;
				for (unsigned short i = 0; i < q->qsize; i++) {

					// Check if Domain Names are the same
					if (q->QNAME[i] != entry->Q.QNAME[i]){
						matching = 0;
						break;
					}

				if (matching){
					*ans = entry->A;
					flag=1;
					break;
					}
				}
			}
		}
		entry = entry->next;		// Goto next cache entry
	}

	if (!flag)
		printf("\n\t\t[ CACHE MISS ]");
	else
		printf("\n\t\t[ CACHE HIT ]");
	
	return flag;
}

void NameToString(char *str, DNS_QUESTION *q){
	unsigned short i = 0, j = 0;
	while (q->QNAME[i]){
		j = i + 1;
		i += q->QNAME[i] + 1;
		while (j < i){
			str[j - 1] = q->QNAME[j];
			++j;
		}
		str[j - 1] = '.';
	}
	str[j] = '\0';
}

void addCache(DNS_QUESTION *q, DNS_ANS *ans){
	DNS_RECORD *entry = (DNS_RECORD*)malloc(sizeof(DNS_RECORD));

	entry->Q = *q;
	entry->A = *ans;
	entry->next = NULL;
	entry->prev = NULL;

	if (Cache != NULL){
		entry->next = Cache;
		Cache->prev = entry;
	}
	Cache = entry;
	printf("\n\t\t[ %s ADDED TO CACHE ]", q->QNAME);
}


