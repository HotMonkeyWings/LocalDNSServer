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

// Converts query name to URL
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

// Add a new entry to the cache
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

// Fetch the Answer Iteratively
void fetchIterative(DNS_QUESTION *q, DNS_ANS *ans){
	printf("\n\t\t[ Searching ]");
	FILE *fp;
	char line[200];
	char cmd[200];
	char query[200];
	char *temp;

	// Convert the Query to URL in ASCII
	NameToString(query, q);

	printf("Query: %s\n", query);

	unsigned short root = 1;
	int pos = strlen(query) - 1;

	char nameserver[50] = { 0 };
	while (pos >= 0){
		strcpy(cmd, "nslookup -type=ns ");		// Adding to nslookup
		if (root == 1 || pos == 0){
			strcat(cmd, query+pos);
			root = 0;
		}
		else 
			strcat(cmd, query + pos + + 1);
		strcat(cmd, nameserver);

		printf("Command Invoked: %s\n", cmd);

		short NSExist = 0;
		fp = popen(cmd, "r");					// Pipe to get command output 

		while (fgets(line, 500, fp) != NULL){
			if (strstr(line, "nameserver = ") != NULL){
				NSExist = 1;					// Name Server exists as substring, hence present
				break;
			}
			
		}
		pclose(fp);

		if (!NSExist)
			break;		// No Name Server found

		temp = strtok(line, "=");
		temp = strtok(NULL, "\n");
		printf("%s\n", temp);				// Output Name Server
		strcpy(nameserver, temp);

		--pos;
		while (pos > 0){
			if (query[pos] == '.')
				break;
			--pos;
		}
	}

	printf("NameServer: %s\n", nameserver);
	strcpy(cmd, "nslookup -type=A ");
	strcat(cmd, query);		// Adding URL to command
	strcat(cmd, nameserver);	// Adding Nameserver to get info from
	printf("Command Invoked: %s\n", nameserver);
	
	fp = popen(cmd, "r");		// Pipe to get command output
	unsigned short c = 0, NF = 0;		

	while (fgets(line, 500, fp) != NULL){

		// Means it wasn't found
		if (line[0] == "*"){
			NF = 1;		// Not Found Flag
			break;
		}
		if (strlen(line) >= 7){
			if (strncmp(line, "Address", 7) == 0){
				++c;
				if (c == 2)
					break;
			}
		}
	}
	pclose(fp);		// Close pipe for command

	temp = strtok(line,": ");
	temp = strtok(NULL, "\n");

	char IP[50];
	strcpy(IP, temp);
	printf("IP Address: %s\n", IP);

	if (NF)
		ans->RDLENGTH = 0;	// Nothing Found

	else {
		
		if (q->QTYPE[0] == 0){
			// A Query
			if (q->QTYPE[1] == 0x1){
				ans->RDLENGTH = 4;			// As its IPv4
				parseIPv4(ans->RDATA, IP);
			}

			// AAAA Query
			else if (q->QTYPE[1] == 0x1c){
				ans->RDLENGTH = 16;
				parseIPv6(ans->RDATA, IP);
			}

			// NS Query
			else if (q->QTYPE[1] == 0x2){
				
			}
			
			// CNAME Query
			else if (q->QTYPE[1] == 0x3){
				
			}
		}
		
		// Add to the cache
		addCache(q, ans);
	}
}

void resolveQuery(DNS_QUESTION *q, DNS_ANS *ans){
	ans->TTL = 30;
	
	// Check if its not in the cache
	if (fetchFromCache(q, ans) == 0)
		fetchIterative(q, ans);
}

// Packs a DNS Packet Header
void assignHeader(char *buffer, DNS_HEADER *header, unsigned short RDLENGTH){
	
	// Assign ID
	buffer[0] = header->ID[0];
	buffer[1] = header->ID[1];

	// Pack the 3rd byte
	char temp = 1;	//QR = 1 as it is a Query Response

	temp = temp << 4;
	temp = temp | (header->OPCODE);	// Assign OPCODE

	temp = temp << 1;
	temp = temp | (header->AA);		// Assign AA

	temp = temp << 1;
	temp = temp | (header->TC);		// Assign TC

	temp = temp << 1;
	temp = temp | (header->RD);		// Assign RD

	buffer[2] = temp;

	temp = 0;						// Assign RA as 0
	
	temp = temp << 7;
	temp = temp | (header->RCODE);	// ASSIGN RCODE

	buffer[3] = temp;

	buffer[5] = header->QDCOUNT;
	buffer[7] = (RDLENGTH == 0) ? 0 : 1;
	buffer[9] = header->NSCOUNT;
	buffer[11] = header->ARCOUNT;
}

void assignQuestion(char *qField, DNS_QUESTION *q){
	unsigned i = 0;
	// Get the Question Field
	while (i < q->qsize){
		qField[i] = q->QNAME[i];
		++i;
	}

	qField[i++] = q->QTYPE[0];
	qField[i++] = q->QTYPE[1];
	
	qField[i++] = q->QCLASS[0];
	qField[i++] = q->QCLASS[1];
}

void assignAnswer(char *ansField, DNS_QUESTION *q, DNS_ANS *ans){
	unsigned i = 0;
	while (i < q->qsize){
		ansField[i] = q->QNAME[i];
		++i;
	}

	ansField[i++] = q->QTYPE[0];
	ansField[i++] = q->QTYPE[1];

	ansField[i++] = q->QCLASS[0];
	ansField[i++] = q->QCLASS[1];

	ansField[i++] = 0;
	ansField[i++] = 0;
	ansField[i++] = 0;
	ansField[i++] = ans->TTL;

	ansField[i++] = 0;
	ansField[i++] = ans->RDLENGTH;

	for (unsigned j = 0; j < ans->RDLENGTH; j++)
		ansField[i++] = ans->RDATA[j];
}

unsigned createResponse(DNS_HEADER *header, DNS_QUESTION *q, DNS_ANS *ans, char *buffer){
	memset(buffer, 0, SIZE);

	unsigned pos = 0;

	assignHeader(buffer, header, ans->RDLENGTH);
	pos = 12;		// Header is 12 bytes

	assignQuestion(buffer + pos, q);
	pos += (q->qsize) + 4;

	if (ans->RDLENGTH != 0){
		assignAnswer(buffer + pos, q, ans);
		pos += (q->qsize) + 10 + (ans->RDLENGTH);
	}
	return pos;
}

void *TTLHandler(){
	pthread_mutex_lock(&lock_cache);
	DNS_RECORD *entry, *temp;

	while (entry != NULL){
		entry->A.TTL -= 1;

		if (entry->A.TTL == 0){
			if (entry->next != NULL)
				(entry->next)->prev = entry->prev;
			
			if (entry->prev == NULL)
				Cache = entry->next;
			else
				(entry->prev)->next = entry->next;
			temp = entry;
			printf("\n\t\t[ Deleting Cache Entry : %s ]\n", temp->Q.QNAME);
			entry = entry->next;
			free (temp);
		}
		else
			entry = entry->next;
	}
	pthread_mutex_unlock(&lock_cache);
}

void *cacheHandler(){
	clock_t start, end;
	while (1){
		start = clock() / CLOCKS_PER_SEC;
		while (1){
			end = clock() / CLOCKS_PER_SEC;
			if (end - start >= 1)
				break;
		}
		pthread_t T_ID;
		pthread_create(&T_ID, NULL, TTLHandler, NULL);
	}
}

void *handleLookup(void *ARG){
	HL_ARG *arg = (HL_ARG *)ARG;

	DNS_HEADER requestHeader;
	DNS_QUESTION requestQuestion;
	DNS_ANS ans;

	parseHeader(arg->buf, &requestHeader);
	parseQuestion(arg->buf + 12, &requestQuestion);

	resolveQuery(&requestQuestion, &ans);

	char buffer[SIZE];
	unsigned int packetSize;
	packetSize = createResponse(&requestHeader, &requestQuestion, &ans, buffer);

	if (sendto(arg->sock, buffer, packetSize, 0, (struct sockaddr *)&(arg->clientAddr), sizeof(arg->clientAddr)) < 0 )
		printf("Error in sendto()");
	else
		printf("\n\t\t[ Response has beeen Sent]\n");
	free(arg);
}

int main(){
	printf("Hi");
}
