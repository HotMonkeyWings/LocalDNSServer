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

#define SIZE 2048
#define QSIZE 100

typedef struct DNSPacketHeader DNSHeader;
typedef struct DNSPacketQuestion DNSQuestion;
typedef struct DNSPacketAnsAddition DNSAns;
typedef struct DNSRecord DNSRecord;

typedef struct handleLookupArg HLArg;

struct DNSPacketHeader
{
    char id[2];
    short unsigned QR;
    short unsigned Opcode;
    short unsigned AA;
    short unsigned TC;
    short unsigned RD;
    short unsigned RA;
    short unsigned Z;
    short unsigned AD;
    short unsigned CD;
    short unsigned RCODE;
    short unsigned QDCOUNT;
    short unsigned ANCOUNT;
    short unsigned NSCOUNT;
    short unsigned ARCOUNT;
};

struct DNSPacketQuestion
{
    char QNAME[QSIZE];
    short unsigned qsize;
    char QTYPE[2];
    char QCLASS[2];
};

struct DNSPacketAnsAddition
{
    unsigned short TTL;
    unsigned short RDLENGTH;
    char RDATA[QSIZE];
};

struct DNSRecord
{
    DNSQuestion Q;
    DNSAns A;

    struct DNSRecord *next;
    struct DNSRecord *prev;
};

struct handleLookupArg
{
    int sock;
    char Buf[SIZE];
    struct sockaddr_in clientAddr;
};

DNSRecord *Cache;
pthread_mutex_t cache_lock;

void getTime(char *t_str)
{
    time_t t;
    struct tm tm;

    t = time(NULL);
    tm = *localtime(&t);
    strcpy(t_str, asctime(&tm));
}

void parseHeader(char *recvBuf, DNSHeader *req)
{

    char octect;

    req->id[0] = recvBuf[0];
    req->id[1] = recvBuf[1];

    octect = recvBuf[2];
    req->QR = (octect & 128) >> 7;
    req->Opcode = (octect & 120) >> 3;
    req->AA = (octect & 4) >> 2;
    req->TC = (octect & 2) >> 1;
    req->RD = octect & 1;

    octect = recvBuf[3];
    req->RA = (octect & 128) >> 7;
    req->Z = (octect & 64) >> 6;
    req->AD = (octect & 32) >> 5;
    req->CD = (octect & 16) >> 4;
    req->RCODE = octect & 15;

    req->QDCOUNT = recvBuf[4];
    req->QDCOUNT = (req->QDCOUNT) << 8;
    req->QDCOUNT = (req->QDCOUNT) + recvBuf[5];

    req->ANCOUNT = recvBuf[6];
    req->ANCOUNT = (req->ANCOUNT) << 8;
    req->ANCOUNT = (req->ANCOUNT) + recvBuf[7];

    req->NSCOUNT = recvBuf[8];
    req->NSCOUNT = (req->NSCOUNT) << 8;
    req->NSCOUNT = (req->NSCOUNT) + recvBuf[9];

    req->ARCOUNT = recvBuf[10];
    req->ARCOUNT = (req->ARCOUNT) << 8;
    req->ARCOUNT = (req->ARCOUNT) + recvBuf[11];
}

void fetchQuestion(char *qstart, DNSQuestion *qstn)
{
    int i = 0;
    while (qstart[i])
    {
        i = i + (qstart[i] + 1);
    }

    qstn->qsize = i + 1;

    for (i = 0; i < qstn->qsize; ++i)
    {
        qstn->QNAME[i] = qstart[i];
        //printf("%c ", qstn->QNAME[i]);
    }
}

void parseQuestion(char *qStart, DNSQuestion *qstn)
{
    fetchQuestion(qStart, qstn);

    qstn->QTYPE[0] = qStart[qstn->qsize];
    qstn->QTYPE[1] = qStart[qstn->qsize + 1];

    qstn->QCLASS[0] = qStart[qstn->qsize + 2];
    qstn->QCLASS[1] = qStart[qstn->qsize + 3];
}

void parseIPv4(char *RDATA, char *ip)
{
    char *octect = strtok(ip, ".");

    //printf("%s-", octect);
    RDATA[0] = atoi(octect);

    octect = strtok(NULL, ".");
    //printf("%s-", octect);
    RDATA[1] = atoi(octect);

    octect = strtok(NULL, ".");
    //printf("%s-", octect);
    RDATA[2] = atoi(octect);

    octect = strtok(NULL, "\0");
    //printf("%s\n", octect);
    RDATA[3] = atoi(octect);
}

void parseIPv6(char *RDATA, char *ip)
{
    char *octect = strtok(ip, ":");
    char byte[2];
    char *ptr;

    printf("%s-", octect);
    RDATA[0] = strtoumax(octect, &ptr, 16); //atoi(octect);

    short i = 1;
    for (short i = 1; i < 15; ++i)
    {
        octect = strtok(NULL, ":");
        printf("%s-\n", octect);
        RDATA[i] = strtoumax(octect, &ptr, 16); // atoi(octect);
    }

    octect = strtok(NULL, "\0");
    printf("%s\n", octect);
    RDATA[15] = strtoumax(octect, &ptr, 16);
}

int fetchFromCache(DNSQuestion *qstn, DNSAns *ans) //[TODO]
{
    printf("\n[ Fetching from Cache ]\n");
    DNSRecord *entry = Cache;
    int found = 0;

    while (entry != NULL)
    {
        if (qstn->qsize == entry->Q.qsize)
        {
            if (qstn->QTYPE[0] == entry->Q.QTYPE[0] && qstn->QTYPE[1] == entry->Q.QTYPE[1])
            {
                short matching = 1;
                for (unsigned short i = 0; i < qstn->qsize; ++i)
                {
                    if (qstn->QNAME[i] != entry->Q.QNAME[i])
                    {
                        matching = 0;
                        break;
                    }
                }
                if (matching == 1)
                {
                    *ans = entry->A;
                    found = 1;
                    break;
                }
            }
        }

        entry = entry->next;
    }
    if (found == 0)
        printf("\n[ Not found in Cache ]\n");
    return found;
}

void DNSNameToString(char *str, DNSQuestion *qstn)
{
    unsigned short i = 0, j = 0;
    while (qstn->QNAME[i])
    {
        j = i + 1;
        i = i + (qstn->QNAME[i] + 1);
        while (j < i)
        {
            str[j - 1] = qstn->QNAME[j];
            ++j;
        }
        str[j - 1] = '.';
    }
    str[j] = '\0';
    //printf("\n%s\n", str);
}

void addToCache(DNSQuestion *qstn, DNSAns *ans)
{
    DNSRecord *entry = (DNSRecord *)malloc(sizeof(DNSRecord));

    entry->Q = *qstn;
    entry->A = *ans;
    entry->next = NULL;
    entry->prev = NULL;

    if (Cache != NULL)
    {
        entry->next = Cache;
        Cache->prev = entry;
    }
    Cache = entry;
    printf("\n[Added to Cache: %s]\n", qstn->QNAME);
}

void fetchIterative(DNSQuestion *qstn, DNSAns *ans)
{
    printf("\n[ Fetching Iteratively ]\n");
    FILE *fp;
    char line[200];
    char cmd[200];
    char qry[200];
    char *tmp;

    DNSNameToString(qry, qstn);

    printf("QRY: %s\n", qry);

    unsigned short root = 1;
    int pos = strlen(qry) - 1;

    char nameserver[50] = {0};
    while (pos >= 0)
    {
        strcpy(cmd, "nslookup -type=ns ");
        if (root == 1 || pos == 0)
        {
            strcat(cmd, qry + pos);
            root = 0;
        }
        else
            strcat(cmd, qry + pos + 1);
        strcat(cmd, nameserver);

        printf("Command: %s\n", cmd);

        short nsExist = 0;
        fp = popen(cmd, "r");

        while (fgets(line, 500, fp) != NULL)
        {
            //puts(line);
            if (strstr(line, "nameserver = ") != NULL)
            {
                nsExist = 1;
                break;
            }
        }
        pclose(fp);

        if (nsExist == 0)
            break;

        tmp = strtok(line, "=");
        tmp = strtok(NULL, "\n");
        printf("%s\n", tmp);
        strcpy(nameserver, tmp);

        --pos;
        while (pos > 0)
        {
            //printf("POS: %d - %c\n", pos, qry[pos]);
            if (qry[pos] == '.')
                break;
            --pos;
        }
    }

    printf("NameServer : %s\n", nameserver);
    strcpy(cmd, "nslookup -type=A ");
    strcat(cmd, qry);
    strcat(cmd, nameserver);
    printf("Command: %s\n", cmd);
    fp = popen(cmd, "r");
    unsigned short c = 0, NF = 0; //NF = Notfound
    while (fgets(line, 500, fp) != NULL)
    {
        if (line[0] == '*')
        {
            NF = 1;
            break;
        }
        if (strlen(line) >= 7)
        {
            if (strncmp(line, "Address", 7) == 0)
            {
                ++c;
                if (c == 2)
                    break;
            }
        }
    }
    pclose(fp);

    tmp = strtok(line, ": ");
    tmp = strtok(NULL, "\n");

    char ip[50];
    strcpy(ip, tmp);
    printf("IP: %s\n", ip);
    if (NF == 1)
    {
        ans->RDLENGTH = 0;
    }
    else
    {
        if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1) //A Query
        {
            ans->RDLENGTH = 4;
            parseIPv4(ans->RDATA, ip);
        }
        else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1c) //AAAA Query
        {
            ans->RDLENGTH = 16;
            //parseIPv6(ans->RDATA, ip);        [TODO]
        }
        else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x2) //NS Query
        {
        }
        else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x5) //CNAME Query
        {
        }
        addToCache(qstn, ans);
    }
}

void fetchRecursive(DNSQuestion *qstn, DNSAns *ans)
{
    printf("\n[ Fetching Recursively ]\n");
    FILE *fp;
    char cmd[200];
    char *tmp;

    //Resolving Root Server
    strcpy(cmd, "nslookup -type=");

    if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1)
        strcat(cmd, "A ");
    else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1c)
        strcat(cmd, "AAAA ");
    else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x2)
        strcat(cmd, "NS ");
    else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x5)
        strcat(cmd, "CNAME ");

    char line[200] = {0};
    DNSNameToString(line, qstn);

    strcat(cmd, line);

    printf("%s\n", cmd);

    fp = popen(cmd, "r");
    unsigned short c = 0, NF = 0; //NF = Notfound
    while (fgets(line, 500, fp) != NULL)
    {
        if (line[0] == '*')
        {
            NF = 1;
            break;
        }
        if (strlen(line) >= 7)
        {
            if (strncmp(line, "Address", 7) == 0)
            {
                ++c;
                if (c == 2)
                    break;
            }
        }
    }
    pclose(fp);

    tmp = strtok(line, ": ");
    tmp = strtok(NULL, "\n");

    char ip[100];
    strcpy(ip, tmp);
    printf("%s\n", ip);

    if (NF == 1)
    {
        ans->RDLENGTH = 0;
    }
    else
    {
        if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1) //A Query
        {
            ans->RDLENGTH = 4;
            parseIPv4(ans->RDATA, ip);
        }
        else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x1c) //AAAA Query
        {
            ans->RDLENGTH = 16;
            //parseIPv6(ans->RDATA, ip);        [TODO]
        }
        else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x2) //NS Query
        {
        }
        else if (qstn->QTYPE[0] == 0 && qstn->QTYPE[1] == 0x5) //CNAME Query
        {
        }
        addToCache(qstn, ans);
    }
}

void resolveQuery(DNSQuestion *qstn, DNSAns *ans)
{
    ans->TTL = 30;

    if (fetchFromCache(qstn, ans) == 0)
    {
        fetchIterative(qstn, ans);
        //fetchRecursive(qstn, ans);
    }
}

void assignHeader(char *sendBuf, DNSHeader *head, unsigned short RDLENGTH)
{
    sendBuf[0] = head->id[0];
    sendBuf[1] = head->id[1];

    char byte = 1; //QR = 1 for response

    byte = byte << 4;
    byte = byte | (head->Opcode);

    byte = byte << 1;
    byte = byte | (head->AA); //[Modify AA]

    byte = byte << 1;
    byte = byte | (head->TC);

    byte = byte << 1;
    byte = byte | (head->RD);

    sendBuf[2] = byte;

    byte = 0; //RA

    byte = byte << 7;
    byte = byte | (head->RCODE);

    sendBuf[3] = byte;

    sendBuf[5] = head->QDCOUNT;
    sendBuf[7] = (RDLENGTH == 0) ? 0 : 1; //[Modify ANCOUNT]
    sendBuf[9] = head->NSCOUNT;
    sendBuf[11] = head->ARCOUNT;
}

void assignQuestion(char *qstField, DNSQuestion *qstn)
{
    unsigned i = 0;
    while (i < qstn->qsize)
    {
        qstField[i] = qstn->QNAME[i];
        ++i;
    }
    qstField[i++] = qstn->QTYPE[0];
    qstField[i++] = qstn->QTYPE[1];

    qstField[i++] = qstn->QCLASS[0];
    qstField[i++] = qstn->QCLASS[1];
}

void assignAnswer(char *ansField, DNSQuestion *qstn, DNSAns *ans)
{
    unsigned i = 0;
    while (i < qstn->qsize)
    {
        ansField[i] = qstn->QNAME[i];
        ++i;
    }
    ansField[i++] = qstn->QTYPE[0];
    ansField[i++] = qstn->QTYPE[1];

    ansField[i++] = qstn->QCLASS[0];
    ansField[i++] = qstn->QCLASS[1];

    ansField[i++] = 0;
    ansField[i++] = 0;
    ansField[i++] = 0;
    ansField[i++] = ans->TTL; //[Modify TTL]

    ansField[i++] = 0; //[Modify RDLENGTH]
    ansField[i++] = ans->RDLENGTH;

    for (unsigned j = 0; j < ans->RDLENGTH; ++j)
    {
        ansField[i++] = ans->RDATA[j];
    }
}

unsigned createResponse(DNSHeader *head, DNSQuestion *qstn, DNSAns *ans, char *sendBuf)
{
    memset(sendBuf, 0, SIZE);

    unsigned pos = 0;

    assignHeader(sendBuf, head, ans->RDLENGTH);
    pos = 12;

    assignQuestion(sendBuf + pos, qstn);
    pos += (qstn->qsize) + 4;

    if (ans->RDLENGTH != 0)
    {
        assignAnswer(sendBuf + pos, qstn, ans);
        pos += (qstn->qsize) + 10 + (ans->RDLENGTH);
    }
    return pos;
}

void *TTLHandler()
{
    pthread_mutex_lock(&cache_lock);
    DNSRecord *entry, *tmp;
    entry = Cache;
    while (entry != NULL)
    {
        entry->A.TTL -= 1;

        if (entry->A.TTL == 0)
        {
            if (entry->next != NULL)
                (entry->next)->prev = entry->prev;

            if (entry->prev == NULL)
                Cache = entry->next;
            else
                (entry->prev)->next = entry->next;
            tmp = entry;
            printf("\n[ Deleting from Cache : %s ]\n", tmp->Q.QNAME);
            entry = entry->next;
            free(tmp);
        }
        else
            entry = entry->next;
    }
    pthread_mutex_unlock(&cache_lock);
}

void *cacheHandler()
{
    clock_t start, end;
    while (1)
    {
        start = clock() / CLOCKS_PER_SEC;
        while (1)
        {
            end = clock() / CLOCKS_PER_SEC;
            if (end - start >= 1)
                break;
        }
        pthread_t TId;
        pthread_create(&TId, NULL, TTLHandler, NULL);
    }
}

void *handleLookup(void *Arg)
{
    HLArg *arg = (HLArg *)Arg;

    DNSHeader reqHeader;
    DNSQuestion reqQstn;
    DNSAns ans;

    parseHeader(arg->Buf, &reqHeader);
    parseQuestion(arg->Buf + 12, &reqQstn);

    resolveQuery(&reqQstn, &ans);

    char sendBuf[SIZE];
    unsigned packetSize;
    packetSize = createResponse(&reqHeader, &reqQstn, &ans, sendBuf);

    if (sendto(arg->sock, sendBuf, packetSize, 0, (struct sockaddr *)&(arg->clientAddr), sizeof(arg->clientAddr)) < 0)
        perror("sendto() failed");
    else
        printf("\n---------------------[ Response Sent ]---------------------\n");
    free(arg);
}

int main(int argc, char *argv[])
{
    Cache = NULL;
    pthread_mutex_init(&cache_lock, NULL);

    unsigned short my_port;

    //Confirm PORT no is given
    if (argc < 2)
    {
        printf("\nPORT : ");
        scanf("%hu", &my_port);
    }
    else
    {
        my_port = atoi(argv[1]);
    }

    //Creating Socket

    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket() failed");
        return 1;
    }

    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        perror("setsockopt() failed");

    //bind socket to address

    struct sockaddr_in server_addr;

    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(my_port);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind() failed");
        return 1;
    }

    printf("Server Listening on port %hu\n", my_port);

    pthread_t cT;
    pthread_create(&cT, NULL, cacheHandler, NULL);

    struct sockaddr_in clientAddr;
    int client_addrLen = sizeof(clientAddr);
    int temp_sock;

    char recvBuf[SIZE];
    int recvLen;

    HLArg *arg;
    while (1)
    {
        if ((recvLen = recvfrom(sock, recvBuf, SIZE - 1, 0, (struct sockaddr *)&clientAddr, &client_addrLen)) < 0)
        {
            perror("recvfrom() failed");
        }
        else
        {
            arg = (HLArg *)malloc(sizeof(HLArg));
            for (int i = 0; i < SIZE; ++i)
            {
                arg->Buf[i] = recvBuf[i];
            }
            arg->sock = sock;
            arg->clientAddr = clientAddr;
            pthread_t tId;
            pthread_create(&tId, NULL, handleLookup, (void *)arg);
            printf("\n---------------[ RequestHandler assigned ]-----------------\n");
        }
    }

    return 0;
}