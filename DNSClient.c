#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char* argv[]){
    printf("Welcome to DNS  Client! \nCTRL+D exit \n");
    while(1){
        char website[200], type[10];
        FILE *fpipe;
        char *template = "nslookup -type=%s -port=1234 %s 127.0.0.1";
        char cmd[200];
        char c = 0;
        printf("Enter website: ");
        if (scanf("%s", website) == EOF)
            break;

        printf("Enter Type: ");
        if (scanf("%s", type) == EOF)
            break;

        if (strcmp(type, "ns") != 0 && strcmp(type, "cname") != 0 && strcmp(type, "a") != 0 && strcmp(type,"aaaa") != 0){
            printf("UNAUTHORISED REQUEST\n");
            continue;
        }
        else{

            sprintf(cmd, template, type, website);

            if (0 == (fpipe = (FILE*)popen(cmd, "r"))){
                perror("popen() failed.");
                exit(EXIT_FAILURE);
            }

            while (fread(&c, sizeof c, 1, fpipe))
                printf("%c", c);

            pclose(fpipe);
        }
    }
}
