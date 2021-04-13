int StartsWith(const char *a, const char *b){
   if(strncmp(a, b, strlen(b)) == 0) 
	   return 1;
   return 0;
}
int ends_with(char *a,char *b){
    for(int i=0;i<strlen(a);i++)
    {
        if(a[i]==b[0])
        {
            for(int j=0;j<strlen(b);j++)
                if(a[i+j]!=b[j])
                    return 0;
            return 1;
        }
    }
    return 0;    
}
void getRoot(char root[100]){
    char line[100];
    system("nslookup -type=ns . > roots.txt");
    FILE *fp = fopen("roots.txt", "r");
    while (fscanf(fp,"%s",line)!=EOF)
    {
        if(ends_with(line,".root-servers.net."))
        {
            strcpy(root,line);
            break;
        }
    }
}
void getDomain(char domain[100], char website[230],char root[100]){
    char cmd[169] = "nslookup -type=ns ",cmd2[100] = "", path[1035]="", *token;
    
    token = strtok(website, ".");
    int i = strncmp(token, "www", 3);
    if (i == 0)
        token = strtok(NULL, ".");
    char *lastpart = strtok(NULL, "\0");
    
    strcat(cmd,lastpart);  
    strcat(cmd," ");  
    strcat(cmd, root);
    strcat(cmd, " > ");
    
    strcat(cmd, "domain.txt");

    system(cmd);

    FILE *fp = fopen("domain.txt", "r");
    while (fgets(path, sizeof(path), fp) != NULL) {
        if(strstr(path, "nameserver"))
        {
            token=strtok(path, " = ");
            token=strtok(NULL, " = ");
            token[strcspn(token, "\n")] = 0;
            strcpy(domain, token);
            break;                    
        }
    }
}
void get_name_server(char domain[100], char website[100], char nameserver[100]){
    char cmd[169] = "nslookup -type=ns ",cmd2[100] = "", path[1035]="", *token, w[100];
    
    strcpy(w, website);
    token = strtok(website, ".");
    int i = strncmp(token, "www", 3);
    if (i == 0)
        token = strtok(NULL, ".");
    
    strcat(cmd,w);  
    strcat(cmd," ");  
    strcat(cmd, domain);
    strcat(cmd, " > ");
    
    strcat(cmd, "nameserver.txt");
    system(cmd);

    FILE *fp = fopen("nameserver.txt", "r");
    while (fgets(path, sizeof(path), fp) != NULL) {
        if(strstr(path, "nameserver"))
        {
            token=strtok(path, " = ");
            token=strtok(NULL, " = ");
            token[strcspn(token, "\n")] = 0;
            strcpy(nameserver, token);
            break;                    
        }
    }
}
void get_main_server(char result[100],char domain[100], char website[100], int type){
    char cmd[169] = "nslookup -type=",cmd2[100] = "", path[1035]="", root[100]="", *token,w[100], nameserver[100];
    

    if(type == 1)
        strcat(cmd, "aaaa ");
    else if(type == 2)
        strcat(cmd, "a ");
    else if(type == 3)
        strcat(cmd, "cname ");
    else
        strcat(cmd, "ns ");
    strcpy(w, website);
    w[strlen(w)-1] = '\0';
    website[strlen(website)-1] = '\0';
    

    strcat(cmd,w);  
    strcat(cmd," ");  


    get_name_server(domain,w, nameserver);
    strcat(cmd, nameserver);
    strcat(cmd, " > ");
    strcat(cmd, "cache/");
    strcat(cmd, website);

    strcat(cmd2, "cache/"); 
    strcat(cmd2, website);
    
    if(type==1)
    {
        strcat(cmd, "-aaaa");
        strcat(cmd2, "-aaaa");
    }
        
    if(type ==2)
    {
        strcat(cmd, "-a");
        strcat(cmd2, "-a");
    }
    if (type == 3)
    {
        strcat(cmd, "-cname");
        strcat(cmd2, "-cname");
    }
    if (type == 4)
    {
        strcat(cmd, "-ns");
        strcat(cmd2, "-ns");
    }
    strcat(cmd, ".txt");
    strcat(cmd2, ".txt");
    printf("Command Invoked: %s\n",cmd);
    system(cmd);
    FILE *fp = fopen(cmd2,"r");

    if(type == 1 || type == 2)
    {
        int i = 0;
        while (fgets(path, sizeof(path), fp) != NULL) {
            if(strstr(path, "Address"))
            {
                if(i == 1)
                {
                    token=strtok(path, " = ");
                    token=strtok(NULL, " = ");
                    token[strcspn(token, "\n")] = 0;
                    strcpy(result, token);
                    i++;
                    break;
                }
                else
                    i++;
                                    
            }
        }
        if(i == 1)
            strcat(result, "not found");
    }
    if(type == 4)
    {
        
        while (fgets(path, sizeof(path), fp) != NULL) {
            if(strstr(path, "nameserver"))
            {
                token=strtok(path, " = ");
                token=strtok(NULL, " = ");
                token[strcspn(token, "\n")] = 0;
                strcat(result, token);
                strcat(result, ";");         
            }
        }
    }
    if(type == 3)
    {
        int flag = 0;
        while (fgets(path, sizeof(path), fp) != NULL) {
            if(strstr(path, "canonical name"))
            {
            printf("%s\n", path);

                token=strtok(path, " = ");
                token=strtok(NULL, " = ");
                token=strtok(NULL, " = ");
                token[strcspn(token, "\n")] = 0;
                strcat(result, token);   
                flag = 1;   
            }
        }
        if(flag == 0)
        {
            strcat(result, "not found");
        }
    }
    
}

char *nslookup_handle(char result[100], char args[100], int type)
{
    int i, n;
    char website[230]="", domain[100]="",root[100]="";
    char website_name[100]="";
    
    strcpy(website, args);
    strcpy(website_name, args);

	printf("\n[ NSLOOKUP OUTPUT ]\n");
    getRoot(root);
    printf("Root: %s\n", root);
    getDomain(domain, website,root);
    printf("Domain:%s\n", domain);
    get_main_server(result, domain, website_name, type);
}
