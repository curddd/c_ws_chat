
//https://www.geeksforgeeks.org/socket-programming-in-cc-handling-multiple-clients-on-server-without-multi-threading/
//Example code: A simple server side code, which echos back the received message.
//Handle multiple socket connections with select and fd_set on Linux 
#include <stdio.h> 
#include <string.h>   //strlen 
#include <stdlib.h> 
#include <errno.h> 
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 

#include <regex.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <time.h>
#include "b64.c"

#define TRUE   1 
#define FALSE  0 
#define PORT 8888 
#define MSG_CHUNKS 65600
#define MAX_CLIENTS 1000


struct ws_conn{
	int fd;
	int hs_status;
    unsigned char *msg;
    int msg_fin;
    unsigned char first_byte;

    char *lastbottle;
};


int strpos(char *haystack, char *needle)
{
   char *p = strstr(haystack, needle);
   if (p)
      return p - haystack;
   return -1;
}

char* hash(char* in_string){
	char *GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	size_t naked_n = strlen(GUID) + strlen(in_string);

	char joined[naked_n+1];
	sprintf(joined, "%s%s", in_string, GUID);

	unsigned char sha_bytes[SHA_DIGEST_LENGTH];
	SHA1(joined,naked_n,sha_bytes);

	size_t b64_len = 0;
	char* b64_string;
	b64_string = base64_encode(sha_bytes,sizeof(sha_bytes),&b64_len);

	return b64_string;
}

void write_header(int fd, char* hash){
	
	char* first =
"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";

	char joined[strlen(first)+strlen(hash)+9];
	sprintf(joined,"%s%s\r\n\r\n",first,hash);
	send(fd, joined, strlen(joined),0);

}

int handle_handshake(int fd, char* header){
	regex_t regex;
	int reti;
	regmatch_t groupArr[2];
	char *regexHeader = "Sec-WebSocket-Key: ([^\r^\n.]*)";
	reti = regcomp(&regex, regexHeader, REG_EXTENDED);
	if(reti){
		puts("couldn't compile regex");
	}
	reti = regexec(&regex, header, 2, groupArr,0);

	if(!reti){
		
		char sourceCopy[strlen(header)+1];
		strcpy(sourceCopy, header); 
		sourceCopy[groupArr[1].rm_eo] = 0;
		char res[(groupArr[1].rm_eo-groupArr[1].rm_so)+1];
		strcpy(res,sourceCopy+groupArr[1].rm_so);
		
		char* handshake_b64;
		handshake_b64 = hash(res);	
		
		write_header(fd, handshake_b64);
		return 1;	
	}
	return 0;
}

void parse_inc_msg(struct ws_conn *client, char *buffer){
    unsigned char fin = 0;

    fin = (unsigned char)buffer[0] & 0x80;

    
    unsigned int opcode = buffer[0] & 0b00001111;

    if(opcode == 0x8){
        client->msg[0] = '\0';
        client->msg_fin = 1;
        return;
    }

    
    unsigned int mask_byte = 2;
    
    unsigned int len_byte = 1;
    unsigned int len = (unsigned int) buffer[len_byte] & 0b01111111;

    
    
    if(len<=125){
          printf("x %u x\n",len);
    }
    else if(len==126){
        puts("and here");
        len = ((unsigned int) buffer[len_byte+1] << 8) |  (unsigned int) buffer[len_byte+2];
        mask_byte = 4;
    }
    else{
        client->msg[0] = '\0';
        client->msg_fin = 1;
        return;
    }

    unsigned char mask[4];
    unsigned char byte[1];
    
    unsigned int msg_start = mask_byte+4;

    strncpy(mask, buffer+mask_byte, 4);
    //len = strlen(buffer+msg_start);
    
    int msg_offset = 0;
    /*
    if(!client->msg_fin){
        msg_offset = strlen(client->msg);
    }
    */
        
    int i =0;
    while(i<len){
        client->msg[i+msg_offset] = (unsigned char)((unsigned int)buffer[msg_start+i] ^ (unsigned int)mask[i % 4]);
        i++;
    }
    
    client->msg_fin = 1;
    client->msg[i+msg_offset] = '\0';
    return;
}

unsigned char *make_out_msg(unsigned char *msg){
    size_t msg_len = strlen(msg);
    unsigned char *out_msg = (unsigned char*) calloc(msg_len+5,sizeof(unsigned char));

    out_msg[0] = (unsigned char) 0b10000001;

    int msg_start = 2;

    if(msg_len<=125){
        out_msg[1] = (unsigned char) msg_len;    
    }
    else{
        out_msg[1] = (unsigned char) 126;
        out_msg[2] = (unsigned char) (msg_len >> (8*1)) & 0xff;
        out_msg[3] = (unsigned char) msg_len & 0xff;
        msg_start = 4;
    }

    strncpy(out_msg+msg_start, msg, msg_len);
    out_msg[msg_len+msg_start+1] = '\0';
    
    return out_msg;
}

void send_all(int client_id, struct ws_conn *clients, unsigned char *msg){
    
    unsigned char *out_msg;
    size_t msg_len = strlen(msg)+6;
    unsigned char *concat_msg = (unsigned char*) calloc(msg_len, sizeof(unsigned char));
    sprintf(concat_msg, "%d: %s",client_id, msg);
    msg_len = strlen(concat_msg);
    if(msg_len<=125){
        msg_len += 2;
    }
    else{
        msg_len += 4;
    }
    out_msg = make_out_msg(concat_msg);
    int j;
    for ( j = 0 ; j < MAX_CLIENTS ; j++)  
    {
        if((clients+j)->fd != 0){
            puts("sending");
            send((clients+j)->fd, out_msg, msg_len,0);
        }
    }
}

void send_one(int client_id, int client_fd, unsigned char *msg){
    unsigned char *out_msg;
    size_t msg_len = strlen(msg)+6;
    unsigned char *concat_msg = (unsigned char*) calloc(msg_len, sizeof(unsigned char));
    sprintf(concat_msg, "%d: %s",client_id, msg);
    msg_len = strlen(concat_msg);
    if(msg_len<=125){
        msg_len += 2;
    }
    else{
        msg_len += 4;
    }
    out_msg = make_out_msg(concat_msg);
    send(client_fd, out_msg, msg_len,0);
}
static char *rand_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK...";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}

char *read_file(char *path){
    FILE *fp;
    long lSize;
    char *buffer;

    puts("opening file");
    puts(path);
    fp = fopen ( path , "r" );
    if( !fp ) perror(path),exit(1);

    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );
    rewind( fp );

    /* allocate memory for entire content */
    buffer = calloc( 1, lSize+1 );
    if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);

    /* copy the file into the buffer */
    if( 1!=fread( buffer , lSize, 1 , fp) )
    fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);

    /* do your work here, buffer is a string contains the whole text */

    fclose(fp);
    

    puts(buffer);
    return buffer;

    
}

char *get_bottle(){
    char *storage = NULL;

	DIR* FD;
	struct dirent *bottle;
	struct dirent *in_file;
	const char *BOTTLE_DIR = "./bottles";
	FD = opendir(BOTTLE_DIR);
	char full_path[1024];

    int file_count = 0;
	while((in_file = readdir(FD))){
		if(!strcmp(in_file->d_name, "."))
			continue;
		if(!strcmp(in_file->d_name, ".."))
			continue;
        file_count++;
    }
    closedir(FD);

    printf("got files %d",file_count);
    char *no_bottles = "No bottles at this time...";

    if(file_count == 0){
        return storage;
    }

    int rand_file = rand() % file_count;
    storage = (char*) calloc(100,sizeof(char));
    int i = 0;
    FD = opendir(BOTTLE_DIR);
    while((in_file = readdir(FD))){
		if(!strcmp(in_file->d_name, "."))
			continue;
		if(!strcmp(in_file->d_name, ".."))
			continue;
        if(i == rand_file){
            sprintf(storage, "%s/%s", BOTTLE_DIR, in_file->d_name);
            break;
        }
        i++;
    }


    return storage;

}



char *store_bottle(char *msg){
    char bottle_name[11];
    rand_string(bottle_name,11);
    
    char bottle_path[999] = {'\0'};
    sprintf(bottle_path, "./bottles/%s",bottle_name);

    FILE *fp;
    fp = fopen(bottle_path, "w");
    fputs(msg,fp);
    fclose(fp);

    char *stored_success = "Bottle thrown...\0";

    return stored_success;

}

int main(int argc , char *argv[]){  
    int opt = TRUE;  
    int master_socket , addrlen , new_socket , 
             activity, i, j, valread , sd;  
    int max_sd;
    int connected = 0;  
    struct sockaddr_in address;  
    struct ws_conn clients[1000];
            
    char buffer[MSG_CHUNKS];  
    unsigned char *out_msg;

    fd_set readfds;  
            
    //bottles dir
    struct stat st = {0};
    if (stat("./bottles", &st) == -1) {
        mkdir("./bottles", 0700);
    }
    srand(time(NULL)); 
        
    //initialise all client_socket[] to 0 so not checked 
    for (i = 0; i < MAX_CLIENTS; i++){  
        clients[i].fd = 0;  
        clients[i].hs_status= 0;
        clients[i].msg = (unsigned char *) calloc(MSG_CHUNKS,sizeof(unsigned char));
    }  
            
    //create a master socket 
    if( (master_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0){  
        perror("socket failed");  
        exit(EXIT_FAILURE);  
    }  
        
    //set master socket to allow multiple connections , 
    //this is just a good habit, it will work without this 
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, 
            sizeof(opt)) < 0 )  
    {  
        perror("setsockopt");  
        exit(EXIT_FAILURE);  
    }  
        
    //type of socket created 
    address.sin_family = AF_INET;  
    address.sin_addr.s_addr = INADDR_ANY;  
    address.sin_port = htons( PORT );  
            
    //bind the socket to localhost port 8888 
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address))<0)  
    {  
        perror("bind failed");  
        exit(EXIT_FAILURE);  
    }  
    printf("Listener on port %d \n", PORT);  
            
    //try to specify maximum of 3 pending connections for the master socket 
    if (listen(master_socket, 30) < 0)  
    {  
        perror("listen");  
        exit(EXIT_FAILURE);  
    }  
            
    //accept the incoming connection 
    addrlen = sizeof(address);  
    puts("Waiting for connections ...");  
            
    while(TRUE)  
    {  
        //clear the socket set 
        FD_ZERO(&readfds);  
        
        //add master socket to set 
        FD_SET(master_socket, &readfds);  
        max_sd = master_socket;  
                
        //add child sockets to set 
        connected = 0;
        for ( i = 0 ; i < MAX_CLIENTS ; i++)  
        {  
            //socket descriptor 
            sd = clients[i].fd;  
                    
            //if valid socket descriptor then add to read list 
            if(sd > 0){
                FD_SET( sd , &readfds);  
                connected++;
            }
                
                    
            //highest file descriptor number, need it for the select function 
            if(sd > max_sd)  
                max_sd = sd;  
        }  
        
        //wait for an activity on one of the sockets , timeout is NULL , 
        //so wait indefinitely 
        printf("connected %d\n",connected);
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);  
        
        if ((activity < 0) && (errno!=EINTR))  
        {  
            printf("select error");  
        }  
                
        //If something happened on the master socket , 
        //then its an incoming connection 
        if (FD_ISSET(master_socket, &readfds))  
        {  
            if ((new_socket = accept(master_socket, 
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)  
            {  
                perror("accept");  
                exit(EXIT_FAILURE);  
            }  
                
            //inform user of socket number - used in send and receive commands 
            printf("New connection\n");
            
            
            

            //add new socket to array of sockets 
            for (i = 0; i < MAX_CLIENTS; i++)  
            {  
                //if position is empty 
                if( clients[i].fd  == 0 )  
                {  
                    clients[i].fd = new_socket;  
                    clients[i].hs_status = 0;
                    clients[i].lastbottle = NULL;    
                    printf("Adding to list of sockets as %d %d\n" , i, new_socket);  
                            
                    break;  
                }  
            }
            continue;  
        }  
                
        //else its some IO operation on some other socket
        for (i = 0; i < MAX_CLIENTS; i++)  
        {  
            sd = clients[i].fd;  
                    
            if (!FD_ISSET( sd , &readfds)){
                continue;
            }
            


            //Check if it was for closing , and also read the 
            //incoming message
            buffer[0] = '\0'; 
            valread = read(sd, buffer, MSG_CHUNKS);
            printf("valread %d %d\n",valread,sd);
            if(valread == 0)
            { 
                
                puts("disconnecting");
                //Somebody disconnected , get his details and print 
                getpeername(sd , (struct sockaddr*)&address, (socklen_t*)&addrlen);  
                /*
                printf("Host disconnected, ip %s, port %d \n" , 
                        inet_ntoa(address.sin_addr) , ntohs(address.sin_port));  
                */
                        
                //Close the socket and mark as 0 in list for reuse 
                close( sd );  
                clients[i].fd = 0;  
                clients[i].hs_status = 0;
                clients[i].lastbottle = NULL;  
                connected--;
                if(connected==1){
                    send_all(0, clients, "You are alone again");
                }
                
            }  
                    
            //Echo back the message that came in 
            else 
            {  
                
                //handshake
                if(clients[i].hs_status == 0){	
                    puts("handshake");
                    clients[i].hs_status = handle_handshake(sd, buffer);
                    if(connected <= 1){
                        send_all(0, clients, "You are alone");
                    }
                    else {
                        send_all(0, clients, "You are not alone");
                    }
                    
                    continue;

                }
                //msg 
                buffer[valread] = '\0';
                parse_inc_msg(&clients[i], buffer);
                if(strlen(clients[i].msg)!=0 && clients[i].msg_fin){
                    printf("%s\n",clients[i].msg);

                    if((strpos(clients[i].msg,"!throwbottle ") == 0)){
                        
                        send_one(0, clients[i].fd, store_bottle(clients[i].msg+13));
                    }
                    else if((strpos(clients[i].msg,"!getbottle") == 0)){
                        clients[i].lastbottle = get_bottle();
                        if(clients[i].lastbottle == NULL){
                            send_one(0, clients[i].fd, "No bottles at this time...");    
                            continue;
                        }
                        send_one(0, clients[i].fd, read_file(clients[i].lastbottle));
                    }
                    else if((strpos(clients[i].msg,"!throwback") == 0)){
                        if(clients[i].lastbottle == NULL){
                            send_one(0, clients[i].fd, "You don't have a bottle");
                            continue;
                        }
                        
                        clients[i].lastbottle = NULL;
                        send_one(0, clients[i].fd, "Bottle returned...");
                    }
                    else if((strpos(clients[i].msg,"!keep") == 0)){
                        if(clients[i].lastbottle == NULL){
                            send_one(0, clients[i].fd, "You don't have a bottle");
                            continue;
                        }
                        remove(clients[i].lastbottle);
                        clients[i].lastbottle = NULL;
                        send_one(0, clients[i].fd, "You keep the bottle");
                    }
                    else{
                        clients[i].lastbottle = NULL;
                        send_all(clients[i].fd, clients, clients[i].msg);
                    }
                    
                }

            }  
            buffer[0] = '\0';
        }  
    }  
            
    return 0;  
}  

