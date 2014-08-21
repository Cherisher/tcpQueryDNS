// File Name: tcpdns.cpp
// Author: Candoit
// Created Time: Tue 19 Aug 2014 09:25:13 CST
#include<iostream>
#include<string>
#include<cstring>
#include<algorithm>
#include<cstdlib>
#include<vector>
#include <fstream>
#include <ctime>
#include "tcpdns.h"
#define __LINUX__

#ifdef __LINUX__
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <arpa/inet.h>
#else
#include <windows.h>
#endif
using namespace std;

vector<string> dhost;
const unsigned int dport=53;
const int timeout=20;
char domain[255] = {'\0'};
pSEARCH p;

pthread_t ntid;

struct myarg {
    int len;
    int sock;
    struct sockaddr_in clientAddr;
    unsigned char *data;
};

void trim(string &str)
{
    str.erase(str.begin(), str.begin()+str.find_first_not_of(' '));
    str.erase(str.begin()+str.find_last_not_of(' ')+1, str.end());
}

void ReadConf()
{
    ifstream fin("tcpdns.conf");
    if(!fin)
    {
        cerr << "Error: Can't open configure file [tcpdns.conf]" << endl;
        exit(-1);
    }
    string line;
    while(getline(fin, line))
    {
        trim(line);
        if(strlen(line.c_str()) !=0)
        {
            cout << "[" << line << "]" << endl;
            dhost.push_back(line);
        }
    }
}
void CheckConf()
{
    vector<string>::iterator iter = dhost.begin();
    while(iter != dhost.end())
    {

        cout <<"["<< *iter++  << "]"<< endl;
    }
}

void bytetodomain(unsigned char *data, int len)
{
    memset(domain, '\0', sizeof(domain));
    int i = 12;
    int j = 0;
    int length = 0;
    length = static_cast<int>(data[i]);
    while (length !=0)
    {
        i += 1;
        int k;
        for(k=0; k < length;k++)
        {
            sprintf(&domain[j],"%c",data[i]);
            i++;
            j++;
        }
        length = static_cast<int>(data[i]);
        if (length != 0)
        {
            sprintf(&domain[j],"%c", '.');
            j++;
        }
    }
    p=(pSEARCH)(data+i+1);
}

unsigned char* QueryDns(string server, int port, struct myarg* argument)
{
    int sock;
    struct sockaddr_in host;
    int received = 0;
    int data_len = 1024;
    char data[data_len];
    if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        printf("Tcp1SocketCollectdata create socket failed!\n");
        return 0;
    }
    struct timeval tv;
    tv.tv_sec = 5; /* 3 Secs Timeout */
    tv.tv_usec = 0; // Not init'ing this can cause strange errors

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    /* Construct the server sockaddr_in structure */
    memset(&host, 0, sizeof(host)); /* Clear struct */
    host.sin_family = AF_INET; /* Internet/IP */
    host.sin_addr.s_addr = inet_addr(server.c_str()); /* IP address */
    host.sin_port = htons(port); /* server port */

    if(connect(sock, (struct sockaddr *) &host, sizeof(host)) < 0)
    {
        printf("Tcp connect socket failed!\n");
        close(sock);
        return NULL;
    }
    unsigned char payload[512];
    payload[0]=(unsigned char)(argument->len >>8);
    payload[1]=(unsigned char)(argument->len);
    memcpy(payload+2, argument->data, argument->len);
    /* 
       for (int i = 0; i< argument->len+2;i++)                         
       {                                                             
       printf("%02x%c",payload[i],(i+1)%16==0?'\n':' ');  
       }
       printf("\n");
       return NULL; 
       */
    if(send(sock, payload, argument->len+2, 0) != argument->len+2) {
        printf("Tcp sent len failed!\n");
        close(sock);
        return NULL;
    }
    if((received = recv(sock, data, data_len, 0)) < 0) {
        printf("Tcp receive failed!%lu\n", pthread_self());
        close(sock);
        return NULL;
    }
    // 校验

    //printf("Tcp received %d bytes\n", received);
    int n = sendto(argument->sock, data+2, received-2, 0, (struct sockaddr *)&(argument->clientAddr), sizeof(argument->clientAddr));
    if (n < 0)
    {   
        printf("sendto error");
    }   
    close(sock);
    return NULL;
}

void * transfer(void *argv)
{
    //    printf("%s(%d)\n", __FUNCTION__, __LINE__);
    struct myarg *argument = (struct myarg*)argv;
    if(!argument->data)
        return ( (void*)-1); ;
    bytetodomain(argument->data, argument->len);
    printf("domain:%s, qtype:%04x, ",domain,ntohs(p->type));
    srand(time(NULL));
    int index = rand() % (dhost.size());
    printf("dhost[%d]:%s\n", index, dhost[index].c_str());
    QueryDns(dhost[index], dport, argument);
    return ( (void*)100); 
}
void CreateServer(string host, unsigned int port)
{
    int ret;
    struct myarg argument;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int sock;
    if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(1);
    }
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(1);
    }
    unsigned char buff[512];
    struct sockaddr_in clientAddr;
    int n;
    socklen_t len = sizeof(clientAddr);
    while (1)
    {
        n = recvfrom(sock, buff, 511, 0, (struct sockaddr*)&clientAddr, &len);
        if (n>0)
        {
            buff[n] = 0;
            argument.len = n;
            argument.clientAddr = clientAddr;
            argument.sock = sock;
            argument.data = buff;
            printf("%s %u querey %d\n", inet_ntoa(argument.clientAddr.sin_addr),ntohs(argument.clientAddr.sin_port), argument.len);

            ret = pthread_create(&ntid, NULL, transfer, &argument);
            if (0 != ret)
            {
                printf("Can't create thread:%s\n",strerror(ret));
            }
        }
        else
        {
            perror("recv");
            break;
        }
    }
}
int main(){
    cout << ">> Please wait program init...." << endl;
    ReadConf();
    cout << dhost.size()<< endl;
    CheckConf();
    cout << ">> set socket..." << endl;
    CreateServer("127.0.0.1",dport);
    cout <<">> Now you can set dns server to 127.0.0.1" << endl;
    return 0;
}
