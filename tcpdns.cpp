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
#define CNZZ_SETNAME "CNZZ"

struct dns_packet_header
{
	uint16_t 	transaction_id;
	uint16_t  	flags;
	uint16_t  	num_queries;
	uint16_t 	answer_rrs;
	uint16_t 	authority_rrs;
	uint16_t  	additional_rrs;
} __attribute__( ( packed ) );

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
		if(strlen(line.c_str()) != 0 && line.at(0) != '#')
		{
			cout << "[" << line << "]" << endl;
			dhost.push_back(line);
		}else{
			cout << "<" << line << ">" << endl;
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
static unsigned int getNameLength( unsigned int i, const uint8_t* payload, unsigned int payloadLen )
{
	if ( payload[i] == 0x00 )
	{
		return ( 1 );
	}
	else if ( payload[i] == 0xC0 )
	{
		return ( 2 );
	}
	else
	{
		uint8_t len = payload[i];
		uint8_t off = len + 1;

		if ( off == 0 ) /* Bad packet */
		{
			return ( 0 );
		}
		else
		{
			return ( off + getNameLength( i + off, payload, payloadLen ) );
		}
	}
}

static uint16_t get16( int* i, const uint8_t* payload )
{
	uint16_t v = *( uint16_t* )&payload[*i];

	( *i ) += 2;

	return ( ntohs( v ) );
}

char domaions[][32] = {
"3rr3.co",
"295701.com",
"z4.cnzz.com",
"s95.cnzz.com",
"c.cnzz.com",
"icon.cnzz.com",
"cnzz.mmstat.com",
"cnzz.com"
};

uint16_t domaions_size = sizeof(domaions)/sizeof(domaions[0]);
static int check_domain(char *host)
{
	int i;
	if(!host) return 0;
	for(i = 0;  i < domaions_size; i++)
	{
		if(strcmp(host, domaions[i]) == 0)
			return 1;
	}
	return 0;
}

int do_cmd(char *cmd)
{
	printf("cmd: %s\n", cmd);
        return system(cmd);
}
static void dump_payload(uint8_t *data, uint16_t length)
{
#if 0
	int i;
	for (i = 0; i < length;i++)                         
	{                                                             
		printf("%02x%c", data[i], (i+1)%16==0?'\n':' ');  
	}
	printf("\n");
#endif
	int i = 0;
	char dns_name[256] = {0};
	char host[128] = {0};
#define NDPI_MAX_DNS_REQUESTS 16
	uint8_t is_query, ret_code, is_dns = 0;
	uint32_t a_record[NDPI_MAX_DNS_REQUESTS] = { 0 }, query_offset, num_a_records = 0;
	struct dns_packet_header header, *dns = ( struct dns_packet_header* )data;

	header.flags = ntohs( dns->flags );
	header.transaction_id = ntohs( dns->transaction_id );
	header.num_queries = ntohs( dns->num_queries );
	header.answer_rrs = ntohs( dns->answer_rrs );
	header.authority_rrs = ntohs( dns->authority_rrs );
	header.additional_rrs = ntohs( dns->additional_rrs );

	is_query = ( header.flags & 0x8000 ) ? 0 : 1;
	ret_code = is_query ? 0 : ( header.flags & 0x0F );

	i += sizeof( struct dns_packet_header );
	query_offset = i;
	if ( is_query ){
		printf( "DNS Request" );
		return;
	}else {
		printf( "DNS Reply" );
		if ( ( header.num_queries <= NDPI_MAX_DNS_REQUESTS ) /* Don't assume that num_queries must be zero */
				&& ( ( ( header.answer_rrs > 0 ) && ( header.answer_rrs <= NDPI_MAX_DNS_REQUESTS ) )
					|| ( ( header.authority_rrs > 0 ) && ( header.authority_rrs <= NDPI_MAX_DNS_REQUESTS ) )
					|| ( ( header.additional_rrs > 0 ) && ( header.additional_rrs <= NDPI_MAX_DNS_REQUESTS ) ) )
		   ){
			is_dns = 1;
			i++;
			if ( data[i] != '\0' )
			{
				while ( ( i < length ) && ( data[i] != '\0' ) )
				{
					i++;
				}

				i++;
			}
			i += 4;
			if ( header.answer_rrs > 0 ){
				uint16_t rsp_type , rsp_class;
				uint16_t num;

				for ( num = 0; num < header.answer_rrs; num++ )
				{
					uint16_t data_len;
					if ( ( i + 6 ) >= length )
					{
						break;
					}
					if ( ( data_len = getNameLength( i, ( const uint8_t* )data, length ) ) == 0 )
					{
						break;
					}else{
						i += data_len;
					}
					rsp_type = get16( &i, ( const uint8_t* )data );
					rsp_class = get16( &i, ( const uint8_t* )data );
					i += 4;

					data_len = get16( &i, ( const uint8_t* )data );
					if ( ( data_len <= 1 ) || ( data_len > ( length - i ) ) )
					{
						//fprintf( stderr, " data_len >length - i( %08X > %08X) break", data_len, length - i);
						break;
					}
					if ( rsp_type == 1 /* A */ )
					{
						if ( data_len == 4 )
						{

							u_int32_t v = ntohl( *( ( u_int32_t* )&data[i] ) );

							//fprintf( stderr, " v = %08X", v);

							if ( num_a_records < ( NDPI_MAX_DNS_REQUESTS - 1 ) )
							{
								a_record[num_a_records++] = v;
							}
							else
							{
								//fprintf( stderr, "One record is enough break");
								break;    /* One record is enough */
							}
						}
					}

					if ( data_len == 0 )
					{
						//fprintf( stderr, "data_len = %08X", data_len);
						break;
					}

					i += data_len;
				} /* for */
			} /* for ( num = 0; num < header.answer_rrs; num++ ) */

		}/* if(header.answer_rrs > 0)*/
	}

	if ( is_dns )
	{
		size_t j = 0;
		i = query_offset + 1;
		while ( ( i < length ) && ( j < ( sizeof( dns_name ) - 1 ) ) && ( data[i] != '\0' ) )
		{
			dns_name[j] = tolower( data[i] );

			if ( dns_name[j] < ' ' )
			{
				dns_name[j] = '.';
			}

			if( j < ( sizeof( host ) - 1 ))
				host[j] = dns_name[j];
			j++, i++;
		}

		if( j < ( sizeof( host ) - 1 ))
			host[j] = '\0';

		if ( a_record[0] != 0 )
		{
			char cmd[256];
			size_t i;
			printf("\n");
			for ( i = 0; i < num_a_records; i++ )
			{
				uint32_t tmp = ntohl(a_record[i]);	
				if(check_domain(host)){
					snprintf(cmd, sizeof(cmd)-1, "ipset -q add %s %s", CNZZ_SETNAME, inet_ntoa(*((struct in_addr *)&tmp)));
					do_cmd(cmd);
				}
				printf("%s:%s\n", host, inet_ntoa(*((struct in_addr *)&tmp)));
				
			}
		}

		i++;
	}	

}

void QueryDns(string server, int port, struct myarg* argument)
{
	int sock;
	struct sockaddr_in host;
	int received = 0;
	int data_len = 1024;
	char data[data_len];
	if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		printf("Tcp create socket failed!\n");
		return ;
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
		return;
	}
	unsigned char payload[512];
	payload[0]=(unsigned char)(argument->len >>8);
	payload[1]=(unsigned char)(argument->len);
	memcpy(payload+2, argument->data, argument->len);

	if(send(sock, payload, argument->len+2, 0) != argument->len+2) {
		printf("Tcp sent len failed!\n");
		close(sock);
		return ;
	}
	if((received = recv(sock, data, data_len, 0)) < 0) {
		printf("Tcp receive failed!%lu\n", pthread_self());
		close(sock);
		return ;
	}
	close(sock);
	// 校验
	dump_payload((uint8_t *)data+2, received -2);
	//printf("Tcp received %d bytes\n", received);
	int n = sendto(argument->sock, data+2, received-2, 0, (struct sockaddr *)&(argument->clientAddr), sizeof(argument->clientAddr));
	if (n < 0)
	{   
		printf("sendto error");
	} 
	return;
}
void QueryDnsUDP(string server, int port, struct myarg* argument)
{
	int s,len;  
	struct sockaddr_in addr;  
	socklen_t addr_len =sizeof(struct sockaddr_in);  
	char buffer[512];  
	/* 建立socket*/  
	if((s = socket(AF_INET,SOCK_DGRAM,0))<0){  
		perror("socket");  
		return; 
	}  
	/* 填写sockaddr_in*/  
	bzero(&addr,sizeof(addr));  
	addr.sin_family = AF_INET;  
	addr.sin_port = htons(port);  
	addr.sin_addr.s_addr = inet_addr(server.c_str());  
        
	if(sendto(s, argument->data, argument->len, 0, (struct sockaddr *)&addr,addr_len) != argument->len) {
                printf("UDP sent len failed!\n");
                close(s);
                return ;
        }
	
	if(( len = recvfrom(s, buffer,sizeof(buffer),0,(struct sockaddr *)&addr, &addr_len)) < 0){
		printf("UDP receive failed!%lu\n", pthread_self());
		close(s);
		return;
	}
	close(s);
        // 校验
	dump_payload((uint8_t *)buffer, len);

        //printf("Tcp received %d bytes\n", received);
        int n = sendto(argument->sock, buffer, len, 0, (struct sockaddr *)&(argument->clientAddr), sizeof(argument->clientAddr));
        if (n < 0)
        {
                printf("sendto error");
        }
	return ;
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
	//QueryDns(dhost[index], dport, argument);
	QueryDnsUDP(dhost[index], dport, argument);

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
	char cmd[1024];
	//do_cmd("iptables -t mangle -C OUTPUT  -m set --match-set "CNZZ_SETNAME" dst -j MARK --set-mark 100 || iptables -t mangle -I OUTPUT  -m set --match-set "CNZZ_SETNAME" dst -j MARK --set-mark 100");
	snprintf(cmd, sizeof(cmd), "ip rule sh |grep \"lookup 100\" |awk -F \":\t\" '{system(\"ip rule del \" $2)}'" );

	do_cmd(cmd);	

//do_cmd("ip rule add fwmark 100 lookup 100");

	cout << ">> Please wait program init...." << endl;
	ReadConf();
	cout << dhost.size()<< endl;
	CheckConf();
	cout << ">> set socket..." << endl;
	cout <<">> Now you can set dns server to 127.0.0.1" << endl;
	snprintf(cmd, sizeof(cmd), "ipset -q create %s hash:ip timeout 600", CNZZ_SETNAME);
	do_cmd(cmd);
	CreateServer("127.0.0.1",dport);
	return 0;
}
