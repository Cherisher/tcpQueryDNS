#ifndef __TCPDNS_H__
#define __TCPDNS_H__
typedef struct//报文head
{
    unsigned short id;
    unsigned short flags;
    unsigned short ques;
    unsigned short answer;
    unsigned short author;
    unsigned short addition;
}DNSHEAD,*pDNSHEAD;

typedef struct//报文的查询部分
{
    unsigned short type;
    unsigned short classin;
}SEARCH,*pSEARCH;
#endif
