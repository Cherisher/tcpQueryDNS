#How to use this program ?
###1. 设置DNS电脑服务器

> * vi /etc/resolve.conf
> * nameserver 127.0.0.1

###2. 设置DNS服务器的IP地址，每行一个

> * vim tcpdns.conf
> * 8.8.8.8
> * 8.8.4.4
   
###3. run make && ./tcpdns


#Next Version TODO:

> 1. 匹配特定的域名用tcpQueryDNS, 支持正则表达式
> 2. 优化程序结构
> 3. 支持windows平台
