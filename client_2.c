#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/des.h>
#include "openssl/evp.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <md5.h>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <iostream>
#pragma warning(disable:4996)
using namespace std;
 
 // 定义数据
int c_fd; // 客户端套接字定义
int n_write; // 写标志位
char readbuf[128]={'\0'};
char writebuf[128]={'\0'}; // 存放待传数据的字符数组
char mode[2]={'\0'}; // 传输模式标志
char half_opt[2]={'\0'}; // 文件传输内标志位
char cry_flag[2]={'\0'}; // 加密标志位
struct sockaddr_in s_addr; // 服务端地址
char end_flag[4]={'/','E','n','d'}; // 传输结束标志位
char exit_flag[5]={'/','E','x','i','t'}; // 退出数据传输模式标志位
int i=0; // 计数位1
int count=0; // 计数位2
FILE *fp; // 文件位置
char filename[100]={'\0'}; // 文件名
DES_cblock key="1234567"; // 密钥
DES_key_schedule key_schedule; // 加密用schedule
unsigned  char input[128]={'\0'}; // 加密输入/解密输出
size_t len = (sizeof(input) + 7) / 8 * 8; // 定义输出长度
unsigned char* output = new unsigned char[len + 1]; // 加密输出/解密输入
DES_cblock ivec; // IV
char judge[5]={'\0'}; // 程序判别位
int judge_flag=0; // 判别结果储存
char check_flag[128]={'\0'};
char check[2]={'\0'};
char data_store[128]={'\0'};

// 功能函数

// 加密函数
void encry(void)
{
	DES_set_key(&key, &key_schedule); // 根据key产生schedule
	memset((char*)&ivec, 0, sizeof(ivec)); //设置IV为0x0000000000000000
	memset(input,0,sizeof(input)); // 清空数组
	memset(output,0,sizeof(output));
	for(i=0;i<sizeof(writebuf);i++)
	{
		input[i]=writebuf[i];
	} // 将写数组数据传递给加密输入
	DES_ncbc_encrypt(input, output, sizeof(input), &key_schedule, &ivec, DES_ENCRYPT); //加密
	printf("加密结果：\n");
	memset(writebuf,0,sizeof(writebuf));
	for (int i = 0; output[i] ; i++)
	{
		writebuf[i]=output[i];
		printf("%c",output[i]);
	}
	printf("\n"); // 打印加密输出
	memset((char*)&ivec, 0, sizeof(ivec)); //设置IV为0x0000000000000000
	//testing
	puts("test1:");
	printf("%s\n",writebuf);
	puts("test2:");
	printf("%s\n",output);
	//解密
	DES_ncbc_encrypt(output, input, len, &key_schedule, &ivec, 0);
	cout << "解密：" << input << endl;;
}

// 模式判别
int judge_prog(void)
{
	count = 0;
	for(i=0;i<4;i++)
        {
        	if(end_flag[i]==judge[i])
        	{
        		count++;
        	}
        	else
        	break;
        }
        if(count==4)
        {
        	return -1;
        }
	count = 0;
	for(i=0;i<5;i++)
        {
        	if(exit_flag[i]==judge[i])
        	{
        		count++;
        	}
        	else
        	break;
        }
        if(count==5)
        {
        	return 1;
        }
	return 0;
}

// 数据传递函数
void datatran(void)
{
        puts("请输入待传数据（输入‘/End’将退出程序）："); // 人机交互提示
	memset(writebuf,0,sizeof(writebuf)); // 清空数组
	memset(judge,0,sizeof(judge)); // 清空数组
	getchar();
        scanf("%[^\n]",writebuf); // 采集待传数据
	memset(data_store,0,sizeof(data_store));
	strcpy(data_store,writebuf);
	for(i=0;i<5;i++)
	{
		judge[i]=writebuf[i];
	} // 将采集到的前5位字符存入judge数组
	if(cry_flag[0]=='Y')
	{
		encry();
	} // 用户选定加密传输时对数据进行加密
	judge_flag=judge_prog();
	n_write=write(c_fd,writebuf,strlen(writebuf)); // 向server端发送数据
}
  
// 文件传递函数 
void filetran(void)
{
	int ch;
	char writestr[2]={'\0'};
 	puts("请输入待传文件路径："); //人机交互，提示输入文件路径
        scanf("%s",filename); // 采集文件路径
        if((fp=fopen(filename,"r"))==NULL)
        puts("打开文件时出错"); // 找不到路径时提示
        else
        {
		while ((ch = fgetc(fp)) != EOF)
		{
			writestr[0]=ch;
			strcat(writebuf,writestr);
		}
		fclose(fp);
		printf("%s",writebuf);
		if(cry_flag[0]=='Y')
		{
			encry();
		}
		n_write=write(c_fd,writebuf,strlen(writebuf)); // 发送文件
	}
}

void hardware_tran_opera(void)
{
	struct utsname uts;
	if (uname(&uts) == -1) 
	{
        	perror("uname error");
        	exit(-1);
    	}
	memset(writebuf,0,sizeof(writebuf));
	sprintf(writebuf,"Operating system: %s %s %s\n", uts.sysname, uts.release, uts.version);
   	printf("Operating system: %s %s %s\n", uts.sysname, uts.release, uts.version);
	n_write=write(c_fd,writebuf,strlen(writebuf)); // 向server端发送数据
}
   
void hardware_tran_mac(void)
{
        int sock, if_count, i;
        struct ifconf ifc;
        struct ifreq ifr[10];
        unsigned char mac[6];

        memset(&ifc, 0, sizeof(struct ifconf));

        sock = socket(AF_INET, SOCK_DGRAM, 0);

        ifc.ifc_len = 10 * sizeof(struct ifreq);
        ifc.ifc_buf = (char *)ifr;
        //获取所有网卡信息
        ioctl(sock, SIOCGIFCONF, (char *)&ifc);

        if_count = ifc.ifc_len / (sizeof(struct ifreq));
        for (i = 0; i < if_count; i++) 
	{        
                if (ioctl(sock, SIOCGIFHWADDR, &ifr[i]) == 0) 
		{  
                        memcpy(mac, ifr[i].ifr_hwaddr.sa_data, 6);
			memset(writebuf,0,sizeof(writebuf));
                        sprintf(writebuf,"eth: %s, mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ifr[i].ifr_name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			puts(writebuf);
			n_write=write(c_fd,writebuf,strlen(writebuf)); // 向server端发送数据
                } 
        }
}

unsigned char PADDING[] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void MD5Init(MD5_CTX *context)
{
    context->count[0] = 0;
    context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}

void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen)
{
    unsigned int i = 0, index = 0, partlen = 0;
    index = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - index;
    context->count[0] += inputlen << 3;
    if(context->count[0] < (inputlen << 3)) {
        context->count[1]++;
    }
    context->count[1] += inputlen >> 29;
    if(inputlen >= partlen) {
        memcpy(&context->buffer[index], input, partlen);
        MD5Transform(context->state, context->buffer);
        for(i = partlen; i + 64 <= inputlen; i += 64) {
            MD5Transform(context->state, &input[i]);
        }
        index = 0;
    }
    else {
        i = 0;
    }
    memcpy(&context->buffer[index], &input[i], inputlen - i);
}

void MD5Final(MD5_CTX *context, unsigned char digest[16])
{
    unsigned int index = 0, padlen = 0;
    unsigned char bits[8];
    index = (context->count[0] >> 3) & 0x3F;
    padlen = (index < 56) ? (56 - index) : (120 - index);
    MD5Encode(bits, context->count, 8);
    MD5Update(context, PADDING, padlen);
    MD5Update(context, bits, 8);
    MD5Encode(digest, context->state, 16);
}

void MD5Encode(unsigned char *output, unsigned int *input, unsigned int len)
{
    unsigned int i = 0, j = 0;
    while(j < len) {
        output[j] = input[i] & 0xFF;
        output[j + 1] = (input[i] >> 8) & 0xFF;
        output[j + 2] = (input[i] >> 16) & 0xFF;
        output[j + 3] = (input[i] >> 24) & 0xFF;
        i++;
        j += 4;
    }
}

void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len)
{
    unsigned int i = 0, j = 0;
    while(j < len) {
        output[i] = (input[j]) |
                    (input[j + 1] << 8) |
                    (input[j + 2] << 16) |
                    (input[j + 3] << 24);
        i++;
        j += 4;
    }
}

void MD5Transform(unsigned int state[4], unsigned char block[64])
{
    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int x[64];
    MD5Decode(x, block, 64);
    FF(a, b, c, d, x[0], 7, 0xd76aa478);    // 1
    FF(d, a, b, c, x[1], 12, 0xe8c7b756);   // 2
    FF(c, d, a, b, x[2], 17, 0x242070db);   // 3
    FF(b, c, d, a, x[3], 22, 0xc1bdceee);   // 4
    FF(a, b, c, d, x[4], 7, 0xf57c0faf);    // 5
    FF(d, a, b, c, x[5], 12, 0x4787c62a);   // 6
    FF(c, d, a, b, x[6], 17, 0xa8304613);   // 7
    FF(b, c, d, a, x[7], 22, 0xfd469501);   // 8
    FF(a, b, c, d, x[8], 7, 0x698098d8);    // 9
    FF(d, a, b, c, x[9], 12, 0x8b44f7af);   // 10
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);  // 11
    FF(b, c, d, a, x[11], 22, 0x895cd7be);  // 12
    FF(a, b, c, d, x[12], 7, 0x6b901122);   // 13
    FF(d, a, b, c, x[13], 12, 0xfd987193);  // 14
    FF(c, d, a, b, x[14], 17, 0xa679438e);  // 15
    FF(b, c, d, a, x[15], 22, 0x49b40821);  // 16

    GG(a, b, c, d, x[1], 5, 0xf61e2562);    // 17
    GG(d, a, b, c, x[6], 9, 0xc040b340);    // 18
    GG(c, d, a, b, x[11], 14, 0x265e5a51);  // 19
    GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);   // 20
    GG(a, b, c, d, x[5], 5, 0xd62f105d);    // 21
    GG(d, a, b, c, x[10], 9, 0x2441453);    // 22
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);  // 23
    GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);   // 24
    GG(a, b, c, d, x[9], 5, 0x21e1cde6);    // 25
    GG(d, a, b, c, x[14], 9, 0xc33707d6);   // 26
    GG(c, d, a, b, x[3], 14, 0xf4d50d87);   // 27
    GG(b, c, d, a, x[8], 20, 0x455a14ed);   // 28
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);   // 29
    GG(d, a, b, c, x[2], 9, 0xfcefa3f8);    // 30
    GG(c, d, a, b, x[7], 14, 0x676f02d9);   // 31
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);  // 32

    HH(a, b, c, d, x[5], 4, 0xfffa3942);    // 33
    HH(d, a, b, c, x[8], 11, 0x8771f681);   // 34
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);  // 35
    HH(b, c, d, a, x[14], 23, 0xfde5380c);  // 36
    HH(a, b, c, d, x[1], 4, 0xa4beea44);    // 37
    HH(d, a, b, c, x[4], 11, 0x4bdecfa9);   // 38
    HH(c, d, a, b, x[7], 16, 0xf6bb4b60);   // 39
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);  // 40
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);   // 41
    HH(d, a, b, c, x[0], 11, 0xeaa127fa);   // 42
    HH(c, d, a, b, x[3], 16, 0xd4ef3085);   // 43
    HH(b, c, d, a, x[6], 23, 0x4881d05);    // 44
    HH(a, b, c, d, x[9], 4, 0xd9d4d039);    // 45
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);  // 46
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);  // 47
    HH(b, c, d, a, x[2], 23, 0xc4ac5665);   // 48

    II(a, b, c, d, x[0], 6, 0xf4292244);    // 49
    II(d, a, b, c, x[7], 10, 0x432aff97);   // 50
    II(c, d, a, b, x[14], 15, 0xab9423a7);  // 51
    II(b, c, d, a, x[5], 21, 0xfc93a039);   // 52
    II(a, b, c, d, x[12], 6, 0x655b59c3);   // 53
    II(d, a, b, c, x[3], 10, 0x8f0ccc92);   // 54
    II(c, d, a, b, x[10], 15, 0xffeff47d);  // 55
    II(b, c, d, a, x[1], 21, 0x85845dd1);   // 56
    II(a, b, c, d, x[8], 6, 0x6fa87e4f);    // 57
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);  // 58
    II(c, d, a, b, x[6], 15, 0xa3014314);   // 59
    II(b, c, d, a, x[13], 21, 0x4e0811a1);  // 60
    II(a, b, c, d, x[4], 6, 0xf7537e82);    // 61
    II(d, a, b, c, x[11], 10, 0xbd3af235);  // 62
    II(c, d, a, b, x[2], 15, 0x2ad7d2bb);   // 63
    II(b, c, d, a, x[9], 21, 0xeb86d391);   // 64

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

int md5()
{
    //字符串加密
    int q;
    //unsigned char encrypt[] = "admin"; //21232f297a57a5a743894a0e4a801fc3
    unsigned char encrypt[128]={'\0'};
	for(q=0;data_store[q];q++)
	{
		encrypt[q]=data_store[q];
	} 
    unsigned char decrypt[16];
    MD5_CTX md5;
    MD5Init(&md5);
    MD5Update(&md5, encrypt, strlen((char *)encrypt));
    MD5Final(&md5, decrypt);
    printf("加密前: %s\n加密后: ", encrypt);
    for(q=0; q<16; q++) {
        printf("%02x", decrypt[q]);
    }
    printf("\n");
	memset(check_flag,0,sizeof(check_flag));
sprintf(check_flag,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",decrypt[0],decrypt[1],decrypt[2],decrypt[3],decrypt[4],decrypt[5],decrypt[6],decrypt[7],decrypt[8],decrypt[9],decrypt[10],decrypt[11],decrypt[12],decrypt[13],decrypt[14],decrypt[15]);
	printf("%s\n",check_flag);
}

int main(int argc,char** argv)
{
 
        if(argc!=3)
	{
                printf("调用格式不正确！\n"); // 调用格式出错时提示并退出
                exit(-1);
        }
        c_fd=socket(AF_INET ,SOCK_STREAM,0); // 客户端套接字产生
        if(c_fd==-1)
	{
                perror("socket"); // 套接字产生失败时报错
        }
        s_addr.sin_family=AF_INET; // IPV4
        s_addr.sin_port=htons(atoi(argv[2])); // 端口
        s_addr.sin_addr.s_addr=inet_addr(argv[1]); // 服务端地址
        if(connect(c_fd,(struct sockaddr *)&s_addr,sizeof(struct sockaddr_in))==-1)
	{
                perror("connect"); // 连接失败时报错
        }
	while(1)
	{
		memset(readbuf,0,sizeof(readbuf));
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作
		puts(readbuf);
		memset(writebuf,0,sizeof(writebuf)); // 清空数组
		scanf("%s",writebuf);
		n_write=write(c_fd,writebuf,strlen(writebuf));
		memset(readbuf,0,sizeof(readbuf));
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作
		puts(readbuf);
		memset(writebuf,0,sizeof(writebuf)); // 清空数组
		scanf("%s",writebuf);
		n_write=write(c_fd,writebuf,strlen(writebuf));
		memset(readbuf,0,sizeof(readbuf));
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作
		puts(readbuf);
		if(strcmp(readbuf,"登录成功！")==0)
		break;
	}
	hardware_tran_opera();
	hardware_tran_mac();
 	while(1)
	{
 		puts("请选择传输模式（D：传数据；F：传文件；E：结束传输）：");
 		scanf("%s",mode); // 采集用户模式设置指令
		memset(writebuf,0,sizeof(writebuf)); // 清空数组
		writebuf[0]=mode[0];
		n_write=write(c_fd,writebuf,strlen(writebuf)); // 告知服务端当前传递模式
		if(mode[0]!='E')
		{
			puts("请选择是否加密（Y：是；N：否）：");
			scanf("%s",cry_flag); // 采集用户加密指令
			memset(writebuf,0,sizeof(writebuf)); // 清空数组
			writebuf[0]=cry_flag[0];
			n_write=write(c_fd,writebuf,strlen(writebuf)); // 告知服务端加密与否
		} // 非E指令下，用户选择是否加密传输，并传递给服务端
 		if(mode[0]=='D')
 		{
 			puts("当前工作在数据传输模式，输入“/Exit”以退出");
 			while(1)
			{
				memset(writebuf,0,sizeof(writebuf)); // 清空数组
        			datatran();
				memset(readbuf,0,sizeof(readbuf)); // 清空数组
				read(c_fd,readbuf,sizeof(readbuf)); // 读操作
				if(strcmp(readbuf,"check")==0)
				{
					md5();
					memset(writebuf,0,sizeof(writebuf)); // 清空数组
					strcpy(writebuf,check_flag);
					puts("test:");
					puts(writebuf);
					n_write=write(c_fd,writebuf,strlen(writebuf)); // 告知服务端
				}
				if(judge_flag==-1)
				exit(-1); //结束程序运行
				if(judge_flag==1)
				break; // 退出当前模式
        		}
        	} // 程序工作在数据传输模式
        	else if(mode[0]=='F')
        	{
        		puts("当前工作在文件传输模式");
        		while(1)
			{
				memset(writebuf,0,sizeof(writebuf)); // 清空数组
       				filetran();
       				puts("请选择（C：继续传输文件；E：退出当前模式）：");
       				scanf("%s",half_opt);
       				if(half_opt[0]=='C'); // 继续传输文件
       				else
       				break; // 退出文件传输模式
        		}
        	} // 程序工作在文件传输模式
        	else
        	{
			memset(writebuf,0,sizeof(writebuf)); // 清空数组
			writebuf[0]='/';
		        writebuf[1]='E';
        		writebuf[2]='n';
        		writebuf[3]='d';
        		n_write=write(c_fd,writebuf,strlen(writebuf)); // 告知服务端终止运行
        		exit(-1); // 终止客户端程序
        	} // 其他情况，包括E模式与错误指令输入
        	if(n_write==-1)
		{
		        puts("write failed"); // 发送失败报错
		        exit(-1);
        	}
        	memset(writebuf,0,sizeof(writebuf)); // 清空数组
	}
        return 0;
}