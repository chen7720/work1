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
#include <openssl/md5.h>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <iostream>
#pragma warning(disable:4996)
using namespace std;

// 宏定义
#define     MD5_LENGTH           16
#define     MAX                  1024

 // 定义数据
int c_fd; // 客户端套接字定义
int n_write; // 写标志位
char readbuf[MAX]={'\0'};
char writebuf[MAX]={'\0'}; // 存放待传数据的字符数组
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
unsigned  char input[MAX]={'\0'}; // 加密输入/解密输出
size_t len = (sizeof(input) + 7) / 8 * 8; // 定义输出长度
unsigned char* output = new unsigned char[len + 1]; // 加密输出/解密输入
DES_cblock ivec; // IV
char judge[5]={'\0'}; // 程序判别位
int judge_flag=0; // 判别结果储存
char check_flag[128]={'\0'};
char check[2]={'\0'};
char data_store[MAX]={'\0'};

// 功能函数

int record_mess(void)
{
	FILE *fp_record = fopen("server_message.txt", "a+");
	if (fp_record==0) { printf("can't open file\n"); return 0;}
	fseek(fp_record, 0, SEEK_END);
	fwrite(readbuf, strlen(readbuf), 1, fp_record);
	fclose(fp_record);
	return 0;
}

// 加密函数
void encry(void)
{
	DES_set_key(&key, &key_schedule); // 根据key产生schedule
	memset((char*)&ivec, 0, sizeof(ivec)); //设置IV为0x0000000000000000
	memset(input,0,MAX); // 清空数组
	memset(output,0,MAX);
	memcpy(input,writebuf,MAX);
	DES_ncbc_encrypt(input, output, sizeof(input), &key_schedule, &ivec, DES_ENCRYPT); //加密
	printf("加密结果：\n");
	memset(writebuf,0,MAX);
	memcpy(writebuf,output,MAX);
	printf("%s\n",writebuf); // 打印加密输出
	memset((char*)&ivec, 0, sizeof(ivec)); //设置IV为0x0000000000000000
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
	memset(writebuf,0,MAX); // 清空数组
	memset(judge,0,sizeof(judge)); // 清空数组
	getchar();
        scanf("%[^\n]",writebuf); // 采集待传数据
	memset(data_store,0,sizeof(data_store));
	strcpy(data_store,writebuf);
	for(i=0;i<5;i++)
	{
		judge[i]=writebuf[i];
	} // 将采集到的前5位字符存入judge数组
	judge_flag=judge_prog();
	if((judge_flag==-1)||(judge_flag==1));
	else
	{
		if(cry_flag[0]=='Y')
		{
			encry();
		} // 用户选定加密传输时对数据进行加密
	}
	n_write=write(c_fd,writebuf,MAX); // 向server端发送数据
}
  
// 文件传递函数 
void filetran(void)
{
	int ch;
	char writestr[2]={'\0'};
 	puts("请输入待传文件路径："); //人机交互，提示输入文件路径
        scanf("%s",filename); // 采集文件路径
        if((fp=fopen(filename,"r"))==NULL)
	{
		while((fp=fopen(filename,"r"))==NULL)
		{
			puts("打开文件时出错"); // 找不到路径时提示
		 	puts("请输入待传文件路径："); //人机交互，提示输入文件路径
        		scanf("%s",filename); // 采集文件路径
		}
	}
	while ((ch = fgetc(fp)) != EOF)
	{
		writestr[0]=ch;
		strcat(writebuf,writestr);
	}
	fclose(fp);
	printf("%s",writebuf);
	strcpy(data_store,writebuf);
	if(cry_flag[0]=='Y')
	{
		encry();
	}
	n_write=write(c_fd,writebuf,sizeof(writebuf)); // 发送文件
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
	n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向server端发送数据
}
   
void hardware_tran_CPUID(void)
{
	unsigned int s1,s2;
	asm volatile
    	( "movl $0x01,%%eax ; \n\t"
      	"xorl %%edx,%%edx ;\n\t"
      	"cpuid ;\n\t"
      	"movl %%edx , %0;\n\t"
      	"movl %%eax , %1;\n\t"
      	:"=m"(s1),"=m"(s2)
    	);
    	char cpu_id[32] = {0};
    	sprintf(cpu_id, "CPUID:%08X-%08X\n", htonl(s2), htonl(s1));
	printf("%s",cpu_id);
	memset(writebuf,0,sizeof(writebuf));
	strcpy(writebuf,cpu_id);
	n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向server端发送数据
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
			printf("%s",writebuf);
			n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向server端发送数据
                } 
        }
}

void md5()
{
	MD5_CTX  ctx;
	char  data[MAX];
	unsigned char  md[MD5_LENGTH];
	char buf[MAX] = "";
	char tmp[3] = "";
	int q=0;
	strcpy(data,data_store);
	data[strlen(data)-1] = '\0';
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, strlen(data));
	MD5_Final(md, &ctx);
	for (q=0; q < MD5_LENGTH; q++)
	{
        sprintf(tmp, "%02X", md[q]);
        strcat(buf, tmp);
    	}
	printf("完整性验证序列: ");
	memset(check_flag,0,sizeof(check_flag));
	strcpy(check_flag,buf);
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
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作，读取输入帐号提示
		record_mess();
		puts(readbuf);
		memset(writebuf,0,sizeof(writebuf)); // 清空数组
		scanf("%s",writebuf);
		n_write=write(c_fd,writebuf,sizeof(writebuf)); // 写帐号
		memset(readbuf,0,sizeof(readbuf));
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作，读取密码
		record_mess();
		puts(readbuf);
		memset(readbuf,0,sizeof(readbuf));
		memset(writebuf,0,sizeof(writebuf)); // 清空数组
		scanf("%s",writebuf);
		n_write=write(c_fd,writebuf,sizeof(writebuf)); // 写密码
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作，读取反馈
		record_mess();
		puts(readbuf);
		if(strcmp(readbuf,"登录成功！")==0)
		break;
	}
	hardware_tran_opera();
	hardware_tran_CPUID();
	hardware_tran_mac();
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	record_mess();
	puts(readbuf);
	if(strcmp(readbuf,"您的硬件设备无接入权限！")==0)
	exit(-1);
 	while(1)
	{
 		puts("请选择传输模式（D：传数据；F：传文件；E：结束传输）：");
 		scanf("%s",mode); // 采集用户模式设置指令
		memset(writebuf,0,sizeof(writebuf)); // 清空数组
		writebuf[0]=mode[0];
		n_write=write(c_fd,writebuf,sizeof(writebuf)); // 告知服务端当前传递模式
		if(mode[0]!='E')
		{
			puts("请选择是否加密（Y：是；N：否）：");
			scanf("%s",cry_flag); // 采集用户加密指令
			memset(writebuf,0,sizeof(writebuf)); // 清空数组
			writebuf[0]=cry_flag[0];
			n_write=write(c_fd,writebuf,sizeof(writebuf)); // 告知服务端加密与否
		} // 非E指令下，用户选择是否加密传输，并传递给服务端
 		if(mode[0]=='D')
 		{
 			puts("当前工作在数据传输模式，输入“/Exit”以退出");
 			while(1)
			{
				memset(writebuf,0,sizeof(writebuf)); // 清空数组
        			datatran();
				if(judge_flag==-1)
				exit(-1); //结束程序运行
				if(judge_flag==1)
				break; // 退出当前模式
				memset(readbuf,0,sizeof(readbuf)); // 清空数组
				read(c_fd,readbuf,sizeof(readbuf)); // 读操作
				record_mess();
				if(strcmp(readbuf,"check")==0)
				{
					md5();
					memset(writebuf,0,sizeof(writebuf)); // 清空数组
					strcpy(writebuf,check_flag);
					n_write=write(c_fd,writebuf,sizeof(writebuf)); // 告知服务端
				}
        		}
        	} // 程序工作在数据传输模式
        	else if(mode[0]=='F')
        	{
        		puts("当前工作在文件传输模式");
        		while(1)
			{
				memset(writebuf,0,sizeof(writebuf)); // 清空数组
       				filetran();
				memset(readbuf,0,sizeof(readbuf)); // 清空数组
				read(c_fd,readbuf,sizeof(readbuf)); // 读操作
				record_mess();
				if(strcmp(readbuf,"check")==0)
				{
					md5();
					memset(writebuf,0,sizeof(writebuf)); // 清空数组
					strcpy(writebuf,check_flag);
					n_write=write(c_fd,writebuf,sizeof(writebuf)); // 告知服务端
				}
       				puts("请选择（C：继续传输文件；E：退出当前模式）：");
       				scanf("%s",half_opt);
       				if(half_opt[0]=='C'); // 继续传输文件
       				else
       				break; // 退出文件传输模式
        		}
        	} // 程序工作在文件传输模式
        	else
        	{
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
