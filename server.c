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
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <iostream>
#pragma warning(disable:4996)
using namespace std;
 
 // 定义数据
int s_fd; // 服务端套接字定义
int c_fd; // 客户端套接字定义
char readbuf[128]={'\0'}; // 存放接收数据的字符数组
struct sockaddr_in s_addr; // 服务端地址
struct sockaddr_in c_addr; // 客户端地址
char mode[2]={'\0'}; // 传输模式标志
char decry_flag[2]={'\0'}; // 解密标志位
char end_flag[4]={'/','E','n','d'}; // 传输结束标志位
char exit_flag[5]={'/','E','x','i','t'}; // 退出数据传输模式标志位
int i=0; // 计数位1
int count=0; // 计数位2
FILE *fp; // 文件位置
char filename[100]={'\0'}; // 文件名
char filename_write[100]={'\0'};
DES_cblock key="1234567"; // 密钥
DES_key_schedule key_schedule; // 解密用schedule
unsigned  char input[128]={'\0'}; // 加密输入/解密输出
size_t len_cry = (128 + 7) / 8 * 8; // 定义输出长度
DES_cblock ivec; // IV
char judge[5]={'\0'}; // 程序判别位
int judge_flag=0; // 判别结果储存
int encryd=0; // 解密使能位
int write_file_enable=0;
char save_file[2]={'\0'};

//功能函数
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

// 解密函数
void decry(void)
{
	DES_set_key(&key, &key_schedule); // 根据key产生schedule
	memset((char*)&ivec, 0, sizeof(ivec)); //设置IV为0x0000000000000000
	unsigned char* output = new unsigned char[len_cry + 1]; // 加密输出/解密输入
	memset(judge,0,sizeof(judge)); // 清空数组
	for(i=0;readbuf[i];i++)
	{
		output[i]=readbuf[i];
	} // 将读数组数据传递给解密输入
	//testing
	puts("test1:");
	printf("%s\n",readbuf);
	puts("test2:");
	printf("%s\n",output);
	memset(readbuf,0,sizeof(readbuf));
	DES_ncbc_encrypt(output, input, len_cry, &key_schedule, &ivec, 0); // 解密
	printf("解密结果：\n");
	for (i = 0; i<sizeof(input) ; i++)
	{
		readbuf[i]=input[i];
		if(i<5)
		judge[i]=readbuf[i];
	}
	judge_flag=judge_prog();
	if(judge_flag==0)
	printf("%s\n",readbuf); // 打印解密结果
}

int main(int argc,char** argv)
{
 
        if(argc !=3)
	{
                puts("调用格式不正确！\n"); // 调用格式出错时提示并退出
                exit(-1);
        }
        s_fd=socket(AF_INET,SOCK_STREAM,0); // 服务端套接字产生
        s_addr.sin_family=AF_INET; // IPV4
        s_addr.sin_port=htons(atoi(argv[2])); // 端口号
        s_addr.sin_addr.s_addr=inet_addr(argv[1]); // 服务端地址 
        bind(s_fd,(struct sockaddr *)&s_addr,sizeof(struct sockaddr_in)); // 地址绑定
        listen(s_fd,10); // 启用监听
        socklen_t len=sizeof(struct sockaddr_in); // 输入地址长度
        c_fd=accept(s_fd,(struct sockaddr *)&c_addr,&len); // 等待客户端连接，返回客户端套接字
        puts("connected successfully"); // 成功连接提示
        printf("clientIP:%s\n",inet_ntoa(c_addr.sin_addr)); // 打印客户端IP地址
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	printf("%s\n",readbuf); // 打印收到的信息
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	printf("%s\n",readbuf); // 打印收到的信息
	memset(readbuf,0,sizeof(readbuf));
        while(1)
	{
                read(c_fd,readbuf,sizeof(readbuf)); // 读操作
		if(readbuf[0]=='D'&&readbuf[1]=='\0')
		{
			write_file_enable=0;
			puts("当前工作在数据传输模式"); // 客户端单独传递D，指示数据传输模式
		}
		else if(readbuf[0]=='F'&&readbuf[1]=='\0')
		{
			write_file_enable=1;
			puts("当前工作在文件传输模式"); // 客户端单独传递F，指示数据传输模式
		}
		else if(readbuf[0]=='Y'&&readbuf[1]=='\0')
		{
			encryd=1; // 加密标志位置1，传递的是加密内容
			puts("加密传输"); // 提示用户当前加密传输
		} // 客户端单独传递Y，指示加密模式
		else if(readbuf[0]=='N'&&readbuf[1]=='\0')
		encryd=0; // 客户端单独传递N，指示无加密
		else if(judge_flag==-1)
	        {
	               	exit(-1);
                } // 客户端传递/End时退出程序
		else if(judge_flag==1)
		puts("退出数据传递模式");
		else if(encryd==1)
		{
			puts("是否解密（Y：是；N：否）：");
			scanf("%s",decry_flag);
			if(decry_flag[0]=='Y')
			{
				decry();
			} // 用户指定解密
			else
	                printf("%s\n",readbuf); // 打印收到的信息
			puts("是否保存到文件：");
			scanf("%s",save_file);
			if(save_file[0]=='Y')
			{
				puts("保存到文件：");
				scanf("%s", filename_write);
				if((fp = fopen(filename_write, "w")) == NULL)
				{
					printf("文件打开失败。\n");
				}
				else
				{
					fputs(readbuf,fp); 
					fclose(fp);
					puts("成功写入！");
				}
			}
		} // 加密模式下询问用户是否解密，并打印输出
		else
		{
			printf("%s\n",readbuf); // 无加密传输时，直接打印收到的信息
			puts("是否保存到文件：");
			scanf("%s",save_file);
			if(save_file[0]=='Y')
			{
				puts("保存到文件：");
				scanf("%s", filename_write);
				if((fp = fopen(filename_write, "w")) == NULL)
				{
					printf("文件打开失败。\n");
				}
				else
				{
					fputs(readbuf,fp); 
					fclose(fp);
					puts("成功写入！");
				}
			}
		}
                memset(readbuf,0,sizeof(readbuf)); // 清空数组
        }
 
        return 0;
}