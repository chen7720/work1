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
int s_fd; // 服务端套接字定义
int c_fd; // 客户端套接字定义
char readbuf[MAX]={'\0'}; // 存放接收数据的字符数组
char writebuf[MAX]={'\0'}; // 存放待传数据的字符数组
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
unsigned  char input[MAX]={'\0'}; // 加密输入/解密输出
size_t len_cry = (MAX + 7) / 8 * 8; // 定义输出长度
DES_cblock ivec; // IV
char judge[5]={'\0'}; // 程序判别位
int judge_flag=0; // 判别结果储存
int encryd=0; // 解密使能位
int write_file_enable=0;
char save_file[2]={'\0'};
int n_write; // 写标志位
char check_flag[128]={'\0'};
char check[2]={'\0'};
char data_store[MAX]={'\0'};
int count_en=0;

//功能函数

int record_mess(void)
{
	FILE *fp_record = fopen("client_message.txt", "a+");
	if (fp_record==0) { printf("can't open file\n"); return 0;}
	fseek(fp_record, 0, SEEK_END);
	fwrite(readbuf, strlen(readbuf), 1, fp_record);
	fclose(fp_record);
	return 0;
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

// 解密函数
void decry(void)
{
	DES_set_key(&key, &key_schedule); // 根据key产生schedule
	memset((char*)&ivec, 0, sizeof(ivec)); //设置IV为0x0000000000000000
	unsigned char* output = new unsigned char[len_cry + 1]; // 加密输出/解密输入
	memset(judge,0,sizeof(judge)); // 清空数组
	for(i=0;i<5;i++)
	{
		judge[i]=readbuf[i];
	} // 将读数组数据传递给解密输入
	memcpy(output,readbuf,MAX);
	memset(readbuf,0,sizeof(readbuf));
	DES_ncbc_encrypt(output, input, len_cry, &key_schedule, &ivec, 0); // 解密
	memcpy(readbuf,input,MAX);
	judge_flag=judge_prog();
	if((judge_flag==-1)||(judge_flag==1));
	else
	{
		printf("解密结果：\n");
		printf("%s\n",readbuf); // 打印解密结果
		record_mess();
	}
	memset(data_store,0,sizeof(data_store));
	strcpy(data_store,readbuf);
}

void decry_for_check(void)
{
	DES_set_key(&key, &key_schedule); // 根据key产生schedule
	memset((char*)&ivec, 0, sizeof(ivec)); //设置IV为0x0000000000000000
	unsigned char* output = new unsigned char[len_cry + 1]; // 加密输出/解密输入
	memset(judge,0,sizeof(judge)); // 清空数组
	memcpy(output,readbuf,MAX);
	memset(readbuf,0,sizeof(readbuf));
	DES_ncbc_encrypt(output, input, len_cry, &key_schedule, &ivec, 0); // 解密
	memcpy(readbuf,input,MAX);
	memset(data_store,0,sizeof(data_store));
	strcpy(data_store,readbuf);
}

int login(void)
{
	//char admin[10]={'a','d','m','i','n'};
	//char admin_key[10]={'2','0','0','2','0','9'};
	char user[5][10]={{'1','0','0','8','6'},{'3','0','0','1','8','8'},{'0','5','9','9'},{'1','5','2','5','9','2'},{'1','8','3','5','0','9'}};
	char key[5][10]={{'0','0','0','0','0','0'},{'1','1','1','1','1','1'}};
	char login_user[10]={'\0'};
	char login_key[10]={'\0'};
	char user_temp[10]={'\0'};
	char key_temp[10]={'\0'};
	int m=0;
	int n=0;
	int user_flag=0;
	int key_flag=0;
	memset(writebuf,0,sizeof(writebuf));
	strcpy(writebuf,"请输入账号：");
	n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	record_mess();
	strcpy(login_user,readbuf);
	memset(writebuf,0,sizeof(writebuf));
	strcpy(writebuf,"请输入密码：");
	n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	record_mess();
	strcpy(login_key,readbuf);
	for(m=0;m<5;m++)
	{
		for(n=0;n<10;n++)
		{
			user_temp[n]=user[m][n];
			key_temp[n]=key[m][n];
		}
		if(strcmp(user_temp,login_user)==0)
		{
			user_flag=1;
			if(strcmp(key_temp,login_key)==0)
			{
				memset(writebuf,0,sizeof(writebuf));
				strcpy(writebuf,"登录成功！"); 
				n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
				key_flag=1;
				return 1;
			}
			else
			{
				memset(writebuf,0,sizeof(writebuf));
				strcpy(writebuf,"错误的密码！");
				n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
				return 0;
			}
		}
		else
		{
			user_flag=0;
		}
	 } 
	if(user_flag==0)
	{
		memset(writebuf,0,sizeof(writebuf));
		strcpy(writebuf,"错误的账号！");
		n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
	}
	return 0;
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
        //puts("connected successfully"); // 成功连接提示
        printf("clientIP:%s\n",inet_ntoa(c_addr.sin_addr)); // 打印客户端IP地址
	int login_flag=0;
	int login_count=0;
	puts("客户端登录中……");
	while(1)
	{
		login_flag=login();
		if(login_flag==1)
		break;
		else
		login_count++;
		if(login_count==3)
		{
			puts("登录失败，已锁定");
			memset(writebuf,0,sizeof(writebuf));
			strcpy(writebuf,"登录失败，已锁定");
			n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
			exit(-1);
		}
	}
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	record_mess();
	printf("%s",readbuf); // 打印收到的信息
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	record_mess();
	printf("%s",readbuf); // 打印收到的信息
	if(strcmp(readbuf,"CPUID:810F8100-FFFB8B07\n")==0)
	{
		memset(readbuf,0,sizeof(readbuf));
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作
		record_mess();
		printf("%s",readbuf); // 打印收到的信息
		if(strcmp(readbuf,"eth: lo, mac: 00:00:00:00:00:00\n")==0)
		{
			memset(readbuf,0,sizeof(readbuf));
			read(c_fd,readbuf,sizeof(readbuf)); // 读操作
			record_mess();
			printf("%s",readbuf); // 打印收到的信息
			if(strcmp(readbuf,"eth: virbr0, mac: 52:54:00:d6:a2:30\n")==0)
			{
				puts("硬件校验通过（CPU ID与MAC均合法）！");
				memset(writebuf,0,sizeof(writebuf));
				strcpy(writebuf,"您的硬件设备具有接入权限！");
				n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
			}
			else
			{
				memset(writebuf,0,sizeof(writebuf));
				strcpy(writebuf,"您的硬件设备无接入权限！");
				n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
				exit(-1);
			}
		}
		else
		{
			memset(writebuf,0,sizeof(writebuf));
			strcpy(writebuf,"您的硬件设备无接入权限！");
			n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
			exit(-1);
		}
	}
	else
	{
		memset(writebuf,0,sizeof(writebuf));
		strcpy(writebuf,"您的硬件设备无接入权限！");
		n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
		exit(-1);
	}
	while(1)
	{
		memset(readbuf,0,sizeof(readbuf));
		read(c_fd,readbuf,sizeof(readbuf)); // 读操作
		record_mess();
		if((strcmp(readbuf,"D")==0)||(strcmp(readbuf,"E")==0)||(strcmp(readbuf,"F")==0))
		break;
		else
		printf("%s",readbuf); // 打印收到的信息
	}
        while(1)
	{
		if((strcmp(readbuf,"D")==0)||(strcmp(readbuf,"E")==0)||(strcmp(readbuf,"F")==0));
		else
		{
                	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
			record_mess();
		}
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
			count_en=0;
		} // 客户端单独传递Y，指示加密模式
		else if(readbuf[0]=='N'&&readbuf[1]=='\0')
		encryd=0; // 客户端单独传递N，指示无加密
		else if(readbuf[0]=='E'&&readbuf[1]=='\0')
		{
			exit(-1);
		}
		else if(encryd==1)
		{
			for(i=0;i<5;i++)
			{
				judge[i]=readbuf[i];
			} 
			judge_flag=judge_prog();
			if(judge_flag==-1)
			exit(-1);
			else if(judge_flag==1);
			else
			{
				puts("是否解密（Y：是；N：否）：");
				scanf("%s",decry_flag);
				if(decry_flag[0]=='Y')
				{
					decry();
					if(judge_flag==-1)
					exit(-1);
				} // 用户指定解密
				else
				{
					for(i=0;i<5;i++)
					judge[i]=readbuf[i];
					judge_flag=judge_prog();
					if(judge_flag==-1)
					exit(-1);
					else if(judge_flag==1);
					else
		        	        printf("%s\n",readbuf); // 打印收到的信息
				}
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
				puts("是否校验完整性：");
				scanf("%s",check);
				if(check[0]=='Y')
				{
					if(decry_flag[0]=='N')
					decry_for_check();
					memset(writebuf,0,sizeof(writebuf));
					strcpy(writebuf,"check");
					n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
					md5();
					memset(readbuf,0,sizeof(readbuf)); // 清空数组
					read(c_fd,readbuf,sizeof(readbuf)); // 读操作
					record_mess();
					if(strcmp(readbuf,check_flag)==0)
					puts("传输完整");
					else
					puts("传输不完整");
				}
				else
				{
					memset(writebuf,0,sizeof(writebuf));
					strcpy(writebuf,"nocheck");
					n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
				}
			}
		} // 加密模式下询问用户是否解密，并打印输出
		else
		{
			for(i=0;i<5;i++)
			{
				judge[i]=readbuf[i];
			} 
			judge_flag=judge_prog();
			if(judge_flag==-1)
			exit(-1);
			else if(judge_flag==1);
			else
			{
				printf("%s\n",readbuf); // 无加密传输时，直接打印收到的信息
				record_mess();
				strcpy(data_store,readbuf);
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
				puts("是否校验完整性：");
				scanf("%s",check);
				if(check[0]=='Y')
				{
					memset(writebuf,0,sizeof(writebuf));
					strcpy(writebuf,"check");
					n_write=write(c_fd,writebuf,sizeof(writebuf)); // 向client端发送数据
					md5();
					memset(readbuf,0,sizeof(readbuf)); // 清空数组
					read(c_fd,readbuf,sizeof(readbuf)); // 读操作
					record_mess();
					if(strcmp(readbuf,check_flag)==0)
					puts("传输完整");
					else
					puts("传输不完整");
				}
			}
		}
                memset(readbuf,0,sizeof(readbuf)); // 清空数组
        }
 
        return 0;
}
