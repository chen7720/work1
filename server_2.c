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
#include <md5.h>
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#include <iostream>
#pragma warning(disable:4996)
using namespace std;
 
 // 定义数据
int s_fd; // 服务端套接字定义
int c_fd; // 客户端套接字定义
char readbuf[128]={'\0'}; // 存放接收数据的字符数组
char writebuf[128]={'\0'}; // 存放待传数据的字符数组
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
int n_write; // 写标志位
char check_flag[128]={'\0'};
char check[2]={'\0'};
char data_store[128]={'\0'};

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
	for (i = 0; input[i] ; i++)
	{
		readbuf[i]=input[i];
		if(i<5)
		judge[i]=readbuf[i];
	}
	judge_flag=judge_prog();
	if(judge_flag==0)
	printf("%s\n",readbuf); // 打印解密结果
	memset(data_store,0,sizeof(data_store));
	strcpy(data_store,readbuf);
}

int login(void)
{
	//char admin[10]={'a','d','m','i','n'};
	//char admin_key[10]={'2','0','0','2','0','9'};
	char user[5][10]={{'1','0','0','8','6'},{'0','5','9','2'},{'0','5','9','9'},{'1','5','2','5','9','2'},{'1','8','3','5','0','9'}};
	char key[5][10]={{'0','0','0','0','0','0'},{'1','1','1','1','1','1'}};
	char login_user[10]={'\0'};
	char login_key[10]={'\0'};
	char user_temp[10]={'\0'};
	char key_temp[10]={'\0'};
	int m=0;
	int n=0;
	memset(writebuf,0,sizeof(writebuf));
	strcpy(writebuf,"请输入账号：");
	n_write=write(c_fd,writebuf,strlen(writebuf)); // 向client端发送数据
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
	strcpy(login_user,readbuf);
	memset(writebuf,0,sizeof(writebuf));
	strcpy(writebuf,"请输入密码：");
	n_write=write(c_fd,writebuf,strlen(writebuf)); // 向client端发送数据
	memset(readbuf,0,sizeof(readbuf));
	read(c_fd,readbuf,sizeof(readbuf)); // 读操作
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
			if(strcmp(key_temp,login_key)==0)
			{
				memset(writebuf,0,sizeof(writebuf));
				strcpy(writebuf,"登录成功！"); 
				n_write=write(c_fd,writebuf,strlen(writebuf)); // 向client端发送数据
				return  1;
			}
			else
			{
				memset(writebuf,0,sizeof(writebuf));
				strcpy(writebuf,"错误的密码！");
				n_write=write(c_fd,writebuf,strlen(writebuf)); // 向client端发送数据
				return 0;
			}
		}
		else
		{
			puts("错误的账号！");
			return 0;
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
			exit(-1);
		}
	}
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
			puts("是否校验完整性：");
			scanf("%s",check);
			if(check[0]=='Y')
			{
				memset(writebuf,0,sizeof(writebuf));
				strcpy(writebuf,"check");
				n_write=write(c_fd,writebuf,strlen(writebuf)); // 向client端发送数据
				md5();
				memset(readbuf,0,sizeof(readbuf)); // 清空数组
				read(c_fd,readbuf,sizeof(readbuf)); // 读操作
				if(strcmp(readbuf,check_flag)==0)
				puts("传输完整");
				else
				puts("传输不完整");
			}
		} // 加密模式下询问用户是否解密，并打印输出
		else
		{
			printf("%s\n",readbuf); // 无加密传输时，直接打印收到的信息
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
				n_write=write(c_fd,writebuf,strlen(writebuf)); // 向client端发送数据
				md5();
				memset(readbuf,0,sizeof(readbuf)); // 清空数组
				read(c_fd,readbuf,sizeof(readbuf)); // 读操作
				if(strcmp(readbuf,check_flag)==0)
				puts("传输完整");
				else
				puts("传输不完整");
			}
		}
                memset(readbuf,0,sizeof(readbuf)); // 清空数组
        }
 
        return 0;
}