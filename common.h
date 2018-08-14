#ifndef _COMMON_H
#define _COMMON_H

#include<pwd.h>
#include<unistd.h>
#include<sys/types.h>
#include<fcntl.h>
#include<sys/socket.h>
#include<netdb.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<shadow.h>
#include<crypt.h>
#include<time.h>
#include<sys/stat.h>
#include<dirent.h>
#include<sys/time.h>
#include<signal.h>
#include<linux/capability.h>
#include<sys/syscall.h>
#include<sys/sendfile.h>
#include<sys/wait.h>

#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<ctype.h>

#define ERR_EXIT(m) \
        do \
        { \
            perror(m); \
            exit(EXIT_FAILURE); \
        }while(0)

#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32//mingling de zui da zhi
#define MAX_ARG 1024
#define MINIFTP_CONF "miniftpd.conf"

#endif
