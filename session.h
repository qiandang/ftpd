#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"
typedef struct session
{
	//kong zhi lianjie
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];//xu yao bao cun ming ling hang
	char cmd[MAX_COMMAND];//jiexi ming ling
	char arg[MAX_ARG];// jie xi can shu
	
	//shu ju lian jie
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;
	int data_fd;
	int data_process;

	//xian su
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;

	//FU ZI jincheng tongdao
	int parent_fd; //fujincheng tongxin de wenjian miao shu fu
	int child_fd;
	
	//ftp xieyi zhuangtai
	int is_ascii;
	long long restart_pos;
	char* rnfr_name;
	int abor_received;

	//lianh jie shu de xianzhi
	unsigned int num_clients;
	unsigned int num_this_ip;
}session_t;
 
void begin_session(session_t *sess);

#endif
