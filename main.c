#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "hash.h"

void check_limits(session_t* sess);
void handle_sigchld(int sig);

unsigned int hash_func(unsigned int buckets, void* key);

static hash_t* s_ip_count_hash;
static hash_t* s_pid_ip_hash;

extern session_t* p_sess;
static unsigned int s_children;
unsigned int handle_ip_count(void* ip);
void drop_ip_count(void* ip);

int main(void)
{
	parseconf_load_file(MINIFTP_CONF);
	daemon(0,0);


	if(getuid() != 0)
	{
	
		fprintf(stderr,"miniftpd:must be started as root\n");
		exit(EXIT_FAILURE);
	}

        session_t sess = 
	{
		//kongzhi lianjie xiangguan
		0,-1,"","","",
		//shu ju lian jie 
		NULL,-1,-1,0,
		//xian su
		0,0,0,0,
		//fu zi jincheng tongdao
		-1,-1,
	        //ftp xieyi de zhuangtai
		0,0,NULL,0,
		//lianjie shude xianzhi
		0,0
	};
	
	p_sess = &sess;
	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;

	s_ip_count_hash = hash_alloc(256, hash_func);
	s_pid_ip_hash = hash_alloc(256, hash_func);

	signal(SIGCHLD, handle_sigchld);
	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
       	
	int conn;
	pid_t pid;

	struct sockaddr_in addr;

	while(1)
        {
		conn = accept_timeout(listenfd, &addr, 0);
		if(conn==-1)
			ERR_EXIT("accept connect");
		
		unsigned int ip = addr.sin_addr.s_addr;
		handle_ip_count(&ip);

		++s_children;
		sess.num_clients = s_children;
		sess.num_this_ip = handle_ip_count(&ip);

		pid = fork();
		if(pid == -1)
		{
			--s_children;
			ERR_EXIT("fork");
		}

		if(pid == 0)
		{
			close(listenfd);
			sess.ctrl_fd = conn;
			check_limits(&sess);
			signal(SIGCHLD, SIG_IGN);
			begin_session(&sess);//lianjie chenggong zijincheng jianli huihua
		}
		else
		{
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid), &ip, sizeof(unsigned int));
			close(conn);//fu jin cheng bu xuyao chu li lian jie
		}
	}
	return 0;
}


void check_limits(session_t* sess)
{
	if(tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
	{
		ftp_reply(sess, FTP_TOO_MANY_USERS, "There are too many connected users, please try later.");
		exit(EXIT_FAILURE);
	}

	//jiancha ip de lianjie shu
	if(tunable_max_per_ip > 0 && sess->num_this_ip > tunable_max_per_ip)
	{
		ftp_reply(sess, FTP_IP_LIMIT, "There are too many connected users for your internet address, please try later.");
		exit(EXIT_FAILURE);
	}
}

void handle_sigchld(int sig)
{
	pid_t pid;
	while((pid - waitpid(-1, NULL, WNOHANG)) > 0)//xun huan zhidao dengdai dao jincheng,hanshu fanhuizhi wei dengdao de pid,meiyou deng dao shi wei 0
	{
	//tui chu de shi hou yinggai rang fu jincheng tongji de zijincheng shu -
		--s_children;
		unsigned int* ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));
		if(ip == NULL)
		{
			continue;
		}

		//dengdao le yige ip,dui ta de lianjie shu chuli
		drop_ip_count(ip);
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}


}

unsigned int hash_func(unsigned int buckets, void* key)
{
	unsigned int* number = (unsigned int*)key;
	return (*number) % buckets;
}

unsigned int handle_ip_count(void* ip)//dang yige kehu denglu de shihou gengxin biaoxiang
{
	unsigned int count;
	unsigned int* p_count = (unsigned int*)hash_lookup_entry(s_ip_count_hash,ip, sizeof(unsigned int));
	if(p_count == NULL)
	{
		count = 1;
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int), &count,  sizeof(unsigned int));
	}
	else
	{
		count = *p_count;
		++count;
		*p_count = count;
	}

	return count;
}

void drop_ip_count(void* ip)
{
	unsigned int count;
	unsigned int* p_count = (unsigned int*)hash_lookup_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	if(p_count == NULL)
	{
		return;
	}
	
	count = *p_count;
	if(count <= 0)
	{
		return;
	}
	--count;
	*p_count = count;

	//ruguo faxian wei 0 jiu shanchu zhege biaoxiang
	if(count == 0)
	{
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}
