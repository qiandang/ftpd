#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"

void ftp_reply(session_t* sess,  int status, const char* text);
void ftp_lreply(session_t* sess,int status,const char* text);

void handle_alarm_timeout(int sig);
void handle_sigalrm(int sig);
void handle_sigurg(int sig);
void start_cmdio_alarm(void);
void start_data_alarm(void);

void check_abor(session_t* sess);

void list_common(session_t* sess, int detail);
void upload_common(session_t* sess, int is_append);
void limit_rate(session_t* sess, int bytes_transfered, int is_upload);

int get_transfer_fd(session_t* sess);
int port_active(session_t* sess);
int pasv_active(session_t* sess);
int get_port_fd(session_t* sess);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_site_help(session_t* sess,char* arg);
static void do_site_umask(session_t* sess,char* arg);
static void do_site_chmod(session_t* sess,char* arg);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);

static void do_site_chmod(session_t* sess, char* chmod_arg);
static void do_site_umask(session_t* sess, char* umask_arg);

typedef struct ftpcmd
{
    const char* cmd;
    void (*cmd_handler)(session_t* sess);
}ftpcmd_t;

static ftpcmd_t ctrl_cmds[] = 
{
    {"USER", do_user },
    {"PASS", do_pass },
    {"CWD",  do_cwd },
    {"XCWD", do_cwd },
    {"CDUP", do_cdup },
    {"XCUP", do_cdup },
    {"QUIT", do_quit },
    {"ACCT", NULL },
    {"SMNT", NULL },
    {"REIN",NULL },
    /* 传输参数命令 */
    {"PORT", do_port },
    {"PASV", do_pasv },
    {"TYPE", do_type },
    {"STRU", /*do_stru*/NULL },
    {"MODE", /*do_mode*/NULL },
    /* 服务命令 */
    {"RETR", do_retr },
    {"STOR", do_stor },
    {"APPE", do_appe },
    {"LIST", do_list },
    {"NLST", do_nlst },
    {"REST",do_rest },
    {"ABOR", do_abor },
    {"\377\364\377\362ABOR", do_abor},
    {"PWD",     do_pwd },
    {"XPWD",    do_pwd },
    {"MKD",     do_mkd },
    {"XMKD", do_mkd },
    {"RMD", do_rmd },
    {"XRMD", do_rmd },
    {"DELE", do_dele },
    {"RNFR",    do_rnfr },
    {"RNTO",    do_rnto },
    {"SITE", do_site },
    {"SYST",    do_syst },
    {"FEAT",    do_feat },
    {"SIZE", do_size },
    {"STAT", do_stat },
    {"NOOP", do_noop },
    {"HELP", do_help },
    {"STOU", NULL },
    {"ALLO", NULL }
};

session_t* p_sess;

void handle_alarm_timeout(int sig)
{
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_FAILURE);
}

void handle_sigalrm(int sig)
{
	if(!p_sess->data_process)
	{
		ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Data timeout. reconnect,sorry.");
		exit(EXIT_FAILURE);
	}
	//fouze dangqian chuyu shuju chuanshu de zhuangtai shoudaole chaoshi xianhao
	p_sess->data_process = 0;
	start_data_alarm();
}


void handle_sigurg(int sig)
{
	if(p_sess->data_fd == -1)//bu shuyu shuju chuanshu zhuangtai
	{
		return;
	}

	//jie shou abor mingling	
	char cmdline[MAX_COMMAND_LINE] = {0};
	int ret = readline(p_sess->ctrl_fd, cmdline, MAX_COMMAND_LINE);
	if(ret <= 0)
	{
		ERR_EXIT("readline");
	}
	//quchu mingling de \r\n
	str_trim_crlf(cmdline);

	if(strcmp(cmdline, "ABOR") == 0 || strcmp(cmdline, "\377\364\377\362ABOR"))
	{
		p_sess->abor_received = 1;
		shutdown(p_sess->data_fd, SHUT_RDWR);
	}
	else
	{
		//fei fa mingling tishi
		ftp_reply(p_sess, FTP_BADCMD, "Unknown command.");
	}
}


void check_abor(session_t* sess)
{
	if(sess->abor_received)
	{
		sess->abor_received = 0;
		ftp_reply(p_sess, FTP_ABOROK, "ABOR successful.");
	}
}

void start_cmdio_alarm(void)
{
	if(tunable_idle_session_timeout > 0)
	{
		//anzhuang xinhao
		signal(SIGALRM, handle_alarm_timeout);
		//qi dong nao zhong
		alarm(tunable_idle_session_timeout);
	}
}

void start_data_alarm(void)
{
	if(tunable_data_connection_timeout > 0)
	{
		//anzhuang xinhao
		signal(SIGALRM, handle_sigalrm);
		//qi dong nao zhong
		alarm(tunable_idle_session_timeout);
	}
	else if(tunable_idle_session_timeout > 0)
	{
		//guanbi xian qian an zhuang de naozhong
		alarm(0);
	}
}

void handle_child(session_t *sess)
{
	//dang kehuduan denglu shi ,xian gei yi ge huanying xinxi
	//fasong 220 xinxi gei ke hu duan
	//writen(sess->ctrl_fd,"220 (miniftpd 0.1)\r\n",strlen("220 (miniftpd 0.1)\r\n"));
	ftp_reply(sess, FTP_GREET, "(miniftpd 0.1)");
	int ret;
	while(1)//cong kehuduan yihang yihang de jieshou shuju
	{
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));
		
		start_cmdio_alarm();

		ret = readline(sess->ctrl_fd,sess->cmdline,MAX_COMMAND_LINE);//an hang du qu
                //jiexi chuli ftp mingling and canshu
		if(ret == -1)
			ERR_EXIT("readline");
		else if(ret == 0)//biao shi kehu duan yi guanbi ,suoyi guanbi fuwu jincheng
			exit(EXIT_SUCCESS);
                

		//quchu \r\n
		str_trim_crlf(sess->cmdline);
		

		//jiexi FTP mingling yu canshu
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		

                //jiang mingling zhuanhua wei daxie
		str_upper(sess->cmd);
           
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
		int i;
		for(i = 0; i < size; i++)
		{
			if ( strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
			{
				if (ctrl_cmds[i].cmd_handler != NULL)
				{
					ctrl_cmds[i].cmd_handler(sess);
				}
				else 
				{
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				}
				
				break;
			}
		}
                
		if (i == size)
		{
			ftp_reply(sess, FTP_BADCMD, "Unknown Command."); 
		}
		
	}
}


void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

void ftp_lreply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

void list_common(session_t* sess,int detail)
{

	DIR *dir = opendir(".");
	if(dir == NULL)
	{
		return 0;
	}
	
	struct dirent *dt;
	struct stat sbuf;
	while((dt = readdir(dir)) != NULL)
	{
		if(lstat(dt->d_name, &sbuf) < 0)
		{	
			continue;	
		}
		if(dt->d_name[0] == '.')
			continue;

		char buf[1024] = {0};
		if(detail)
		{
			const char* perms = statbuf_get_perms(&sbuf);

			int off = 0;
			off += sprintf(buf,"%s ", perms);
			off += sprintf(buf + off," %3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf + off,"%8lu", (unsigned long)sbuf.st_size);
				
			const char* datebuf = statbuf_get_date(&sbuf);		

			off += sprintf(buf + off, "%s ", datebuf);
			
			if(S_ISLNK(sbuf.st_mode))
			{	
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name);
			}	
			else 
			{
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
			}	
		}
		else
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}

		writen(sess->data_fd, buf, strlen(buf));

	}

	closedir(dir);
}


void limit_rate(session_t* sess, int bytes_transfered, int is_upload)
{
	sess->data_process = 1;
	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	double elapsed;//ben ci chuanshu suo yong shijian
	elapsed = curr_sec - sess->bw_transfer_start_sec;
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec)/(double)1000000;
	if(elapsed <= (double)0)
	{
		elapsed = (double)0.01;
	}
	//jisuan dangqian chuanshu sudu
	unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);
	double rate_ratio;
	if(is_upload)
	{
		if(bw_rate <= sess->bw_upload_rate_max)
		{
			//buxuyao xiansu
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}

		rate_ratio = bw_rate / sess->bw_upload_rate_max;
	}
	else
	{
		if(bw_rate <= sess->bw_download_rate_max)
		{
			//gengxin kaishi de shijian
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			//buxuyao xiansu
			return;
		}

		rate_ratio = bw_rate / sess->bw_download_rate_max;
	}

	double pause_time;
	pause_time = (rate_ratio - (double)1) * elapsed;

	//sleep zhi chi miao, zheli bushi yong sleep() hanshu, yin wei zhe ge han shu nei bu keneng shiyong shi zhong xinhao,xuyao he alarm() jiehe shiyong
	nano_sleep(pause_time);

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
}

void  upload_common(session_t* sess, int is_append)
{
	//chuang jian shuju lianjie
	int data = get_transfer_fd(sess);

	//jian ce shifou shou dao port huozhe pasv mingling
	 if (data == 0)
	 {
		return;
	 }

	 long long offset = sess->restart_pos;
	 sess->restart_pos = 0;

	 //dakai wenjian
	 int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);//meiyou ke zhi xingde quanxian
	 if(fd == -1)
	 {

		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	 }

	 //jia xie de suo,zai shangchuan de shi hou qita jincheng bukeyi du ye bu keyi xie, danshi bu neng jia xie de suo
	int ret;
	ret = lock_file_write(fd);
	if(ret == -1)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	//rest+stor
	//appe
	if(!is_append && offset == 0)     //STOR
	{
		ftruncate(fd, 0);//qin ling yuan ben cunzai de wenjian
		if(lseek(fd, 0, SEEK_SET) < 0)//wenjian dingwei dao wenjian toude weizhi
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file."); 
			return;
		}
	}	
	else if(!is_append && offset != 0)
	{
		if(lseek(fd, offset, SEEK_SET) < 0)
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if(is_append)//zhui jia
	{
		if(lseek(fd, 0, SEEK_END) < 0)//jiang zhizhen pianyi dao wenjian de mo wei
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}

	
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if(!S_ISREG(sbuf.st_mode))
	{

		ftp_reply(sess, FTP_UPLOADFAIL, "Failed to open file.");
		return;
	}

	//  yi 2 jinzhi chuanshu
	char text[1024] = {0};
	if(sess->is_ascii)
	{
		sprintf(text, "opening ascii mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size);
	}
	else 
	{
		sprintf(text, "opening binaary mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size);
	}//wenjian ming baocun zai arg dangzhong


	ftp_reply(sess, FTP_DATACONN, text);


	int flag = 0;
	
	//xia zai wen jian
	char buf[1024];
	
	//shui mian shijian = (dangqian chuanshu sudu - zuida chuan shu sudu)*dangqian chuanshu shijian
	//chongxin anzhuang xinhao bing qidong naozhong
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	while(1)
	{
		ret = read(sess->data_fd, buf, sizeof(buf));
		if(ret == -1)
		{
			if(errno == EINTR)
			{
				continue;
			}
			else
			{
				flag = 2;
				break;
			}
		}
		else
			if(ret == 0)
			{
				flag = 0;
				break;
			}
		
		limit_rate(sess, ret, 1);

		if(sess->abor_received)
		{
			flag = 2;
			break;
		}

		if(writen(fd, buf, ret) != ret)
		{
			flag = 1;
			break;
		}
	}
	
	//guan bi shu ju tao jie zi
	close(sess->data_fd);
	sess->data_fd = -1;

	close(fd);

	if(flag == 0 && !sess->abor_received)
	{
		//226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}

	else if(flag == 1)
	{
		//451
		ftp_reply(sess, FTP_BADSENDFILE, "failure writting to local file.");
	}
	else if(flag == 2)
	{
	//426
	ftp_reply(sess, FTP_BADSENDNET, "Failure reading from network.");
	}

	check_abor(sess);

	start_cmdio_alarm();
}

int port_active(session_t* sess)
{
	if(sess->port_addr)
	{
		return 1;
	}
	
	return 0;
}

int pasv_active(session_t* sess)
{
	/*
	if(sess->pasv_listen_fd != -1)
		return 1;

	*/
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);

	int active = priv_sock_get_int(sess->child_fd);

	if(active)
	{
		if(port_active(sess))
		{
			fprintf(stderr, "both port and pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0; 
}

int get_port_fd(session_t* sess)
{

		priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);

		unsigned short port = ntohs(sess->port_addr->sin_port);

		char* ip = inet_ntoa(sess->port_addr->sin_addr);

		priv_sock_send_int(sess->child_fd, (int)port);
		priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

		char res = priv_sock_get_result(sess->child_fd);

		if(res == PRIV_SOCK_RESULT_BAD)
		{
			return 0;
		}
		else if(res == PRIV_SOCK_RESULT_OK)
		{
			sess->data_fd = priv_sock_recv_fd(sess->child_fd);
		}
		return 1;
}

int get_pasv_fd(session_t* sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD)
	{
		return 0;
	}
	else if(res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	return 1;
}

int get_transfer_fd(session_t* sess)
{

	if(!port_active(sess) && !pasv_active(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN, "Use Port or pasv first");
		return 0;
	}
		
	int ret = 1;

	//ru guo shi zhu dong moshi bei ji huo
	if(port_active(sess))
	{
		//chuang jian lianjie tao jie zi 
		if(get_port_fd(sess) == 0)
		{	
			ret = 0;
		}
		/*int fd = tcp_client(0);
		if(connect_timeout(fd, sess->port_addr, tunable_connect_timeout) < 0)
		{
			close(fd);
			return 0;
		}
		sess->data_fd = fd;*/
	}
	

	if(pasv_active(sess))
	{
		if(get_pasv_fd(sess) == 0)

			ret = 0;

	}

	//zuowan yihou pan ding shi fou wei kongzhizhen,ruguobushi shuoming zhiqian zuoguo do port,fen pei le nei cun,(yi dan chuang jian cheng gong)xianzai yi jing mei you yong le ,shi fang ci nei cun
	if(sess->port_addr != NULL)
	{			
		free(sess->port_addr);
		sess->port_addr = NULL;
	}

	if(ret)
	{
		start_data_alarm();
	}
	return ret;
	
}

static void do_user(session_t *sess)
{
	//user jjl
	struct passwd *pw = getpwnam(sess->arg);
	if(pw == NULL)
	{
		//yonghu bu cunzai
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	sess->uid = pw->pw_uid;
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
	
}


static void do_pass(session_t *sess)
{
	//pass 123456
	
	struct passwd *pw = getpwuid(sess->uid);
	if(pw == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}
	
	struct spwd *sp = getspnam(pw->pw_name);
	if(sp == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//jiang ming wen jia mi
	char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
	//yanzheng mima
	if(strcmp(encrypted_pass, sp->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//denglu zhihou kai qi nenggou jie shou sigurg xinhao de gongneng
	signal(SIGURG, handle_sigurg);
	//kaiqi diao yong hanshu jie shou xinhao sigurg de nengli
	activate_sigurg(sess->ctrl_fd);

	umask(tunable_local_umask);	
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);

	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

void do_cwd(session_t *sess)
{
  if(chdir(sess->arg) < 0)
  {
	 ftp_reply(sess, FTP_FILEFAIL, "Failed to change to directory.");
	 return;
  } 

  ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}
void do_cdup(session_t *sess)
{
  if(chdir("..") < 0)
  {
	 ftp_reply(sess, FTP_FILEFAIL, "Failed to change to directory.");
	 return;
  } 

  ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

void do_quit(session_t *sess)
{
	ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
	//221 GOOGBYE
	exit(EXIT_SUCCESS);
   
}

static void do_port(session_t *sess)
{
	//clear_transfer(sess);
	unsigned int v[6];

	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u",&v[2],&v[3],&v[4],&v[5],&v[0],&v[1]);

	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	sess->port_addr->sin_family = AF_INET;
	unsigned char* p = (unsigned char*)&sess->port_addr->sin_port;
	p[0] = v[0];
	p[1] = v[1];

	p = (unsigned char*)&sess->port_addr->sin_addr;
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];	

	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");

}

void do_pasv(session_t *sess)
{
	clear_transfer(sess);
	//char ip[16] = {0};
	//getlocalip(ip);
	/*
	sess->pasv_listen_fd = tcp_server("192.168.229.135", 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if(getsockname(sess->pasv_listen_fd, (struct sockaddr*)&addr, &addrlen) < 0) //keyi huoqu bendi de dizhi xinxi
	{
		ERR_EXIT("getsockname");
	}
	unsigned short port = ntohs(addr.sin_port);
	*/

	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);

	unsigned short port = (int)priv_sock_get_int(sess->child_fd);

	unsigned int v[4];
	sscanf("192.168.229.138", "%u.%u.%u.%d", &v[0], &v[1], &v[2], &v[3]);
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", v[0], v[1], v[2], v[3], port >> 8, port & 0xFF);

	ftp_reply(sess, FTP_PASVOK, text);
}

void do_type(session_t *sess)
{
    if (strcmp("A",sess->arg) == 0)
    {
        sess->is_ascii = 1;
        ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");

    }
    else if (strcmp("I",sess->arg) == 0)
    {
        sess->is_ascii = 0;
        ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
    }
    else
    {
        ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
    }
}

/*
void do_stru(session_t *sess)
{

}

void do_mode(session_t *sess)
{

}
*/

void do_retr(session_t *sess)
{
	//xiazai wenjian//duandian xuchuan
	
	//chuang jian shuju lianjie
	int data = get_transfer_fd(sess);

	//jian ce shifou shou dao port huozhe pasv mingling
	 if (data == 0)
	 {
		return;
	 }

	 long long offset = sess->restart_pos;
	 sess->restart_pos = 0;

	 //dakai wenjian
	 int fd = open(sess->arg, O_RDONLY);
	 if(fd == -1)
	 {

		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	 }

	 //jia du de suo,qita jincheng keyi du, danshi bu neng jia xie de suo
	int ret;
	ret = lock_file_read(fd);
	if(ret == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	//panduan shifou shi putong wenjian
	//shebei wenjian buneng xiazai dao kehuduan
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if(!S_ISREG(sbuf.st_mode))
	{

		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}
	
	//ding wei dao duan dian
	if(offset != 0)
	{
		ret = lseek(fd, offset, SEEK_SET);//dingwei hanshu
		if(ret == -1)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to lseek.");
			return;
		}
	}


	//  yi 2 jinzhi chuanshu
	char text[1024] = {0};
	if(sess->is_ascii)
	{
		sprintf(text, "opening ascii mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size);
	}
	else 
	{
		sprintf(text, "opening binaary mode data connection for %s (%lld bytes).", sess->arg, (long long)sbuf.st_size);
	}//wenjian ming baocun zai arg dangzhong


	ftp_reply(sess, FTP_DATACONN, text);


	int flag = 1;
	/*
	//xia zai wen jian
	char buf[4096];
	while(1)
	{
		ret = read(fd, buf, sizeof(buf));
		if(ret == -1)
		{
			if(errno == EINTR)
			{
				continue;
			}
			else
			{
				flag = 1;
				break;
			}
		}
		else
			if(ret == 0)
			{
				flag = 0;
				break;
			}
		if(writen(sess->data_fd, buf, ret) != ret)
		{
			flag = 2;
			break;
		}
	}*/
	
	//shiyong sendfile hanshu 
	//shouxian ji suan wenjian de daxiao
	long long bytes_to_send = sbuf.st_size;
	if(offset > bytes_to_send)
	{
		bytes_to_send = 0;
	}
	else
	{
		bytes_to_send -= offset;
	}

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
	while(bytes_to_send)
	{
		int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
		if(ret == -1)
		{
			flag = 2;
			break;
		}
		limit_rate(sess, ret, 0);
		if(sess->abor_received)
		{
			flag = 2;
			break;
		}
		bytes_to_send -= ret;//ret wei yijing fasong de zijieshu
	}

	if(bytes_to_send == 0)
	{
		flag = 0;
	}

	//guan bi shu ju tao jie zi
	close(sess->data_fd);
	sess->data_fd = -1;
	
	close(fd);

	if(flag == 0 && !sess->abor_received)
	{
		//226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else if(flag == 1)
	{
		//451
		ftp_reply(sess, FTP_BADSENDFILE, "failure reading from local file.");
	}
	else if(flag == 2)
	{
		//426
		ftp_reply(sess, FTP_BADSENDNET, "Failure to writing to network stream.");
	}

	check_abor(sess);

	//chongxin kaiqi kong zhi lianjie tongdao de naozhong
	start_cmdio_alarm();
}

void do_stor(session_t *sess)
{
	upload_common(sess, 0);
 
}

void do_appe(session_t *sess)
{
	upload_common(sess, 1);
   
}

void do_list(session_t *sess)
{
	int data = get_transfer_fd(sess);

	//jian ce shifou shou dao port huozhe pasv mingling
	 if (data == 0)
	 {
		return;
	 }

	//chuang jian shu ju lian jie

	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//chuan shu lie biao
	list_common(sess, 1);
	
	//guan bi shu ju tao jie zi
	close(sess->data_fd);
	sess->data_fd = -1;

	//226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");

	clear_transfer(sess);
}

void do_nlst(session_t *sess)
{/*
	int data = get_transfer_fd(sess);
	//jian ce shifou shou dao port huozhe pasv mingling
	 if (data == 0)
	 {
		return;
	 }

	//chuang jian shu ju lian jie

	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	//chuan shu lie biao
	list_common(sess, 0);
	
	//guan bi shu ju tao jie zi
	close(sess->data_fd);
	sess->data_fd = -1;

	//226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");

	clear_transfer(sess);*/
}

void do_rest(session_t *sess)
{
	sess->restart_pos = str_to_longlong(sess->arg);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}
void do_abor(session_t *sess)
{
	ftp_reply(sess, FTP_ABOR_NOCONN, "No transfer to ABOR.");
}

void do_pwd(session_t *sess)
{
    char text[1024] = {0};
    char dir[1024+1] = {0};
    getcwd(dir,1024); 
    sprintf(text, "\"%s\"", dir);
    ftp_reply(sess, FTP_PWDOK, text);
}

void do_mkd(session_t *sess)
{
	//0777 & umask,yisi jiushi chuangjian wenjianjia
       if(mkdir(sess->arg,0777) < 0)
       {
	       ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
	       return;
       }


       char text[4096] = {0};
       if(sess->arg[0] == '/')
       {
	       sprintf(text, "%s created", sess->arg);
       }

       else
       {
	       char dir[4096+1] = {0};
	       getcwd(dir, 4096);
	       if(dir[strlen(dir)-1] == '/')
	       {
		       sprintf(text, "%s%s created", dir, sess->arg);
	       }
	       else
	       {
		       sprintf(text, "%s%s created", dir, sess->arg);
	       }
       }

	ftp_reply(sess, FTP_MKDIROK, text);
}

void do_rmd(session_t *sess)
{
	if(rmdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "remove directory operation failed.");
		return;
	}


	ftp_reply(sess, FTP_RMDIROK, "remove directory operation successful.");

}

void do_dele(session_t *sess)
{
	if(unlink(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Delete operation failed.");
		return;
	}

		ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

void do_rnfr(session_t *sess)
{
	//xiugai wenjian ming
	sess->rnfr_name = (char*)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, strlen(sess->arg) + 1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

void do_rnto(session_t *sess)
{
	if(sess->rnfr_name == NULL)
	{
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}
	rename(sess->rnfr_name, sess->arg);

	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");

	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
}

void do_site(session_t *sess)
{
	char cmd[100] = {0};
	char arg[100] = {0};

	str_split(sess->arg, cmd, arg, ' ');
	if(strcmp(cmd, "CHMOD") == 0)
	{
		do_site_chmod(sess, arg);
	}
	else if(strcmp(cmd, "UMASK") == 0)
	{
		do_site_umask(sess, arg);
	}
	else if(strcmp(cmd, "HELP") == 0)
	{
		ftp_reply(sess, FTP_SITEHELP, "CHMOD UMASK HELP");
	}
	else
	{
		ftp_reply(sess, FTP_BADCMD, "unknow SITE command.");
	}	
}

/*
void do_site_help(session_t* sess,char* cmdline)
{
  
}
*/

void do_site_umask(session_t* sess, char* umask_arg)
{
	if(strlen(umask_arg) == 0)
  	{
		char text[1024] = {0};
	  	sprintf(text, "Your current umask is: 0%o", tunable_local_umask);
	  	ftp_reply(sess, FTP_UMASKOK, text);
  	}
  	else
	{
		unsigned int um = str_octal_to_uint(umask_arg);
		umask(um);
		char text[1024] = {0};
		sprintf(text, "UMASK set to 0%o", um);
		ftp_reply(sess, FTP_UMASKOK, text);
	}

}

void do_site_chmod(session_t* sess, char* chmod_arg)
{
    if(strlen(chmod_arg) == 0)
    {
	ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
	return;
    }

    char perm[100] = {0};
    char file[100] = {0};
    str_split(chmod_arg, perm, file, ' ');
    if(strlen(file) == 0)
    {
	    ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments");
	    return;
    }

    unsigned int mode = str_octal_to_uint(perm);
    if(chmod(file, mode) < 0)
    {
	    ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD Command failed.");
    }
    else
    {
	    ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD Command ok.");
    }

}

void do_syst(session_t *sess)
{
    ftp_reply(sess, FTP_SYSTOK, "Linux Type: L8");
}

void do_feat(session_t *sess)
{
    ftp_lreply(sess, FTP_FEAT, "Features");
    writen(sess->ctrl_fd," EPRT\r\n",strlen(" EPRT\r\n"));
    writen(sess->ctrl_fd," EPSV\r\n",strlen(" EPSV\r\n"));
    writen(sess->ctrl_fd," MDTM\r\n",strlen(" MDTM\r\n"));
    writen(sess->ctrl_fd," PASV\r\n",strlen(" PASV\r\n"));
    writen(sess->ctrl_fd," REST STREAM\r\n",strlen(" REST STREAM\r\n"));
    writen(sess->ctrl_fd," SIZE\r\n",strlen(" SIZE\r\n"));
    writen(sess->ctrl_fd," TVFS\r\n",strlen(" PASV\r\n"));
    writen(sess->ctrl_fd," UTF8\r\n",strlen(" UTF8\r\n"));
    ftp_reply(sess, FTP_FEAT, "End");
}

void do_size(session_t *sess)
{
	struct stat buf;
	if(stat(sess->arg, &buf) < 0 )
	{
		ftp_reply(sess, FTP_FILEFAIL, "Size operation fail.");
		return;
	}
	
	if(!S_ISREG(buf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
	}

	char text[1024] = {0};
	sprintf(text, "%lld", (long long)buf.st_size);
	ftp_reply(sess, FTP_SIZEOK, text);
}

void do_stat(session_t *sess)
{
	ftp_lreply(sess,FTP_STATOK,"FTP server status:");
	if(sess->bw_upload_rate_max == 0)
	{
		char text[1024];
		sprintf(text, "No session upload bandwidth limit\r\n");
		writen(sess->ctrl_fd, text, strlen(text));
	}
	else if(sess->bw_upload_rate_max > 0)
	{
		char text[1024];
		sprintf(text, "Session upload bandwidth limit in byte/s is %u\r\n", sess->bw_upload_rate_max);
		writen(sess->ctrl_fd, text, strlen(text));
	}
	if(sess->bw_download_rate_max == 0)
	{
		char text[1024];
		sprintf(text, "No session download bandwidth limit\r\n");
		writen(sess->ctrl_fd, text, strlen(text));
	}
	else if(sess->bw_download_rate_max > 0)
	{
		char text[1024];
		sprintf(text, "Session download bandwidth limit in byte/s is %u\r\n", sess->bw_download_rate_max);
		writen(sess->ctrl_fd, text, strlen(text));
	}
    	
	char text[1024] = {0};
	sprintf(text, "At session startup, client count was %u\r\n", sess->num_clients);
	writen(sess->ctrl_fd, text, strlen(text));
    	ftp_reply(sess,FTP_STATOK,"STAT OK");
}

void do_noop(session_t *sess)
{
	//fangzhi kongxian duankai
    ftp_reply(sess,FTP_OPTSOK,"Noop OK");
}

void do_help(session_t *sess)
{
    ftp_lreply(sess,FTP_HELP,"The following commands are recognized.");
    writen(sess->ctrl_fd," ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n",
            strlen(" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n"));
    writen(sess->ctrl_fd," MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n",
            strlen(" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n"));
    writen(sess->ctrl_fd," RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n",
            strlen(" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"));
    writen(sess->ctrl_fd," XPWD XRMD\r\n",strlen(" XPWD XRMD\r\n"));
    ftp_reply(sess,FTP_HELP,"HELP OK");
}

void clear_transfer(session_t* sess)
{
    shutdown(sess->data_fd,SHUT_RDWR);
    sess->data_fd = -1;
    if ( port_active(sess) )
    {
	sess->port_addr = NULL;
        free(sess->port_addr);   
    }

    if ( pasv_active(sess) )
    {
        close(sess->pasv_listen_fd);
        sess->pasv_listen_fd = -1;
    }
   // if ( NULL != sess->rn_filepath )
     //   free(sess->rn_filepath);
  //  sess->rest_pos = 0;
   // sess->bappe = 0;
}
