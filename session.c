#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"

void begin_session(session_t *sess)
{
	activate_oobinline(sess->ctrl_fd);
	/*
	int sockfds[2];
	if(socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		ERR_EXIT("socketpair");
       	*/

	priv_sock_init(sess);

	pid_t pid;
       	pid = fork();
	if(pid < 0)
		ERR_EXIT("fork");
	if(pid == 0)//zijincheng
	{
		/*
		close(sockfds[0]);
		sess->child_fd = sockfds[1];
		*/
		priv_sock_set_child_context(sess);
		handle_child(sess);
		//fu wu jincheng
        }
	else
	{
		priv_sock_set_parent_context(sess);
		/*
		close(sockfds[1]);
		sess->parent_fd = sockfds[0];
		*/
		handle_parent(sess);
		//nobody jincheng
	}
}
