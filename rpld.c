/*
 *   Authors:
 *    Alexander Aring		<alex.aring@gmail.com>
 *
 *   This software is Copyright 2019 by the above mentioned author(s),
 *   All Rights Reserved.
 *
 *   The license which is distributed with this software in the file COPYRIGHT
 *   applies to this software. If your distribution is missing this file, you
 *   may request it from <alex.aring@gmail.com>.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ev.h>

#include <libmnl/libmnl.h>

#include "process.h"
#include "netlink.h"
#include "helpers.h"
#include "socket.h"
#include "config.h"
#include "send.h"
#include "recv.h"
#include "log.h"

#include "crypto/kyber/ref/kem.h"

#define VERSION "0.0.1"
#define PATH_RPLD_LOG "/var/log/rpld.log"
#define PATH_RPLD_CONF "/etc/rpld.conf"
#define LOG_FACILITY LOG_DAEMON

// ICMPV6_PLD_MAXLEN

static struct list_head ifaces;
static int sock;
static ev_async icmpv6_async;
static ev_io sock_watcher;

ev_timer exchange_timer;
static ev_io sock_exchange;
int in_exchange = 0;

/* TODO overwrite root setting */
static char usage_str[] = {
	"\n"
	"  -C, --config=PATH       Set the config file.  Default is /etc/rpld.conf\n"
	"  -d, --debug=NUM         Set the debug level.  Values can be 1, 2, 3, 4 or 5.\n"
	"  -h, --help              Show this help screen.\n"
	"  -f, --facility=NUM      Set the logging facility.\n"
	"  -l, --logfile=PATH      Set the log file.\n"
	"  -m, --logmethod=X       Set method to: syslog, stderr, stderr_syslog, logfile,\n"
	"  -v, --version           Print the version and quit.\n"};

static void usage(FILE *o, const char *pname)
{
	fprintf(o, "usage: %s %s\n", pname, usage_str);
}

static void icmpv6_cb(EV_P_ ev_io *w, int revents)
{
	flog(LOG_INFO, "icmpv6_cb");
	int len, hoplimit;
	struct sockaddr_in6 rcv_addr;
	struct in6_pktinfo *pkt_info = NULL;
	unsigned char msg[MSG_SIZE_RECV];
	unsigned char chdr[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];

	len = recv_rs_ra(sock, msg, &rcv_addr, &pkt_info, &hoplimit, chdr);
	if (len > 0 && pkt_info)
	{
		process(sock, &ifaces, msg, len, &rcv_addr, pkt_info, hoplimit);
	}
	else if (!pkt_info)
	{
		dlog(LOG_INFO, 4, "recv_rs_ra returned null pkt_info");
	}
	else if (len <= 0)
	{
		dlog(LOG_INFO, 4, "recv_rs_ra returned len <= 0: %d", len);
	}
}

static void icmpv6_async_cb(EV_P_ ev_async *w, int revents)
{
	flog(LOG_INFO, "icmpv6_async_cb");

	// Reinitialize the socket watcher for ICMPv6 handling
	ev_io_init(&sock_watcher, icmpv6_cb, sock, EV_READ);
	ev_io_start(loop, &sock_watcher);

	ev_run(loop, 0);
}

static void key_exchange_cb(EV_P_ ev_io *w, int revents)
{
	flog(LOG_INFO, "key_exchange_cb");
	int len, hoplimit;
	struct sockaddr_in6 rcv_addr;
	struct in6_pktinfo *pkt_info = NULL;
	unsigned char msg[MSG_SIZE_RECV];
	unsigned char chdr[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];

	len = recv_rs_ra(sock, msg, &rcv_addr, &pkt_info, &hoplimit, chdr);
	if (len > 0 && pkt_info)
	{
		process_exchange(sock, &ifaces, msg, len, &rcv_addr, pkt_info, hoplimit, loop, w, &in_exchange);
	}
	else if (!pkt_info)
	{
		dlog(LOG_INFO, 4, "recv_rs_ra returned null pkt_info");
	}
	else if (len <= 0)
	{
		dlog(LOG_INFO, 4, "recv_rs_ra returned len <= 0: %d", len);
	}
}

static void trickle_cb_sec(EV_P_ ev_timer *w, int revents)
{
	struct dag *dag = container_of(w, struct dag, trickle_w);

	if (dag->iface->enc_mode == ENC_MODE_NONE)
		send_dio(sock, dag);
	else
		send_dio_sec(sock, dag);
}

static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break(loop, EVBREAK_ALL);
}

/** 
 * @brief This function is called when the exchange timer expires, stopping it if necessary
 */
static void break_exchange_cb(EV_P_ ev_timer *w, int revents)
{
	ev_timer_stop(loop, w);
	if (in_exchange == 1)
	{
		ev_break(loop, EVBREAK_ONE);
	}
}

/**
 * @brief This function is called when the dis_w timer expires.
 * If an encryption is set, it try to perform the initial key exchange
 * After that, it sends the dis/sec_dis message, and then it sends a signal to start the rpl process.
 */
static void send_dis_sec_cb(EV_P_ ev_timer *w, int revents)
{
	struct iface *iface = container_of(w, struct iface, dis_w);

	ev_timer_stop(loop, w);

	if (!iface->enc_mode == ENC_MODE_NONE)
	{
		in_exchange = 1;

		/** After 4 seconds waiting for a exchange response, break the loop */
		ev_timer_init(&exchange_timer, break_exchange_cb, 4., 0.);
		ev_timer_start(loop, &exchange_timer);

		send_pk(sock, iface);

		ev_io_init(&sock_exchange, key_exchange_cb, sock, EV_READ);
		ev_io_start(loop, &sock_exchange);

		ev_run(loop, 0);
		send_dis_sec(sock, iface);
	} else {
		send_dis(sock, iface);
	}

	ev_async_send(loop, &icmpv6_async);
}

/* TODO move somewhere else */
struct ev_loop *foo;
/**
 * @brief This function starts a timer for a dag to regularly send DIO messages
 * It is called when a DAG is created/initialized
 */
void dag_init_timer(struct dag *dag)
{
	ev_timer_init(&dag->trickle_w, trickle_cb_sec,
				  dag->trickle_t, dag->trickle_t);
	ev_timer_start(foo, &dag->trickle_w);
}

/**
 * @brief After the configuration is loaded, we setup the rpls via the ifaces from the conf file
 *
 * @param loop the event loop
 * @param ifaces the list of ifaces from the conf file
 */
static int rpld_setup(struct ev_loop *loop, struct list_head *ifaces)
{
	struct list *i, *r, *d;
	struct iface *iface;
	struct rpl *rpl;
	struct dag *dag;

	DL_FOREACH(ifaces->head, i)
	{
		iface = container_of(i, struct iface, list);

		/* schedule a dis at statup */
		ev_timer_init(&iface->dis_w, send_dis_sec_cb, 1, 1);
		ev_timer_start(loop, &iface->dis_w);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char const *conf_path = PATH_RPLD_CONF;
	struct ev_loop *loop = EV_DEFAULT;
	char *logfile = PATH_RPLD_LOG;
	const char *pname = argv[0];
	int facility = LOG_FACILITY;
	int log_method = L_UNSPEC;
	ev_signal exitsig;
	int opt;
	int rc;

	/* TODO this is a hack need to rework some parts */
	foo = loop;

	/* TODO add longopt as the help says it */
	while ((opt = getopt(argc, argv, "C:m:f:l:d:h")) != -1)
	{
		switch (opt)
		{
		case 'C':
			conf_path = optarg;
			break;
		case 'm':
			if (!strcmp(optarg, "syslog"))
			{
				log_method = L_SYSLOG;
			}
			else if (!strcmp(optarg, "stderr_syslog"))
			{
				log_method = L_STDERR_SYSLOG;
			}
			else if (!strcmp(optarg, "stderr"))
			{
				log_method = L_STDERR;
			}
			else if (!strcmp(optarg, "stderr_clean"))
			{
				log_method = L_STDERR_CLEAN;
			}
			else if (!strcmp(optarg, "logfile"))
			{
				log_method = L_LOGFILE;
			}
			else if (!strcmp(optarg, "none"))
			{
				log_method = L_NONE;
			}
			else
			{
				fprintf(stderr, "%s: unknown log method: %s\n",
						pname, optarg);
				exit(1);
			}
			break;
		case 'f':
			facility = atoi(optarg);
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'd':
			/* TODO I hate atoi() ? */
			set_debuglevel(atoi(optarg));
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(0);
		default:
			usage(stderr, argv[0]);
			exit(1);
		}
	}

	init_random_gen();
	ev_signal_init(&exitsig, sigint_cb, SIGINT);
	ev_signal_start(loop, &exitsig);

	if (log_method == L_UNSPEC)
		log_method = L_STDERR;
	if (log_open(log_method, pname, logfile, facility) < 0)
	{
		perror("log_open");
		exit(1);
	}

	flog(LOG_INFO, "version %s started", VERSION);

	rc = netlink_open();
	if (rc == -1)
	{
		perror("mnl_socket_open");
		exit(1);
	}

	rc = config_load(conf_path, &ifaces);
	if (rc < 0)
	{
		netlink_close();
		flog(LOG_ERR, "Failed to parse config: %s", conf_path);
		exit(1);
	}

	rc = rpld_setup(loop, &ifaces);
	if (rc != 0)
	{
		netlink_close();
		config_free(&ifaces);
		exit(1);
	}

	rc = set_var(PROC_SYS_IP6_MAX_HBH_OPTS_NUM, 99);
	if (rc == -1)
	{
		flog(LOG_ERR, "Failed to set hbh max value");
		return -1;
	}

	sock = open_icmpv6_socket(&ifaces);
	if (sock < 0)
	{
		perror("open_icmpv6_socket");
		netlink_close();
		config_free(&ifaces);
		exit(1);
	}

	ev_async_init(&icmpv6_async, icmpv6_async_cb);
	ev_async_start(loop, &icmpv6_async);

	ev_run(loop, 0);

	netlink_close();
	close_icmpv6_socket(sock, &ifaces);
	config_free(&ifaces);
	log_close();

	flog(LOG_INFO, "exited");

	return 0;
}
