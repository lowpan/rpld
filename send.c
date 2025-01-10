/*
 *   Authors:
 *    Alexander Aring		<alex.aring@gmail.com>
 *
 *   Original Authors:
 *    Lars Fenneberg		<lf@elemental.net>
 *
 *   This software is Copyright 1996,1997,2019 by the above mentioned author(s),
 *   All Rights Reserved.
 *
 *   The license which is distributed with this software in the file COPYRIGHT
 *   applies to this software. If your distribution is missing this file, you
 *   may request it from <alex.aring@gmail.com>.
 */

#include <linux/ipv6.h>
#include <netinet/icmp6.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "helpers.h"
#include "buffer.h"
#include "config.h"
#include "config.h"
#include "send.h"
#include "log.h"
#include "rpl.h"

struct nd_rpl_sender_keys sender_keys;

static int really_send(int sock, const struct iface *iface,
					   const struct in6_addr *dest,
					   struct safe_buffer *sb)
{
	struct sockaddr_in6 addr;
	int rc;
	memset((void *)&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(IPPROTO_ICMPV6);
	memcpy(&addr.sin6_addr, dest, sizeof(struct in6_addr));

	struct iovec iov;
	iov.iov_len = sb->used;
	iov.iov_base = (caddr_t)sb->buffer;

	char __attribute__((aligned(8))) chdr[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	memset(chdr, 0, sizeof(chdr));
	struct cmsghdr *cmsg = (struct cmsghdr *)chdr;

	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;

	struct in6_pktinfo *pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pkt_info->ipi6_ifindex = iface->ifindex;
	memcpy(&pkt_info->ipi6_addr, iface->ifaddr_src, sizeof(struct in6_addr));

#ifdef HAVE_SIN6_SCOPE_ID
	if (IN6_IS_ADDR_LINKLOCAL(&addr.sin6_addr) || IN6_IS_ADDR_MC_LINKLOCAL(&addr.sin6_addr))
		addr.sin6_scope_id = iface->ifindex;
#endif

	struct msghdr mhdr;
	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_name = (caddr_t)&addr;
	mhdr.msg_namelen = sizeof(struct sockaddr_in6);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (void *)cmsg;
	mhdr.msg_controllen = sizeof(chdr);

	flog(LOG_INFO, "Sending message, message header.len: %d; mhdr.msg_iov.iov_len: %lu", mhdr.msg_namelen, mhdr.msg_iov->iov_len);

	rc = sendmsg(sock, &mhdr, 0);
	safe_buffer_free(sb);

	return rc;
}
void send_dio(int sock, struct dag *dag)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dio(dag, sb);
	rc = really_send(sock, dag->iface, &all_rpl_addr, sb);
	
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(&all_rpl_addr.in6_u, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Dio to: %s", addr_str);
}

void send_dio_sec(int sock, struct dag *dag)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dio_sec(dag, sb);
	flog(LOG_INFO, "send_dio_sec buffer: %s", get_hex_str(sb->buffer, sb->used));
	rc = really_send(sock, dag->iface, &all_rpl_addr, sb);
	
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(&all_rpl_addr.in6_u, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Sec Dio to: %s", addr_str);
}

void send_dao(int sock, const struct in6_addr *to, struct dag *dag)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dao(dag, sb);
	rc = really_send(sock, dag->iface, to, sb);
	
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(to, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Dao to: %s", addr_str);
}

void send_dao_sec(int sock, const struct in6_addr *to, struct dag *dag)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dao_sec(dag, sb);
	rc = really_send(sock, dag->iface, to, sb);
	
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(to, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Sec Dao to: %s", addr_str);
}

void send_dao_ack(int sock, const struct in6_addr *to, struct dag *dag)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dao_ack(dag, sb);
	rc = really_send(sock, dag->iface, to, sb);
	
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(to, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Dao Ack to: %s", addr_str);
}

void send_dao_ack_sec(int sock, const struct in6_addr *to, struct dag *dag)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dao_ack_sec(dag, sb);
	rc = really_send(sock, dag->iface, to, sb);
	
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(to, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Sec Dao Ack to: %s", addr_str);
}

void send_dis(int sock, struct iface *iface)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dis(sb);
	rc = really_send(sock, iface, &all_rpl_addr, sb);

	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(&all_rpl_addr.in6_u, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Dis to: %s", addr_str);
}

void send_dis_sec(int sock, struct iface *iface)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_dis_sec(sb);
	rc = really_send(sock, iface, &all_rpl_addr, sb);

	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(&all_rpl_addr.in6_u, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent Sec Dis to: %s", addr_str);
}

void send_pk(int sock, struct iface *iface)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_pk(sb, iface);
	rc = really_send(sock, iface, &all_rpl_addr, sb);
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(&all_rpl_addr.in6_u, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent PK to: %s", addr_str);
}

void send_ct(int sock, const struct in6_addr *to, struct iface *iface, u_int8_t *rec_pk)
{
	struct safe_buffer *sb;
	int rc;

	sb = safe_buffer_new();
	if (!sb)
		return;

	dag_build_ct(sb, rec_pk, iface->enc_mode);
	rc = really_send(sock, iface, to, sb);

	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(to, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Sent CT to: %s", addr_str);
}
