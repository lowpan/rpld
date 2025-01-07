/*
 *   Authors:
 *    Alexander Aring           <alex.aring@gmail.com>
 *
 *   Original Authors:
 *    Lars Fenneberg            <lf@elemental.net>
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

#include <stdio.h>

#include "process.h"
#include "netlink.h"
#include "send.h"
#include "dag.h"
#include "log.h"
#include "rpl.h"
#include "config.h"
#include "crypto/aes/tiny-AES-c-master/aes.h"

#include "crypto/kyber/ref/kem.h"

void dagid_to_hex(const uint8_t *rpl_dagid, char *dagid_hex)
{
	for (int i = 0; i < 16; i++)
	{
		sprintf(&dagid_hex[i * 2], "%02x", rpl_dagid[i]);
	}
	dagid_hex[32] = '\0';
	//     flog(LOG_INFO, "DODAGID em hexadecimal: %s", dagid_hex);
}

uint8_t *decrypt_dodagid(const char *dagid_hex)
{
	flog(LOG_INFO, "Iniciando a descriptografia do DODAGID");

	//  flog(LOG_INFO, "DODAGID antes da descriptografia %s", dagid_hex);

	const uint8_t *aes_key = get_aes_key();
	log_hex("AES key", aes_key, 16);
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	flog(LOG_INFO, "Chave AES inicializada com sucesso");

	uint8_t data_to_decrypt[16];
	for (int i = 0; i < 16; i++)
	{
		sscanf(&dagid_hex[i * 2], "%02hhx", &data_to_decrypt[i]);
	}

	AES_ECB_decrypt(&ctx, data_to_decrypt);

	static uint8_t decrypted_data[16];
	memcpy(decrypted_data, data_to_decrypt, 16);

	flog(LOG_INFO, "Descriptografia do DODAGID concluída");

	/*flog(LOG_INFO, "DODAGID descriptografado: ");
	for (int i = 0; i < 16; i++) {
		flog(LOG_INFO, "%02x", decrypted_data[i]);
	}*/

	return decrypted_data;
}

static void process_dio(int sock, struct iface *iface, const void *msg,
						size_t len, struct sockaddr_in6 *addr)
{
	struct nd_rpl_dio *dio = msg;
	const struct rpl_dio_destprefix *diodp;
	char addr_str[INET6_ADDRSTRLEN];
	struct in6_prefix pfx;
	struct dag *dag;
	uint16_t rank;

	if (len < sizeof(*dio))
	{
		flog(LOG_INFO, "dio length mismatch, drop");
		return;
	}
	len -= sizeof(*dio);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received dio %s", addr_str);

	char dagid_hex[33];
	dagid_to_hex((uint8_t *)dio->rpl_dagid.s6_addr, dagid_hex);
	// flog(LOG_INFO, "Consulta do DODAGID no process.c %s", dagid_hex);

	uint8_t *decrypted_dagid = decrypt_dodagid(dagid_hex);

	/*flog(LOG_INFO, "DODAGID após descriptografia no process.c ");
	  for (int i = 0; i < 16; i++) {
	 flog(LOG_INFO, "%02x", decrypted_dagid[i]);
	}*/

	memcpy(dio->rpl_dagid.s6_addr, decrypted_dagid, 16);

	dag = dag_lookup(iface, dio->rpl_instanceid,
					 &dio->rpl_dagid);
	if (dag)
	{
		if (dag->my_rank == 1)
			return;
	}
	else
	{
		diodp = (struct rpl_dio_destprefix *)(((unsigned char *)msg) + sizeof(*dio));

		if (len < sizeof(*diodp) - 16)
		{
			flog(LOG_INFO, "diodp length mismatch, drop");
			return;
		}
		len -= sizeof(*diodp) - 16;

		if (diodp->rpl_dio_type != 0x3)
		{
			flog(LOG_INFO, "we assume diodp - not supported, drop");
			return;
		}

		if (len < bits_to_bytes(diodp->rpl_dio_prefixlen))
		{
			flog(LOG_INFO, "diodp prefix length mismatch, drop");
			return;
		}
		len -= bits_to_bytes(diodp->rpl_dio_prefixlen);

		pfx.len = diodp->rpl_dio_prefixlen;
		memcpy(&pfx.prefix, &diodp->rpl_dio_prefix,
			   bits_to_bytes(pfx.len));

		flog(LOG_INFO, "received but no dag found %s", addr_str);

		dag = dag_create(iface, dio->rpl_instanceid,
						 &dio->rpl_dagid, DEFAULT_TICKLE_T,
						 UINT16_MAX, dio->rpl_version, &pfx);
		if (!dag)
			return;

		addrtostr(&dio->rpl_dagid, addr_str, sizeof(addr_str));
		flog(LOG_INFO, "created dag %s", addr_str);
	}

	flog(LOG_INFO, "process dio %s", addr_str);

	rank = ntohs(dio->rpl_dagrank);
	if (!dag->parent)
	{
		dag->parent = dag_peer_create(&addr->sin6_addr);
		if (!dag->parent)
			return;
	}

	if (rank > dag->parent->rank)
		return;

	dag->parent->rank = rank;
	dag->my_rank = rank + 1;

	dag_process_dio(dag);

	if (dag->parent)
		send_dao(sock, &dag->parent->addr, dag);
}

void decrypt_dio_sec(void *msg, uint8_t *decrypted_data)
{
	flog(LOG_INFO, "decrypt dio_sec");
	uint8_t encrypted_data[32];
	memcpy(encrypted_data, msg + 9, 8);
	memcpy(encrypted_data + 8, msg + 51, 5);
	memcpy(encrypted_data + 13, msg + 58, 3);
	memcpy(encrypted_data + 16, msg + 17, 16);

	const uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	log_hex("decrypt_dio_sec AES key", aes_key, 16);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	log_hex("DIO to decrypt", encrypted_data, 32);
	AES_ECB_decrypt(&ctx, encrypted_data);
	AES_ECB_decrypt(&ctx, encrypted_data + 16);
	log_hex("DIO decrypted", encrypted_data, 32);

	memcpy(decrypted_data, encrypted_data, sizeof(encrypted_data));
}

static void process_dio_sec(int sock, struct iface *iface, void *msg,
							size_t len, struct sockaddr_in6 *addr)
{
	const struct nd_rpl_security *dio_sec = (const struct nd_rpl_security *)msg;
	const struct nd_rpl_dio *dio = (const struct nd_rpl_dio *)(msg + sizeof(struct nd_rpl_security) + 1);
	// const struct nd_rpl_dio *dio = msg;
	const struct rpl_dio_destprefix *diodp;
	char addr_str[INET6_ADDRSTRLEN];
	struct in6_prefix pfx;
	struct dag *dag;
	uint16_t rank;

	log_hex("Encrypted DIO in process_dio_sec", msg, len);

	uint8_t decrypted_dio[32];

	decrypt_dio_sec(msg, decrypted_dio);

	memcpy(msg + 9, decrypted_dio, 8);
	memcpy(msg + 51, decrypted_dio + 8, 5);
	memcpy(msg + 58, decrypted_dio + 13, 3);
	memcpy(msg + 17, decrypted_dio + 16, 16);

	log_hex("msg information after decryption", msg, len);

	if (len < sizeof(*dio))
	{
		flog(LOG_INFO, "dio length mismatch, drop");
		return;
	}
	len -= sizeof(*dio);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received dio %s", addr_str);

	dag = dag_lookup(iface, dio->rpl_instanceid,
					 &dio->rpl_dagid);
	if (dag)
	{
		if (dag->my_rank == 1)
			return;
	}
	else
	{
		diodp = (struct rpl_dio_destprefix *)(((unsigned char *)msg) + sizeof(*dio) + sizeof(dio_sec) + 1);

		if (len < sizeof(*diodp) - 16)
		{
			flog(LOG_INFO, "diodp length mismatch, drop");
			return;
		}
		len -= sizeof(*diodp) - 16;

		if (diodp->rpl_dio_type != 0x3)
		{
			flog(LOG_INFO, "we assume diodp - not supported, drop");
			return;
		}

		if (len < bits_to_bytes(diodp->rpl_dio_prefixlen))
		{
			flog(LOG_INFO, "diodp prefix length mismatch, drop");
			return;
		}
		len -= bits_to_bytes(diodp->rpl_dio_prefixlen);
		pfx.len = diodp->rpl_dio_prefixlen;
		memcpy(&pfx.prefix, &diodp->rpl_dio_prefix,
			   bits_to_bytes(pfx.len));

		flog(LOG_INFO, "received but no dag found %s", addr_str);
		dag = dag_create(iface, dio->rpl_instanceid,
						 &dio->rpl_dagid, DEFAULT_TICKLE_T,
						 UINT16_MAX, dio->rpl_version, &pfx);
		if (!dag)
			return;

		addrtostr(&dio->rpl_dagid, addr_str, sizeof(addr_str));
		flog(LOG_INFO, "created dag %s", addr_str);
	}

	flog(LOG_INFO, "process dio %s", addr_str);

	rank = ntohs(dio->rpl_dagrank);
	if (!dag->parent)
	{
		dag->parent = dag_peer_create(&addr->sin6_addr);
		if (!dag->parent)
			return;
	}

	if (rank > dag->parent->rank)
		return;

	dag->parent->rank = rank;
	dag->my_rank = rank + 1;

	dag_process_dio_sec(dag);

	if (dag->parent)
		send_dao_sec(sock, &dag->parent->addr, dag);
}

static void process_dao(int sock, struct iface *iface, const void *msg,
						size_t len, struct sockaddr_in6 *addr)
{
	const struct rpl_dao_target *target;
	const struct nd_rpl_dao *dao = msg;
	char addr_str[INET6_ADDRSTRLEN];
	const struct nd_rpl_opt *opt;
	const unsigned char *p;
	struct child *child;
	struct dag *dag;
	struct list *c;
	int optlen;
	int rc;

	if (len < sizeof(*dao))
	{
		flog(LOG_INFO, "dao length mismatch, drop");
		return;
	}
	len -= sizeof(*dao);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received dao %s", addr_str);

	char dagid_hex[33];
	dagid_to_hex((uint8_t *)dao->rpl_dagid.s6_addr, dagid_hex);
	// flog(LOG_INFO, "Consulta do DODAGID no process.c %s", dagid_hex);

	uint8_t *decrypted_dagid = decrypt_dodagid(dagid_hex);

	/*flog(LOG_INFO, "DODAGID após descriptografia no process.c ");
	for (int i = 0; i < 16; i++) {
		flog(LOG_INFO, "%02x", decrypted_dagid[i]);
	}*/

	memcpy(dao->rpl_dagid.s6_addr, decrypted_dagid, 16);

	dag = dag_lookup(iface, dao->rpl_instanceid,
					 &dao->rpl_dagid);
	if (!dag)
	{
		addrtostr(&dao->rpl_dagid, addr_str, sizeof(addr_str));
		flog(LOG_INFO, "can't find dag %s", addr_str);
		return;
	}

	p = msg;
	p += sizeof(*dao);
	optlen = len;
	flog(LOG_INFO, "dao optlen %d", optlen);
	while (optlen > 0)
	{
		opt = (const struct nd_rpl_opt *)p;

		if (optlen < sizeof(*opt))
		{
			flog(LOG_INFO, "rpl opt length mismatch, drop");
			return;
		}

		flog(LOG_INFO, "dao opt %d", opt->type);
		switch (opt->type)
		{
		case RPL_DAO_RPLTARGET:
			target = (const struct rpl_dao_target *)p;
			if (optlen < sizeof(*opt))
			{
				flog(LOG_INFO, "rpl target length mismatch, drop");
				return;
			}

			addrtostr(&target->rpl_dao_prefix, addr_str, sizeof(addr_str));
			flog(LOG_INFO, "dao target %s", addr_str);
			dag_lookup_child_or_create(dag,
									   &target->rpl_dao_prefix,
									   &addr->sin6_addr);
			break;
		default:
			/* IGNORE NOT SUPPORTED */
			break;
		}

		/* TODO critical, we trust opt->len here... which is wire data */
		optlen -= (2 + opt->len);
		p += (2 + opt->len);
		flog(LOG_INFO, "dao optlen %d", optlen);
	}

	DL_FOREACH(dag->childs.head, c)
	{
		child = container_of(c, struct child, list);

		rc = nl_add_route_via(dag->iface->ifindex, &child->addr,
							  &child->from);
		flog(LOG_INFO, "via route %d %s", rc, strerror(errno));
	}

	flog(LOG_INFO, "process dao %s", addr_str);
	send_dao_ack(sock, &addr->sin6_addr, dag);
}

void decrypt_dao_sec(void *msg, uint8_t *decrypted_data)
{
	flog(LOG_INFO, "decrypt_dao_sec");
	uint8_t encrypted_data[32];
	memcpy(encrypted_data, msg + 9, 4);
	memcpy(encrypted_data + 4, msg + 51, 5);
	memcpy(encrypted_data + 9, msg + 58, 5);
	memcpy(encrypted_data + 14, msg + 65, 2);
	memcpy(encrypted_data + 16, msg + 13, 16);

	const uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	log_hex("decrypt_dao_sec AES key", aes_key, 16);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	log_hex("DAO to decrypt", encrypted_data, 32);
	AES_ECB_decrypt(&ctx, encrypted_data);
	AES_ECB_decrypt(&ctx, encrypted_data + 16);
	log_hex("DAO decrypted", encrypted_data, 32);

	memcpy(decrypted_data, encrypted_data, sizeof(encrypted_data));
}

static void process_dao_sec(int sock, struct iface *iface, void *msg,
							size_t len, struct sockaddr_in6 *addr)
{
	const struct nd_rpl_security *dao_sec = (const struct nd_rpl_security *)msg;
	const struct nd_rpl_dao *dao = (const struct nd_rpl_dao *)(msg + sizeof(struct nd_rpl_security) + 1);
	const struct rpl_dao_target *target;
	// const struct nd_rpl_dao *dao = msg;
	char addr_str[INET6_ADDRSTRLEN];
	const struct nd_rpl_opt *opt;
	const unsigned char *p;
	struct child *child;
	struct dag *dag;
	struct list *c;
	int optlen;
	int rc;

	uint8_t decrypted_dao[32];

	decrypt_dao_sec(msg, decrypted_dao);
	// log_hex("DECRYPTED DAO", decrypted_dao, 32);

	log_hex("msg information before decryption", msg, len);

	memcpy(msg + 9, decrypted_dao, 4);
	memcpy(msg + 51, decrypted_dao + 4, 5);
	memcpy(msg + 58, decrypted_dao + 9, 5);
	memcpy(msg + 65, decrypted_dao + 13, 2);
	memcpy(msg + 13, decrypted_dao + 16, 16);

	log_hex("msg information after decryption", msg, len);

	if (len < sizeof(*dao))
	{
		flog(LOG_INFO, "dao length mismatch, drop");
		return;
	}
	len -= sizeof(*dao);
	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received dao_sec %s", addr_str);

	dag = dag_lookup(iface, dao->rpl_instanceid,
					 &dao->rpl_dagid);
	if (!dag)
	{
		addrtostr(&dao->rpl_dagid, addr_str, sizeof(addr_str));
		flog(LOG_INFO, "can't find dag sec %s", addr_str);
		return;
	}

	p = msg;
	p += sizeof(*dao);
	optlen = len;
	flog(LOG_INFO, "dao optlen %d", optlen);
	while (optlen > 0)
	{
		opt = (const struct nd_rpl_opt *)p;

		if (optlen < sizeof(*opt))
		{
			flog(LOG_INFO, "rpl opt length mismatch, drop");
			return;
		}

		flog(LOG_INFO, "dao opt %d", opt->type);
		switch (opt->type)
		{
		case RPL_DAO_RPLTARGET:
			target = (const struct rpl_dao_target *)p;
			if (optlen < sizeof(*opt))
			{
				flog(LOG_INFO, "rpl target length mismatch, drop");
				return;
			}

			addrtostr(&target->rpl_dao_prefix, addr_str, sizeof(addr_str));
			flog(LOG_INFO, "dao_sec target %s", addr_str);
			dag_lookup_child_or_create(dag,
									   &target->rpl_dao_prefix,
									   &addr->sin6_addr);
			break;
		default:
			/* IGNORE NOT SUPPORTED */
			break;
		}

		/* TODO critical, we trust opt->len here... which is wire data */
		optlen -= (2 + opt->len);
		p += (2 + opt->len);
		flog(LOG_INFO, "dao optlen %d", optlen);
	}

	DL_FOREACH(dag->childs.head, c)
	{
		child = container_of(c, struct child, list);

		rc = nl_add_route_via(dag->iface->ifindex, &child->addr,
							  &child->from);
		flog(LOG_INFO, "via route %d %s", rc, strerror(errno));
	}

	flog(LOG_INFO, "process dao_sec %s", addr_str);
	send_dao_ack_sec(sock, &addr->sin6_addr, dag);
}

static void process_daoack(int sock, struct iface *iface, const void *msg,
						   size_t len, struct sockaddr_in6 *addr)
{
	const struct nd_rpl_daoack *daoack = msg;
	char addr_str[INET6_ADDRSTRLEN];
	struct dag *dag;
	int rc;

	if (len < sizeof(*daoack))
	{
		flog(LOG_INFO, "rpl daoack length mismatch, drop");
		return;
	}

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received daoack %s", addr_str);

	char dagid_hex[33];
	dagid_to_hex((uint8_t *)daoack->rpl_dagid.s6_addr, dagid_hex);
	// flog(LOG_INFO, "Consulta do DODAGID_DAOACK no process.c %s", dagid_hex);

	uint8_t *decrypted_dagid = decrypt_dodagid(dagid_hex);

	/*flog(LOG_INFO, "DODAGID após descriptografia no process.c ");
	for (int i = 0; i < 16; i++) {
		flog(LOG_INFO, "%02x", decrypted_dagid[i]);
	}*/

	memcpy(daoack->rpl_dagid.s6_addr, decrypted_dagid, 16);

	dag = dag_lookup(iface, daoack->rpl_instanceid,
					 &daoack->rpl_dagid);
	if (!dag)
	{
		addrtostr(&daoack->rpl_dagid, addr_str, sizeof(addr_str));
		flog(LOG_INFO, "can't find dag %s", addr_str);
		return;
	}

	if (dag->parent)
	{
		rc = nl_add_route_default(dag->iface->ifindex, &dag->parent->addr);
		flog(LOG_INFO, "default route %d %s", rc, strerror(errno));
	}
}

void decrypt_daoack_sec(const void *msg, uint8_t *decrypted_data)
{
	flog(LOG_INFO, "decrypt_daoack_sec");
	uint8_t encrypted_data[32];
	memcpy(encrypted_data, msg + 9, 4);
	memcpy(encrypted_data + 4, msg + 31, 5);
	memcpy(encrypted_data + 9, msg + 38, 5);
	memcpy(encrypted_data + 14, msg + 45, 2);
	memcpy(encrypted_data + 16, msg + 13, 16);

	const uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	log_hex("decrypt_daoack_sec AES key", aes_key, 16);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	log_hex("DAOACK to decrypt", encrypted_data, 32);
	AES_ECB_decrypt(&ctx, encrypted_data);
	AES_ECB_decrypt(&ctx, encrypted_data + 16);
	log_hex("DAOACK decrypted", encrypted_data, 32);

	memcpy(decrypted_data, encrypted_data, sizeof(encrypted_data));
}

static void process_daoack_sec(int sock, struct iface *iface, const void *msg,
							   size_t len, struct sockaddr_in6 *addr)
{
	const struct nd_rpl_security *daoack_sec = (const struct nd_rpl_security *)msg;
	const struct nd_rpl_daoack *daoack = (const struct nd_rpl_daoack *)(msg + sizeof(struct nd_rpl_security) + 1);
	// const struct nd_rpl_daoack *daoack = msg;
	char addr_str[INET6_ADDRSTRLEN];
	struct dag *dag;
	int rc;

	log_hex("Encrypted DAOACK in process_daoack_sec", msg, len);

	uint8_t decrypted_daoack[32];

	decrypt_daoack_sec(msg, decrypted_daoack);

	log_hex("msg information before decryption", msg, len);

	memcpy(msg + 9, decrypted_daoack, 4);
	memcpy(msg + 31, decrypted_daoack + 4, 5);
	memcpy(msg + 38, decrypted_daoack + 9, 5);
	memcpy(msg + 45, decrypted_daoack + 13, 2);
	memcpy(msg + 13, decrypted_daoack + 16, 16);

	log_hex("msg information after decryption", msg, len);

	if (len < sizeof(*daoack))
	{
		flog(LOG_INFO, "rpl daoack length mismatch, drop");
		return;
	}

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received daoack %s", addr_str);
	log_hex("DODAGID ACK", daoack->rpl_dagid.s6_addr, 16);
	dag = dag_lookup(iface, daoack->rpl_instanceid,
					 &daoack->rpl_dagid);
	if (!dag)
	{
		addrtostr(&daoack->rpl_dagid, addr_str, sizeof(addr_str));
		flog(LOG_INFO, "can't find dag daoack_sec %s", addr_str);
		return;
	}

	if (dag->parent)
	{
		rc = nl_add_route_default(dag->iface->ifindex, &dag->parent->addr);
		flog(LOG_INFO, "default route %d %s", rc, strerror(errno));
	}
}

static void process_dis(int sock, struct iface *iface, void *msg,
						size_t len, struct sockaddr_in6 *addr)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct list *r, *d;
	struct rpl *rpl;
	struct dag *dag;

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received dis %s", addr_str);

	DL_FOREACH(iface->rpls.head, r)
	{
		rpl = container_of(r, struct rpl, list);
		DL_FOREACH(rpl->dags.head, d)
		{
			dag = container_of(d, struct dag, list);

			send_dio(sock, dag);
		}
	}
}

void decrypt_dis_sec(void *msg, uint8_t *decrypted_data)
{
	flog(LOG_INFO, "decrypt_dis_sec");
	uint8_t encrypted_data[16];
	memcpy(encrypted_data, msg + 8, 2);
	memcpy(encrypted_data + 2, msg + 13, 5);
	memcpy(encrypted_data + 7, msg + 20, 5);
	memcpy(encrypted_data + 12, msg + 27, 4);

	const uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	log_hex("decrypt_dis_sec AES key", aes_key, 16);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	log_hex("DIS to decrypt", encrypted_data, 16);
	AES_ECB_decrypt(&ctx, encrypted_data);
	log_hex("DIS decrypted", encrypted_data, 16);

	memcpy(decrypted_data, encrypted_data, sizeof(encrypted_data));
}

static void process_dis_sec(int sock, struct iface *iface, void *msg,
							size_t len, struct sockaddr_in6 *addr)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct list *r, *d;
	struct rpl *rpl;
	struct dag *dag;

	/*log_hex("Encrypted DIS in process_dis_sec", msg, len);

	uint8_t decrypted_dis[16];

	decrypt_dis_sec(msg, decrypted_dis);

	log_hex("Decrypted DIS in process_dis_sec", decrypted_dis, 16);

	log_hex("msg information before decryption", msg, len);

	memcpy(msg + 8, decrypted_dis, 2);
	memcpy(msg + 13, decrypted_dis + 2, 5);
	memcpy(msg + 20, decrypted_dis + 7, 5);
	memcpy(msg + 27, decrypted_dis + 12, 4);

	log_hex("msg information after decryption", msg, len);*/

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "received dis %s", addr_str);

	DL_FOREACH(iface->rpls.head, r)
	{
		rpl = container_of(r, struct rpl, list);
		DL_FOREACH(rpl->dags.head, d)
		{
			dag = container_of(d, struct dag, list);

			send_dio_sec(sock, dag);
		}
	}
}

/**
 * @brief
 *
 * @param sock int representing the socket
 * @param iface interface structure
 * @param msg received data from the ICMPv6 packet
 * @param len length of the received data
 * @param addr Socket address
 */
static void process_pk_sec_exch(int sock, struct iface *iface, const void *msg,
								size_t len)
{
	u_int8_t pk[CRYPTO_PUBLICKEYBYTES];
	if (len < CRYPTO_PUBLICKEYBYTES)
	{
		flog(LOG_WARNING, "received packet too short for public key exchange");
		return;
	}
	memcpy(pk, msg, CRYPTO_PUBLICKEYBYTES);
	// log_hex("Saved Received Public Key: ", pk, CRYPTO_PUBLICKEYBYTES);

	send_ct(sock, iface, &pk);
}

static void process_ct_sec_exch(const void *msg, size_t len)
{
	u_int8_t ct[CRYPTO_CIPHERTEXTBYTES];
	if (len < CRYPTO_CIPHERTEXTBYTES)
	{
		flog(LOG_WARNING, "received packet too short for ciphertext exchange");
		return;
	}
	memcpy(ct, msg, CRYPTO_CIPHERTEXTBYTES);
	// log_hex("Received Ciphertext: ", ct, CRYPTO_CIPHERTEXTBYTES);

	// log_hex("Using static Secret Key to decapsulate", sender_keys.rpl_sec_skey, CRYPTO_SECRETKEYBYTES);
	crypto_kem_dec(shared_secret, ct, sender_keys.rpl_sec_skey);
	log_hex("Decapsulated Shared Secret: ", shared_secret, CRYPTO_BYTES);
}

void process_exchange(int sock, const struct list_head *ifaces, unsigned char *msg,
					  int len, struct sockaddr_in6 *addr, struct in6_pktinfo *pkt_info,
					  int hoplimit, struct ev_loop *loop, ev_io *w)
{
	flog(LOG_INFO, "process exchange");
	char addr_str[INET6_ADDRSTRLEN];
	char if_namebuf[IFNAMSIZ] = {""};
	char *if_name = if_indextoname(pkt_info->ipi6_ifindex, if_namebuf);
	if (!if_name)
	{
		if_name = "unknown interface";
	}
	dlog(LOG_DEBUG, 4, "%s received a packet", if_name);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));

	if (!pkt_info)
	{
		flog(LOG_WARNING, "%s received packet with no pkt_info from %s!", if_name, addr_str);
		return;
	}

	/*
	 * can this happen?
	 */

	if (len < 4)
	{
		flog(LOG_WARNING, "%s received icmpv6 packet with invalid length (%d) from %s", if_name, len, addr_str);
		return;
	}
	len -= 4;

	struct icmp6_hdr *icmph = (struct icmp6_hdr *)msg;
	struct iface *iface = iface_find_by_ifindex(ifaces, pkt_info->ipi6_ifindex);
	if (!iface)
	{
		dlog(LOG_WARNING, 4, "%s received icmpv6 RS/RA packet on an unknown interface with index %d", if_name,
			 pkt_info->ipi6_ifindex);
		return;
	}

	if (icmph->icmp6_type != ND_RPL_MESSAGE)
	{
		/*
		 *      We just want to listen to RPL
		 */

		flog(LOG_ERR, "%s icmpv6 filter failed", if_name);
		return;
	}

	switch (icmph->icmp6_code)
	{
	case ND_RPL_SEC_PK_EXCH:
		flog(LOG_INFO, "Received ICMPv6 pk_sec_exch from address: %s; ICMPv6 type: %u; code: %u; checksum: %X",
			 addr_str, icmph->icmp6_type, icmph->icmp6_code, icmph->icmp6_cksum);
		// log_hex("ICMPv6 data received: ", &icmph->icmp6_dataun, len);
		process_pk_sec_exch(sock, iface, &icmph->icmp6_dataun, len);
		ev_io_stop(loop, w);
		ev_break(loop, EVBREAK_ONE);
		break;
	case ND_RPL_SEC_CT_EXCH:
		flog(LOG_INFO, "Received ICMPv6 ct_sec_exch from address: %s; ICMPv6 type: %u; code: %u; checksum: %X",
			 addr_str, icmph->icmp6_type, icmph->icmp6_code, icmph->icmp6_cksum);
		// log_hex("ICMPv6 data received: ", &icmph->icmp6_dataun, len);
		process_ct_sec_exch(&icmph->icmp6_dataun, len);
		ev_io_stop(loop, w);
		ev_break(loop, EVBREAK_ONE);
		break;
	default:
		flog(LOG_ERR, "%s received code for non exchange purpose: 0x%02x",
			 if_name, icmph->icmp6_code);
		break;
	}
}

void process(int sock, const struct list_head *ifaces, unsigned char *msg,
			 int len, struct sockaddr_in6 *addr, struct in6_pktinfo *pkt_info,
			 int hoplimit)
{
	char addr_str[INET6_ADDRSTRLEN];
	char if_namebuf[IFNAMSIZ] = {""};
	char *if_name = if_indextoname(pkt_info->ipi6_ifindex, if_namebuf);
	if (!if_name)
	{
		if_name = "unknown interface";
	}
	dlog(LOG_DEBUG, 4, "%s received a packet", if_name);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));

	if (!pkt_info)
	{
		flog(LOG_WARNING, "%s received packet with no pkt_info from %s!", if_name, addr_str);
		return;
	}

	/*
	 * can this happen?
	 */

	if (len < 4)
	{
		flog(LOG_WARNING, "%s received icmpv6 packet with invalid length (%d) from %s", if_name, len, addr_str);
		return;
	}
	len -= 4;

	struct icmp6_hdr *icmph = (struct icmp6_hdr *)msg;
	struct iface *iface = iface_find_by_ifindex(ifaces, pkt_info->ipi6_ifindex);
	if (!iface)
	{
		dlog(LOG_WARNING, 4, "%s received icmpv6 RS/RA packet on an unknown interface with index %d", if_name,
			 pkt_info->ipi6_ifindex);
		return;
	}

	if (icmph->icmp6_type != ND_RPL_MESSAGE)
	{
		/*
		 *      We just want to listen to RPL
		 */

		flog(LOG_ERR, "%s icmpv6 filter failed", if_name);
		return;
	}

	switch (icmph->icmp6_code)
	{
	case ND_RPL_DAG_IS:
		process_dis(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	case ND_RPL_SEC_DAG_IS:
		process_dis_sec(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	case ND_RPL_DAG_IO:
		process_dio(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	case ND_RPL_SEC_DAG_IO:
		process_dio_sec(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	case ND_RPL_DAO:
		process_dao(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	case ND_RPL_SEC_DAG:
		process_dao_sec(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	case ND_RPL_DAO_ACK:
		process_daoack(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	case ND_RPL_SEC_DAG_ACK:
		process_daoack_sec(sock, iface, &icmph->icmp6_dataun, len, addr);
		break;
	default:
		flog(LOG_ERR, "%s received unsupported RPL code 0x%02x",
			 if_name, icmph->icmp6_code);
		break;
	}
}
