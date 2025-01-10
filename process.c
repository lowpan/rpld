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
#include "crypto/kyber/ref/indcpa.h"

void dagid_to_hex(const uint8_t *rpl_dagid, char *dagid_hex)
{
	for (int i = 0; i < 16; i++)
	{
		sprintf(&dagid_hex[i * 2], "%02x", rpl_dagid[i]);
	}
	dagid_hex[32] = '\0';
}

uint8_t *decrypt_dodagid(const char *dagid_hex)
{
	uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	flog(LOG_INFO, "Iniciando a descriptografia do DODAGID");

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

	return decrypted_data;
}

static void process_dio(int sock, struct iface *iface, const void *msg,
						size_t len, struct sockaddr_in6 *addr)
{
	const struct nd_rpl_dio *dio = msg;
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
	flog(LOG_INFO, "Received Dio from %s", addr_str);

	char dagid_str[INET6_ADDRSTRLEN];
	addrtostr(&dio->rpl_dagid, dagid_str, sizeof(addr_str));
	flog(LOG_INFO, "Dag lookup for iface: %s, rpl_instanceid: %d, rpld_dagid: %s", iface->ifname, dio->rpl_instanceid, dagid_str);

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
	// log_hex("decrypt_dio_sec AES key", aes_key, 16);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	// log_hex("DIO to decrypt", encrypted_data, 32);
	AES_ECB_decrypt(&ctx, encrypted_data);
	AES_ECB_decrypt(&ctx, encrypted_data + 16);
	// log_hex("DIO decrypted", encrypted_data, 32);

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

	uint8_t decrypted_dio[32];

	decrypt_dio_sec(msg, decrypted_dio);

	memcpy(msg + 9, decrypted_dio, 8);
	memcpy(msg + 51, decrypted_dio + 8, 5);
	memcpy(msg + 58, decrypted_dio + 13, 3);
	memcpy(msg + 17, decrypted_dio + 16, 16);

	if (len < sizeof(*dio))
	{
		flog(LOG_INFO, "dio length mismatch, drop");
		return;
	}
	len -= sizeof(*dio);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Received Sec Dio from %s", addr_str);

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
	flog(LOG_INFO, "Received Dao from %s", addr_str);

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
	// flog(LOG_INFO, "dao optlen %d", optlen);
	while (optlen > 0)
	{
		opt = (const struct nd_rpl_opt *)p;

		if (optlen < sizeof(*opt))
		{
			flog(LOG_INFO, "rpl opt length mismatch, drop");
			return;
		}

		// flog(LOG_INFO, "dao opt %d", opt->type);
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
		// flog(LOG_INFO, "dao optlen %d", optlen);
	}

	DL_FOREACH(dag->childs.head, c)
	{
		child = container_of(c, struct child, list);

		rc = nl_add_route_via(dag->iface->ifindex, &child->addr,
							  &child->from);
		char child_addr_str[INET6_ADDRSTRLEN];
		addrtostr(&child->addr, child_addr_str, sizeof(child_addr_str));
		flog(LOG_INFO, "via route %d %s %s", rc, strerror(errno), child_addr_str);
	}

	// flog(LOG_INFO, "process dao %s", addr_str);
	send_dao_ack(sock, &addr->sin6_addr, dag);
}

// void decrypt_dao_sec(void *msg, uint8_t *decrypted_data)
// {
// 	flog(LOG_INFO, "decrypt_dao_sec");
// 	uint8_t encrypted_data[32];
// 	memcpy(encrypted_data, msg + 9, 1);
// 	memcpy(encrypted_data + 1, msg + 11, 2);
// 	memcpy(encrypted_data + 3, msg + 51, 5);
// 	memcpy(encrypted_data + 8, msg + 58, 5);
// 	memcpy(encrypted_data + 13, msg + 65, 3);
// 	memcpy(encrypted_data + 16, msg + 13, 16);

// 	const uint8_t aes_key[16];
// 	memcpy(aes_key, shared_secret, 16);
// 	// log_hex("decrypt_dao_sec AES key", aes_key, 16);

// 	struct AES_ctx ctx;
// 	AES_init_ctx(&ctx, aes_key);

// 	// log_hex("DAO to decrypt", encrypted_data, 32);
// 	AES_ECB_decrypt(&ctx, encrypted_data);
// 	AES_ECB_decrypt(&ctx, encrypted_data + 16);
// 	// log_hex("DAO decrypted", encrypted_data, 32);

// 	memcpy(decrypted_data, encrypted_data, sizeof(encrypted_data));
// }

u_int8_t *decrypt_dao_sec(u_int8_t *buf_to_dec, size_t len)
{
	const uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	int rounds = len / 16;
	flog(LOG_INFO, "decryption rounds: %d", rounds);
	u_int8_t *decrypted_data = mzalloc(len);
	u_int8_t data_pack_to_decrypt[16];
	for (int i = 0; i < rounds; i++)
	{
		memset(data_pack_to_decrypt, 0, 16);

		memcpy(data_pack_to_decrypt, buf_to_dec + i * 16, 16);
		AES_ECB_decrypt(&ctx, data_pack_to_decrypt);

		memcpy(decrypted_data + i * 16, data_pack_to_decrypt, 16);
	}

	return decrypted_data;
}

void built_to_decrypt_dao(const void *msg, size_t len, struct safe_buffer *sb_to_decrypt, int *enc_pref, int *missing)
{
	u_int8_t const *parser = (u_int8_t const *)msg;
	flog(LOG_INFO, "Start Parse and Decrypt DAO. Parser: %s", get_hex_str(parser, len));

	parser += sizeof(struct nd_rpl_security) + 1; /** Move to start of DAO */
	len -= sizeof(struct nd_rpl_security) + 1;
	flog(LOG_INFO, "Moved rpld security. Parser: %s", get_hex_str(parser, len));

	struct nd_rpl_dao *dao = (const struct nd_rpl_dao *)parser;
	// dao->rpl_flags |= RPL_DAO_D_MASK;
	safe_buffer_append(sb_to_decrypt, &dao->rpl_instanceid, 1);
	safe_buffer_append(sb_to_decrypt, &dao->rpl_resv, 1);
	safe_buffer_append(sb_to_decrypt, &dao->rpl_daoseq, 1);
	safe_buffer_append(sb_to_decrypt, &dao->rpl_dagid, 16);
	// safe_buffer_append(sb_to_decrypt, dao, 20);
	flog(LOG_INFO, "Append DAO To Decrypt Buffer with target: %s", get_hex_str(sb_to_decrypt->buffer, sb_to_decrypt->used));

	parser += 20;
	len -= 20;
	flog(LOG_INFO, "Moved DAO. Parser: %s", get_hex_str(parser, len));

	int optlen = len;
	const struct nd_rpl_opt *opt;
	const struct rpl_dao_target *target;
	const struct nd_rpl_pad1 *pad1;
	const struct nd_rpl_padn *padn;
	while (optlen > 0)
	{
		opt = (const struct nd_rpl_opt *)parser;
		flog(LOG_INFO, "DAO opt %s, type %d, len %d", get_hex_str(opt, sizeof(struct nd_rpl_opt)), opt->type, opt->len);

		if (optlen == 1)
		{
			pad1 = (const struct nd_rpl_pad1 *)parser;
			safe_buffer_append(sb_to_decrypt, pad1, 1);
			*missing += 1;

			flog(LOG_INFO, "Append To Decrypt Pad1: %s", get_hex_str(sb_to_decrypt->buffer, sb_to_decrypt->used));
			parser += 1;
			optlen -= 1;
		}
		else
		{

			switch (opt->type)
			{
			case RPL_DAO_RPLTARGET:
				target = (const struct rpl_dao_target *)parser;
				flog(LOG_INFO, "Target: %s", get_hex_str(target, 20));

				safe_buffer_append(sb_to_decrypt, &target->rpl_dao_prefix, 16);
				flog(LOG_INFO, "Append To Decrypt Target Prefix: %s", get_hex_str(sb_to_decrypt->buffer, sb_to_decrypt->used));
				safe_buffer_append(sb_to_decrypt, &target->rpl_dao_prefixlen, 1);
				flog(LOG_INFO, "Append To Decrypt Target Prefix Length: %s", get_hex_str(sb_to_decrypt->buffer, sb_to_decrypt->used));
				*enc_pref += 1;
				break;
			case RPL_OPT_PADN:
				padn = (const struct nd_rpl_padn *)parser;
				safe_buffer_append(sb_to_decrypt, &padn->padding, padn->option_length);
				*missing += padn->option_length;

				flog(LOG_INFO, "Append To Decrypt PadN: %s", get_hex_str(sb_to_decrypt->buffer, sb_to_decrypt->used));
				break;
			default:
				/* IGNORE NOT SUPPORTED */
				break;
			}
			parser += (2 + opt->len);
			optlen -= (2 + opt->len);
		}

		flog(LOG_INFO, "dao optlen %d", optlen);
	}
}

void build_decrypted_dao_packet(struct safe_buffer *sb, void const *decrypted_dao, int *enc_pref, int *aux_missing)
{
	struct nd_rpl_security dao_sec = {};
	struct nd_rpl_dao dao = {};

	struct in6_prefix prefix;
	const struct child *child;
	const struct list *c;

	safe_buffer_append(sb, &dao_sec, sizeof(dao_sec) + 1); /** Add DAO Sec + 1 (9 bytes) to buffer */
	flog(LOG_INFO, "Buffer with dao sec: %s", get_hex_str(sb->buffer, sb->used));

	u_int8_t const *parser = (u_int8_t const *)decrypted_dao;

	memcpy(&dao, parser, 4); /** Get 4+16 bytes of dao */
	dao.rpl_flags |= RPL_DAO_D_MASK;
	parser += 4;
	memcpy(dao.rpl_dagid.s6_addr, parser, 16); /** Get 16 bytes of dagid */
	parser += 16;
	safe_buffer_append(sb, &dao, sizeof(dao)); /** Add DAO to buffer */

	flog(LOG_INFO, "Buffer with dao: %s", get_hex_str(sb->buffer, sb->used));

	/** Add preffix to target and targets to buffer */
	for (int i = 0; i < *enc_pref; i++)
	{
		memcpy(&prefix.prefix, parser, 16);
		flog(LOG_INFO, "preffix: %s", get_hex_str(&prefix.prefix, 16));
		parser += 16;
		memcpy(&prefix.len, parser, 1);
		flog(LOG_INFO, "preffix len: %s", get_hex_str(&prefix.len, 1));
		parser += 1;

		append_target(&prefix, sb);
		flog(LOG_INFO, "Append Buffer with target: %s", get_hex_str(sb->buffer, sb->used));
	}

	/** Add paddings */
	int missing = *aux_missing;
	while (missing > 0)
	{
		flog(LOG_INFO, "missing: %d", missing);
		if (missing > 5)
		{ /** PadN with max size */
			struct nd_rpl_padn padn = {};
			padn.option_type = 0x01;
			padn.option_length = 5;

			padn.padding = mzalloc(5);
			memcpy(padn.padding, parser, 5);
			flog(LOG_INFO, "5 pads: %s", get_hex_str(padn.padding, 5));

			safe_buffer_append(sb, &padn, 2);
			safe_buffer_append(sb, padn.padding, 5);
			parser += 5;
			missing -= 5;
			flog(LOG_INFO, "Buffer with padN of %d pads: %s", 5, get_hex_str(sb->buffer, sb->used));
		}
		else if (missing > 1)
		{ /** PadN with relative size */
			struct nd_rpl_padn padn = {};
			padn.option_type = 0x01;
			padn.option_length = missing - 4;

			padn.padding = mzalloc(missing);
			memcpy(padn.padding, parser, missing);
			flog(LOG_INFO, "%d pads: %s", missing, get_hex_str(padn.padding, missing));

			safe_buffer_append(sb, &padn, 2);
			safe_buffer_append(sb, padn.padding, missing);
			parser += missing;
			missing = 0;
			flog(LOG_INFO, "Buffer with padN of %d pads: %s", missing, get_hex_str(sb->buffer, sb->used));
		}
		else if (missing == 1)
		{ /** Pad1 */
			struct nd_rpl_pad1 pad1 = {};
			pad1.option_type = 0x00;
			safe_buffer_append(sb, &pad1, 1);
			missing = 0;
			parser++;
			flog(LOG_INFO, "Buffer with pad1: %s", get_hex_str(sb->buffer, sb->used));
		}
		else
		{
			break;
		}
	}
}

void parse_and_decrypt_dao_sec(const void *msg, size_t len)
{
	struct safe_buffer *sb_to_decrypt = safe_buffer_new();
	struct safe_buffer *sb_decrypted_msg = safe_buffer_new();

	int enc_pref = 0;
	int missing = 0;

	built_to_decrypt_dao(msg, len, sb_to_decrypt, &enc_pref, &missing);

	uint8_t decrypted_dao[sb_to_decrypt->used];
	memcpy(decrypted_dao, decrypt_dao_sec(sb_to_decrypt->buffer, sb_to_decrypt->used), sb_to_decrypt->used);
	flog(LOG_INFO, "DAO decrypted: %s", get_hex_str(decrypted_dao, sizeof(decrypted_dao)));

	// build_decrypted_dao_packet(sb_decrypted_msg, decrypted_dao, &enc_pref, &missing);
}

static void process_dao_sec(int sock, struct iface *iface, const void *msg,
							size_t len, struct sockaddr_in6 *addr)
{
	parse_and_decrypt_dao_sec(msg, len);

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

	log_hex("msg in process_dao_sec", msg, len);

	uint8_t decrypted_dao[32];

	decrypt_dao_sec(msg, decrypted_dao);

	memcpy(msg + 9, decrypted_dao, 1);
	memcpy(msg + 11, decrypted_dao + 1, 2);
	memcpy(msg + 51, decrypted_dao + 3, 5);
	memcpy(msg + 58, decrypted_dao + 8, 5);
	memcpy(msg + 65, decrypted_dao + 13, 3);
	memcpy(msg + 13, decrypted_dao + 16, 16);

	log_hex("msg information after decryption", msg, len);

	if (len < sizeof(*dao))
	{
		flog(LOG_INFO, "dao length mismatch, drop");
		return;
	}
	len -= sizeof(*dao);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Received Sec Dao from %s", addr_str);

	char dagid_str[INET6_ADDRSTRLEN];
	addrtostr(&dao->rpl_dagid, dagid_str, sizeof(addr_str));
	flog(LOG_INFO, "Dag lookup for iface: %s, rpl_instanceid: %d, rpld_dagid: %s", iface->ifname, dao->rpl_instanceid, dagid_str);

	dag = dag_lookup(iface, dao->rpl_instanceid,
					 &dao->rpl_dagid);
	if (!dag)
	{
		addrtostr(&dao->rpl_dagid, addr_str, sizeof(addr_str));
		flog(LOG_INFO, "can't find dag sec %s", addr_str);
		return;
	}

	p = msg;
	p += (sizeof(struct nd_rpl_security) + sizeof(struct nd_rpl_dao)) + 1;
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
			flog(LOG_INFO, "dao opt rpl target");
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
		case RPL_OPT_PAD0:
			flog(LOG_INFO, "dao opt pad0");
			p += 1;
			break;
		case RPL_OPT_PADN:
			flog(LOG_INFO, "dao opt padn");
			p += (2 + opt->len);
			break;
		default:
			/* IGNORE NOT SUPPORTED */
			break;
		}

		/* TODO critical, we trust opt->len here... which is wire data */
		optlen -= (2 + opt->len);
		p += (2 + opt->len);
		// flog(LOG_INFO, "dao optlen %d", optlen);
	}

	DL_FOREACH(dag->childs.head, c)
	{
		child = container_of(c, struct child, list);

		rc = nl_add_route_via(dag->iface->ifindex, &child->addr,
							  &child->from);
		char child_addr_str[INET6_ADDRSTRLEN];
		addrtostr(&child->addr, child_addr_str, sizeof(child_addr_str));
		flog(LOG_INFO, "via route %d %s %s", rc, strerror(errno), child_addr_str);
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
	flog(LOG_INFO, "Received Dao Ack from %s", addr_str);

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
		char parent_addr_str[INET6_ADDRSTRLEN];
		addrtostr(&dag->parent->addr, parent_addr_str, sizeof(parent_addr_str));
		flog(LOG_INFO, "default route %d %s %s", rc, strerror(errno), parent_addr_str);
	}
}

void decrypt_daoack_sec(const void *msg, uint8_t *decrypted_data)
{
	flog(LOG_INFO, "decrypt_daoack_sec");
	uint8_t encrypted_data[32];
	memcpy(encrypted_data, msg + 9, 1);
	memcpy(encrypted_data + 1, msg + 11, 2);
	memcpy(encrypted_data + 3, msg + 31, 5);
	memcpy(encrypted_data + 8, msg + 38, 5);
	memcpy(encrypted_data + 13, msg + 45, 3);
	memcpy(encrypted_data + 16, msg + 13, 16);

	const uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	// log_hex("decrypt_daoack_sec AES key", aes_key, 16);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	// log_hex("DAOACK to decrypt", encrypted_data, 32);
	AES_ECB_decrypt(&ctx, encrypted_data);
	AES_ECB_decrypt(&ctx, encrypted_data + 16);
	// log_hex("DAOACK decrypted", encrypted_data, 32);

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

	// log_hex("Encrypted DAOACK in process_daoack_sec", msg, len);

	uint8_t decrypted_daoack[32];

	decrypt_daoack_sec(msg, decrypted_daoack);

	// log_hex("msg information before decryption", msg, len);

	memcpy(msg + 9, decrypted_daoack, 1);
	memcpy(msg + 11, decrypted_daoack + 1, 2);
	memcpy(msg + 31, decrypted_daoack + 3, 5);
	memcpy(msg + 38, decrypted_daoack + 8, 5);
	memcpy(msg + 45, decrypted_daoack + 13, 3);
	memcpy(msg + 13, decrypted_daoack + 16, 16);

	// log_hex("msg information after decryption", msg, len);

	if (len < sizeof(*daoack))
	{
		flog(LOG_INFO, "rpl daoack length mismatch, drop");
		return;
	}

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Received Sec Dao Ack from %s", addr_str);
	// log_hex("DODAGID ACK", daoack->rpl_dagid.s6_addr, 16);
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
		char parent_addr_str[INET6_ADDRSTRLEN];
		addrtostr(&dag->parent->addr, parent_addr_str, sizeof(parent_addr_str));
		flog(LOG_INFO, "default route %d %s %s", rc, strerror(errno), parent_addr_str);
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
	flog(LOG_INFO, "Received Dis from %s", addr_str);

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
	// flog(LOG_INFO, "decrypt_dis_sec");
	uint8_t encrypted_data[16];
	memcpy(encrypted_data, msg + 8, 2);
	memcpy(encrypted_data + 2, msg + 13, 5);
	memcpy(encrypted_data + 7, msg + 20, 5);
	memcpy(encrypted_data + 12, msg + 27, 4);

	const uint8_t aes_key[16];
	memcpy(aes_key, shared_secret, 16);
	// log_hex("decrypt_dis_sec AES key", aes_key, 16);

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, aes_key);

	// log_hex("DIS to decrypt", encrypted_data, 16);
	AES_ECB_decrypt(&ctx, encrypted_data);
	// log_hex("DIS decrypted", encrypted_data, 16);

	memcpy(decrypted_data, encrypted_data, sizeof(encrypted_data));
}

static void process_dis_sec(int sock, struct iface *iface, void *msg,
							size_t len, struct sockaddr_in6 *addr)
{
	char addr_str[INET6_ADDRSTRLEN];
	struct list *r, *d;
	struct rpl *rpl;
	struct dag *dag;

	// log_hex("Encrypted DIS in process_dis_sec", msg, len);

	uint8_t decrypted_dis[16];

	decrypt_dis_sec(msg, decrypted_dis);

	// log_hex("Decrypted DIS in process_dis_sec", decrypted_dis, 16);

	// log_hex("msg information before decryption", msg, len);

	memcpy(msg + 8, decrypted_dis, 2);
	memcpy(msg + 13, decrypted_dis + 2, 5);
	memcpy(msg + 20, decrypted_dis + 7, 5);
	memcpy(msg + 27, decrypted_dis + 12, 4);

	// log_hex("msg information after decryption", msg, len);

	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));
	flog(LOG_INFO, "Received Sec Dis from %s", addr_str);

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
 * @brief After receiving the public key, the node encapsulates the shared secret and sends the cipher text to the sender
 *
 * @param sock the socket number
 * @param iface the interface
 * @param msg message from the packet with the received public key
 */
static void process_pk_sec_exch(int sock, struct iface *iface, const void *msg, struct sockaddr_in6 *addr)
{
	char addr_str[INET6_ADDRSTRLEN];
	addrtostr(&addr->sin6_addr, addr_str, sizeof(addr_str));

	u_int8_t *rec_pk;

	if (iface->enc_mode == ENC_MODE_RSA)
	{
		rec_pk = mzalloc(RSA_KEY_SIZE_BYTES);
		if (!rec_pk)
		{
			flog(LOG_ERR, "failed to allocate memory for public key");
			return;
		}
		memcpy(rec_pk, msg, RSA_KEY_SIZE_BYTES);
		send_ct(sock, &addr->sin6_addr, iface, rec_pk);
	}
	else if (iface->enc_mode == ENC_MODE_KYBER)
	{
		rec_pk = mzalloc(CRYPTO_PUBLICKEYBYTES);
		if (!rec_pk)
		{
			flog(LOG_ERR, "failed to allocate memory for public key");
			return;
		}
		memcpy(rec_pk, msg, CRYPTO_PUBLICKEYBYTES);
		send_ct(sock, &addr->sin6_addr, iface, rec_pk);
	}
}

/**
 * @brief After receiving the cipher text, the node decapsulates the shared secret and store it
 *
 * @param msg message from the packet with the received cipher text
 * @param iface the interface
 */
static void process_ct_sec_exch(const void *msg, struct iface *iface)
{
	flog(LOG_INFO, "process_ct_sec_exch");
	if (iface->enc_mode == ENC_MODE_RSA)
	{
		long long *cipher_text;
		cipher_text = mzalloc(RSA_CIPHERTEXT_SIZE_BYTES);
		if (!cipher_text)
		{
			flog(LOG_ERR, "failed to allocate memory for cipher text");
			return;
		}

		memcpy(cipher_text, msg, RSA_CIPHERTEXT_SIZE_BYTES);
		struct key_class sk_class;
		uint8_to_key_class(iface->secret_key, &sk_class);
		const char *dec_shared_secret = rsa_decrypt(cipher_text, RSA_CIPHERTEXT_SIZE_BYTES, &sk_class);
		memcpy(shared_secret, dec_shared_secret, RSA_SS_SIZE_BYTES);
	}
	else if (iface->enc_mode == ENC_MODE_KYBER)
	{
		u_int8_t *cipher_text;
		cipher_text = mzalloc(KYBER_CIPHERTEXTBYTES);
		if (!cipher_text)
		{
			flog(LOG_ERR, "failed to allocate memory for cipher text");
			return;
		}
		memcpy(cipher_text, msg, KYBER_CIPHERTEXTBYTES);

		indcpa_dec(shared_secret, cipher_text, iface->secret_key);
	}
}

/**
 * @brief This function is called during the initial key exchange before the RPL process starts
 * If it receives and sucessfully process a public key or cipher text packet, it stops the key exchange event loop
 */
void process_exchange(int sock, const struct list_head *ifaces, unsigned char *msg,
					  int len, struct sockaddr_in6 *addr, struct in6_pktinfo *pkt_info,
					  int hoplimit, struct ev_loop *loop, ev_io *w, int *in_exchange)
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
	flog(LOG_INFO, "Packet addres: %s", addr_str);

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
		flog(LOG_INFO, "Sec exchange received PK from %s", addr_str);
		struct list *r, *d;
		struct rpl *rpl;
		struct dag *dag;

		char iface_addr_str[INET6_ADDRSTRLEN];
		char dag_addr_str[INET6_ADDRSTRLEN];

		addrtostr(&iface->ifaddr, iface_addr_str, sizeof(iface_addr_str));

		flog(LOG_INFO, "Listing RPLs of iface %s", iface_addr_str);
		DL_FOREACH(iface->rpls.head, r)
		{
			rpl = container_of(r, struct rpl, list);
			DL_FOREACH(rpl->dags.head, d)
			{
				dag = container_of(d, struct dag, list);

				addrtostr(&dag->self, dag_addr_str, sizeof(dag_addr_str));
				flog(LOG_INFO, "Dag address: %s", dag_addr_str);
				if (dag != NULL)
				{
					process_pk_sec_exch(sock, iface, &icmph->icmp6_dataun, addr);
					*in_exchange = 0;
					ev_io_stop(loop, w);
					ev_break(loop, EVBREAK_ONE);
				}
			}
		}
		break;
	case ND_RPL_SEC_CT_EXCH:
		flog(LOG_INFO, "Sec exchange received CT from %s", addr_str);
		process_ct_sec_exch(&icmph->icmp6_dataun, iface);
		*in_exchange = 0;
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
	flog(LOG_INFO, "Processing packet from addres: %s", addr_str);

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
		/* We just want to listen to RPL */
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
	case ND_RPL_SEC_PK_EXCH:
		struct list *r, *d;
		struct rpl *rpl;
		struct dag *dag;

		char iface_addr_str[INET6_ADDRSTRLEN];
		char dag_addr_str[INET6_ADDRSTRLEN];

		addrtostr(&iface->ifaddr, iface_addr_str, sizeof(iface_addr_str));

		/** Process a public key packet only if the node already has a dag */
		DL_FOREACH(iface->rpls.head, r)
		{
			rpl = container_of(r, struct rpl, list);
			DL_FOREACH(rpl->dags.head, d)
			{
				dag = container_of(d, struct dag, list);
				addrtostr(&dag->self, dag_addr_str, sizeof(dag_addr_str));

				if (dag != NULL)
				{
					process_pk_sec_exch(sock, iface, &icmph->icmp6_dataun, addr);
				}
			}
		}
		break;
	case ND_RPL_SEC_CT_EXCH:
		process_ct_sec_exch(&icmph->icmp6_dataun, iface);
		break;
	default:
		flog(LOG_ERR, "%s received unsupported RPL code 0x%02x",
			 if_name, icmph->icmp6_code);
		break;
	}
}
