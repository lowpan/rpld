
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

#ifndef __RPLD_HELPERS__
#define __RPLD_HELPERS__

#include <arpa/inet.h>
#include <errno.h>

#include <stdlib.h>
#include <stdint.h>

#include "log.h"

#include "crypto/RSA/rsa.h"

#define RSA_MODE 1

#if (RSA_MODE == 1)
#define RSA_SS_SIZE_BYTES 16
#elif (RSA_MODE == 2)
#define RSA_SS_SIZE_BYTES 32
#else
#error "RSA_MODE must be in {1,2}"
#endif

#define RSA_KEY_SIZE_BYTES 16 /** Results from the append of the long long modulus + long long expoent */
#define RSA_CIPHERTEXT_SIZE_BYTES RSA_SS_SIZE_BYTES * 8

#define mzalloc(size) calloc(1, size)

/* thanks mcr, I stole that form unstrung */
static const struct in6_addr all_rpl_addr = {.s6_addr = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a}};

/* This assumes that str is not null and str_size > 0 */
static inline void addrtostr(const struct in6_addr *addr, char *str, size_t str_size)
{
	const char *res;

	res = inet_ntop(AF_INET6, addr, str, str_size);

	if (res == NULL)
	{
		flog(LOG_ERR, "addrtostr: inet_ntop: %s", strerror(errno));
		strncpy(str, "[invalid address]", str_size);
		str[str_size - 1] = '\0';
	}
}

static inline uint8_t bits_to_bytes(uint8_t bits)
{
	uint8_t o = bits >> 3;
	uint8_t b = bits & 0x7;

	return b ? o + 1 : o;
}

char *get_hex_str(const u_int8_t *data, size_t len);

int hex_to_bytes(const char *hex_string, uint8_t *byte_array, size_t byte_array_size);

void key_class_to_uint8(struct key_class key_class, u_int8_t *key_array);
void uint8_to_key_class(const u_int8_t *key_array, struct key_class *key_class);

struct in6_prefix
{
	struct in6_addr prefix;
	uint8_t len;
};

struct iface_llinfo;
int gen_stateless_addr(const struct in6_prefix *prefix,
					   const struct iface_llinfo *llinfo,
					   struct in6_addr *dst);
#define PROC_SYS_IP6_IFACE_FORWARDING "/proc/sys/net/ipv6/conf/%s/forwarding"
#define PROC_SYS_IP6_MAX_HBH_OPTS_NUM "/proc/sys/net/ipv6/max_hbh_opts_number"
int set_interface_var(const char *iface, const char *var, const char *name,
					  uint32_t val);
int set_var(const char *var, uint32_t val);
void init_random_gen(void);
int gen_random_private_ula_pfx(struct in6_prefix *prefix);

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)

/* The Linux kernel is _not_ the inventor of that! */
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) ); })

#endif /* __RPLD_HELPERS__ */
