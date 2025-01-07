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

#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>

#include "helpers.h"
#include "config.h"
#include "log.h"

int hex_to_bytes(const char *hex_string, uint8_t *byte_array, size_t byte_array_size)
{
	for (size_t i = 0; i < byte_array_size; i++)
	{
		char high_nibble = hex_string[i * 2];
		char low_nibble = hex_string[i * 2 + 1];

		if (!isxdigit(high_nibble) || !isxdigit(low_nibble))
		{
			flog(LOG_ERR, "hex_to_bytes: invalid hex characters");
			return -2;
		}

		// Convert hex characters to a single byte
		byte_array[i] = (uint8_t)((strtol((char[]){high_nibble, '\0'}, NULL, 16) << 4) |
								  strtol((char[]){low_nibble, '\0'}, NULL, 16));
	}
	return 0;
}

void log_hex(const char *label, const u_int8_t *data, size_t len)
{
	printf("%s with lenght %lu: ", label, len);
	for (size_t i = 0; i < len; i++)
	{
		printf("%02X", data[i]);
	}
	printf("\n");
}

/** This function receives as input a public_key_class
 * and outputs a uint8_t array in key_array corresponding to the concatenation of the public key fields */
void key_class_to_uint8(struct key_class key_class, u_int8_t *key_array)
{
	// Convert modulus (64 bits)
	for (int i = 0; i < 8; i++)
	{
		key_array[i] = (key_class.modulus >> (56 - 8 * i)) & 0xFF;
	}
	// Convert exponent (64 bits)
	for (int i = 0; i < 8; i++)
	{
		key_array[8 + i] = (key_class.exponent >> (56 - 8 * i)) & 0xFF;
	}
}

/** This function receives as input a uint8_t array
 * and outputs a public_key_class */
void uint8_to_key_class(const u_int8_t *key_array, struct key_class *key_class)
{
	key_class->modulus = 0;
	key_class->exponent = 0;

	// Reconstruct modulus (64 bits)
	for (int i = 0; i < 8; i++)
	{
		key_class->modulus = (key_class->modulus << 8) | key_array[i];
	}

	// Reconstruct exponent (64 bits)
	for (int i = 0; i < 8; i++)
	{
		key_class->exponent = (key_class->exponent << 8) | key_array[8 + i];
	}
}

int gen_stateless_addr(const struct in6_prefix *prefix,
					   const struct iface_llinfo *llinfo,
					   struct in6_addr *dst)
{
	uint8_t len = bits_to_bytes(prefix->len);
	int i;

	memset(dst, 0, sizeof(*dst));

	/* TODO only supported right now, gets tricky with bluetooth */
	if (prefix->len != 64 || llinfo->addr_len != 8)
		return -1;

	memcpy(dst, &prefix->prefix, len);

	for (i = 0; i < llinfo->addr_len; i++)
		dst->s6_addr[len + i] = llinfo->addr[i];

	/* U/L */
	dst->s6_addr[8] ^= 0x02;

	return 0;
}

__attribute__((format(printf, 1, 2))) static char *strdupf(char const *format, ...)
{
	va_list va;
	va_start(va, format);
	char *strp = 0;
	int rc = vasprintf(&strp, format, va);
	if (rc == -1 || !strp)
	{
		flog(LOG_ERR, "vasprintf failed: %s", strerror(errno));
		exit(-1);
	}
	va_end(va);

	return strp;
}

/* note: also called from the root context */
int set_var(const char *var, uint32_t val)
{
	int retval = -1;
	FILE *fp = 0;

	if (access(var, F_OK) != 0)
		goto cleanup;

	fp = fopen(var, "w");
	if (!fp)
	{
		flog(LOG_ERR, "failed to set %s: %s", var, strerror(errno));
		goto cleanup;
	}

	if (0 > fprintf(fp, "%u", val))
	{
		goto cleanup;
	}

	retval = 0;

cleanup:
	if (fp)
		fclose(fp);

	return retval;
}

int set_interface_var(const char *iface, const char *var, const char *name, uint32_t val)
{
	int retval = -1;
	FILE *fp = 0;
	char *spath = strdupf(var, iface);

	/* No path traversal */
	if (!iface[0] || !strcmp(iface, ".") || !strcmp(iface, "..") || strchr(iface, '/'))
		goto cleanup;

	if (access(spath, F_OK) != 0)
		goto cleanup;

	fp = fopen(spath, "w");
	if (!fp)
	{
		if (name)
			flog(LOG_ERR, "failed to set %s (%u) for %s: %s", name, val, iface, strerror(errno));
		goto cleanup;
	}

	if (0 > fprintf(fp, "%u", val))
	{
		goto cleanup;
	}

	retval = 0;

cleanup:
	if (fp)
		fclose(fp);

	free(spath);

	return retval;
}

void init_random_gen()
{
	srandom(time(NULL));
}

int gen_random_private_ula_pfx(struct in6_prefix *prefix)
{
	int i;

	prefix->len = 64;
	memset(&prefix->prefix, 0, sizeof(prefix->prefix));
	prefix->prefix.s6_addr[0] = 0xfd;
	for (i = 1; i < 6; i++)
		prefix->prefix.s6_addr[i] = random() & 0xff;

	return 0;
}
