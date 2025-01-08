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

#ifndef __RPLD_SEND_H__
#define __RPLD_SEND_H__

#include "dag.h"
#include "crypto/kyber/ref/kem.h"

void send_dio(int sock, struct dag *dag);
void send_dao(int sock, const struct in6_addr *to, struct dag *dag);
void send_dao_ack(int sock, const struct in6_addr *to, struct dag *dag);
void send_dis(int sock, struct iface *iface);
void send_pk(int sock, struct iface *iface);
void send_ct(int sock, const struct in6_addr *to, struct iface *iface, u_int8_t pk[CRYPTO_PUBLICKEYBYTES]);

#endif /* __RPLD_SEND_H__ */
