/*
 *   Authors:
 *    Alexander Aring           <alex.aring@gmail.com>
 *
 *   This software is Copyright 2019 by the above mentioned author(s),
 *   All Rights Reserved.
 *
 *   The license which is distributed with this software in the file COPYRIGHT
 *   applies to this software. If your distribution is missing this file, you
 *   may request it from <alex.aring@gmail.com>.
 */

#ifndef __RPLD_CONFIG__
#define __RPLD_CONFIG__

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <net/if.h>
#include <stdint.h>

#include "dag.h"
#include "list.h"

#define MAX_RPL_INSTANCEID UINT8_MAX
#define DEFAULT_TICKLE_T 5
#define DEFAULT_DAG_VERSION 1

enum enc_mode
{
        ENC_MODE_NONE = 0,
        ENC_MODE_RSA = 1,
        ENC_MODE_KYBER = 2,
};

struct iface_llinfo
{
        unsigned char *addr;
        uint8_t addr_len;
        uint32_t ifindex;
};

struct iface
{
        char ifname[IFNAMSIZ];
        uint32_t ifindex;

        ev_timer dis_w;
        struct iface_llinfo llinfo;

        enum enc_mode enc_mode;
        u_int8_t *shared_secret;
        u_int8_t *public_key;
        u_int8_t *secret_key;

        struct in6_addr ifaddr;
        struct in6_addr *ifaddrs;
        int ifaddrs_count;
        struct in6_addr *ifaddr_src;

        struct list_head rpls;
        bool dodag_root;

        struct list list;
};

const uint8_t *get_aes_key(void);
int config_load(const char *filename, struct list_head *ifaces);
void config_free(struct list_head *ifaces);

struct iface *iface_find_by_ifindex(const struct list_head *ifaces,
                                    uint32_t ifindex);

#endif /* __RPLD_CONFIG__ */
