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

#include <sys/types.h>
#include <ifaddrs.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "helpers.h"
#include "netlink.h"
#include "config.h"
#include "log.h"

#include "crypto/kyber/ref/kem.h"

static uint8_t aes_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
const uint8_t *get_aes_key(void)
{
        return aes_key;
}

static inline int cmp_iface_addrs(void const *a, void const *b)
{
        return memcmp(a, b, sizeof(struct in6_addr));
}

/*
 * Return first IPv6 link local addr in if_addr.
 * Return all the IPv6 addresses in if_addrs in ascending
 * order.
 * Return value is -1 if there was no link local addr.
 * otherwise return value is count of addres in if_addrs
 * not including the all zero (unspecified) addr at the
 * end of the list.
 */
static int get_iface_addrs(char const *name, struct in6_addr *if_addr,
                           struct in6_addr **if_addrs)
{
        struct ifaddrs *addresses = 0;
        int link_local_set = 0;
        int i = 0;

        if (getifaddrs(&addresses) != 0)
        {
                flog(LOG_ERR, "getifaddrs failed on %s: %s", name, strerror(errno));
        }
        else
        {
                for (struct ifaddrs *ifa = addresses; ifa != NULL; ifa = ifa->ifa_next)
                {

                        if (!ifa->ifa_addr)
                                continue;

                        if (ifa->ifa_addr->sa_family != AF_INET6)
                                continue;

                        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ifa->ifa_addr;

                        /* Skip if it is not the interface we're looking for. */
                        if (strcmp(ifa->ifa_name, name) != 0)
                                continue;

                        *if_addrs = realloc(*if_addrs, (i + 1) * sizeof(struct in6_addr));
                        (*if_addrs)[i++] = a6->sin6_addr;

                        /* Skip if it is not a linklocal address or link locak address already found*/
                        uint8_t const ll_prefix[] = {0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
                        if (link_local_set || 0 != memcmp(&(a6->sin6_addr), ll_prefix, sizeof(ll_prefix)))
                                continue;

                        if (if_addr)
                                memcpy(if_addr, &(a6->sin6_addr), sizeof(struct in6_addr));

                        link_local_set = 1;
                }
        }

        if (addresses)
                freeifaddrs(addresses);

        /* last item in the list is all zero (unspecified) address */
        *if_addrs = realloc(*if_addrs, (i + 1) * sizeof(struct in6_addr));
        memset(&(*if_addrs)[i], 0, sizeof(struct in6_addr));

        /* Sort the addresses so the output is predictable. */
        qsort(*if_addrs, i, sizeof(struct in6_addr), cmp_iface_addrs);

        if (!link_local_set)
                return -1;

        return i;
}

static int parse_ipv6_prefix(struct in6_prefix *prefix, const char *str)
{
        char ip[INET6_ADDRSTRLEN] = {};
        const char *tmp, *del;
        unsigned long p;
        int rc;

        del = strchr(str, '/');
        if (!del)
                return -1;

        /* stupid check, why I am doing that */
        tmp = strchr(del + 1, '/');
        if (tmp)
                return -1;

        strncpy(ip, str, del - str);
        rc = inet_pton(AF_INET6, ip, &prefix->prefix);
        if (rc != 1)
                return -1;

        p = strtoul(del + 1, NULL, 10);
        if (p == ULONG_MAX || p > UINT8_MAX)
                return -1;

        prefix->len = p;
        return 0;
}

#if 0
struct dag *iface_find_dag(const struct list_head *dags, uint16_t inst_id)
{
        struct dag *dag;
        struct list *e;

        DL_FOREACH(dags->head, e) {
                dag = container_of(e, struct dag, list);

                if (dag->inst_id == inst_id)
                        return dag;
        }

        return NULL;
}
#endif

struct iface *iface_find_by_ifindex(const struct list_head *ifaces,
                                    uint32_t ifindex)
{
        struct iface *iface;
        struct list *e;

        DL_FOREACH(ifaces->head, e)
        {
                iface = container_of(e, struct iface, list);

                if (iface->ifindex == ifindex)
                        return iface;
        }

        return NULL;
}

static struct iface *iface_create()
{
        struct iface *iface;

        iface = mzalloc(sizeof(*iface));
        if (!iface)
                return NULL;

        return iface;
}

static void iface_free(struct iface *iface)
{
        free(iface->ifaddrs);
        free(iface->llinfo.addr);
        free(iface);
}

static int config_load_dags(lua_State *L, struct iface *iface,
                            uint8_t instanceid)
{
        struct in6_addr dodagid;
        struct in6_prefix dest;
        ev_tstamp trickle_t;
        uint8_t version;
        struct dag *dag;
        int rc;

        lua_getfield(L, -1, "dags");
        if (!lua_istable(L, -1))
                return -1;

        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
                lua_getfield(L, -1, "dest_prefix");
                if (lua_isstring(L, -1))
                {
                        rc = parse_ipv6_prefix(&dest, lua_tostring(L, -1));
                        if (rc == -1)
                                return -1;
                }
                else
                {
                        rc = gen_random_private_ula_pfx(&dest);
                        if (rc == -1)
                                return -1;
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "trickle_t");
                if (lua_isnumber(L, -1))
                {
                        trickle_t = lua_tonumber(L, -1);
                }
                else
                {
                        trickle_t = DEFAULT_TICKLE_T;
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "dodagid");
                if (lua_isstring(L, -1))
                {
                        rc = inet_pton(AF_INET6, lua_tostring(L, -1), &dodagid);
                        if (rc != 1)
                                return -1;
                }
                else
                {
                        rc = gen_stateless_addr(&dest, &iface->llinfo,
                                                &dodagid);
                        if (rc == -1)
                                return -1;
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "version");
                if (lua_isnumber(L, -1))
                {
                        version = lua_tonumber(L, -1);
                }
                else
                {
                        version = DEFAULT_DAG_VERSION;
                }
                lua_pop(L, 1);

                lua_pop(L, 1);

                dag = dag_create(iface, instanceid, &dodagid,
                                 trickle_t, 1, version, &dest);
                if (!dag)
                        return -1;

                /* we are root, self is dodagid */
                memcpy(&dag->self, &dodagid, sizeof(dag->self));
        }
        lua_pop(L, 1);

        return 0;
}

static int config_load_instances(lua_State *L, struct iface *iface)
{
        uint8_t instanceid;
        int rc;

        lua_getfield(L, -1, "rpls");
        if (!lua_istable(L, -1))
                return -1;

        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
                lua_getfield(L, -1, "instance");
                if (!lua_isnumber(L, -1))
                        return -1;

                instanceid = lua_tonumber(L, -1);
                lua_pop(L, 1);

                rc = config_load_dags(L, iface, instanceid);
                if (rc == -1)
                        return rc;

                lua_pop(L, 1);
        }
        lua_pop(L, 1);

        return 0;
}

void parse_and_set_key(const char *aux_public_key, struct key_class *key)
{
        char *token;
        char *input_copy = strdup(aux_public_key); // Create a modifiable copy of the string
        if (!input_copy)
        {
                fprintf(stderr, "Memory allocation failed\n");
                return;
        }

        // Extract the modulus (first number)
        token = strtok(input_copy, ",");
        if (token)
        {
                key->modulus = atoll(token); // Convert to long long
        }
        else
        {
                fprintf(stderr, "Error parsing modulus\n");
                free(input_copy);
                return;
        }

        // Extract the exponent (second number)
        token = strtok(NULL, ",");
        if (token)
        {
                key->exponent = atoll(token); // Convert to long long
        }
        else
        {
                fprintf(stderr, "Error parsing exponent\n");
                free(input_copy);
                return;
        }

        free(input_copy); // Clean up the allocated memory
}

/** Parse the encryption parameters in the config file, if any
 * If it is to configure a encryption, it must have the enc_mode field with 1 or 2
 * See encryption modes in config.h
 */
static int config_encryption(lua_State *L, struct iface *iface)
{
        flog(LOG_INFO, "config_encryption");
        lua_getfield(L, -1, "enc_mode");
        if (lua_isnil(L, -1))
        {
                iface->enc_mode = ENC_MODE_NONE;
                flog(LOG_DEBUG, "enc_mode not found, setting to none");
                lua_pop(L, 1);
                return 0;
        }
        else
        {
                if (!lua_isnumber(L, -1))
                {
                        flog(LOG_ERR, "enc_mode is not a number");
                        return -1;
                }
                iface->enc_mode = lua_tonumber(L, -1);
                flog(LOG_DEBUG, "enc_mode: %d", iface->enc_mode);
                lua_pop(L, 1);

                /** RSA encryption mode */
                if (iface->enc_mode == ENC_MODE_NONE)
                {
                        return 0;
                }
                else if (iface->enc_mode == ENC_MODE_RSA)
                {
                        flog(LOG_DEBUG, "RSA encryption mode");
                        lua_getfield(L, -1, "public_key");
                        if (lua_isnil(L, -1))
                        {
                                /** If the public key hasn't been passed, generate it and the private key */
                                struct key_class public_key;
                                struct key_class secret_key;
                                rsa_gen_keys(&public_key, &secret_key, "primes.txt");
                                iface->public_key = mzalloc(RSA_KEY_SIZE_BYTES);
                                iface->secret_key = mzalloc(RSA_KEY_SIZE_BYTES);
                                key_class_to_uint8(public_key, iface->public_key);
                                key_class_to_uint8(secret_key, iface->secret_key);
                                lua_pop(L, 1);
                                return 0;
                        }
                        else
                        {
                                char *aux_public_key;
                                aux_public_key = lua_tostring(L, -1);

                                struct key_class public_key;
                                parse_and_set_key(aux_public_key, &public_key);
                                iface->public_key = mzalloc(RSA_KEY_SIZE_BYTES);
                                key_class_to_uint8(public_key, iface->public_key);
                        }
                        lua_pop(L, 1);

                        lua_getfield(L, -1, "secret_key");
                        if (lua_isnil(L, -1))
                        {
                                /** If the secret key hasn't been passed, generate it and the public key  */
                                struct key_class public_key;
                                struct key_class secret_key;
                                rsa_gen_keys(&public_key, &secret_key, "primes.txt");
                                iface->public_key = mzalloc(RSA_KEY_SIZE_BYTES);
                                iface->secret_key = mzalloc(RSA_KEY_SIZE_BYTES);
                                key_class_to_uint8(public_key, iface->public_key);
                                key_class_to_uint8(secret_key, iface->secret_key);
                                lua_pop(L, 1);
                                return 0;
                        }
                        else
                        {
                                char *aux_secret_key;
                                aux_secret_key = lua_tostring(L, -1);

                                struct key_class secret_key;
                                parse_and_set_key(aux_secret_key, &secret_key);
                                iface->secret_key = mzalloc(RSA_KEY_SIZE_BYTES);
                                key_class_to_uint8(secret_key, iface->secret_key);
                        }
                        lua_pop(L, 1);
                }
                /** Kyber encryption mode */
                else if (iface->enc_mode == ENC_MODE_KYBER)
                {
                        flog(LOG_DEBUG, "Kyber encryption mode");
                        char aux_public_key[CRYPTO_PUBLICKEYBYTES * 2];
                        char aux_secret_key[CRYPTO_SECRETKEYBYTES * 2];

                        lua_getfield(L, -1, "public_key");
                        if (lua_isnil(L, -1))
                        {
                                /** If the public key hasn't been passed, generate it and the private key */
                                crypto_kem_keypair(iface->public_key, iface->secret_key);
                                lua_pop(L, 1);
                                return 0;
                        }
                        else
                        {
                                strncpy(aux_public_key, lua_tostring(L, -1), CRYPTO_PUBLICKEYBYTES * 2);

                                iface->public_key = mzalloc(CRYPTO_PUBLICKEYBYTES);
                                if (hex_to_bytes(aux_public_key, iface->public_key, CRYPTO_PUBLICKEYBYTES) != 0)
                                {
                                        return -1;
                                }
                        }
                        lua_pop(L, 1);

                        lua_getfield(L, -1, "secret_key");
                        if (lua_isnil(L, -1))
                        {
                                /** If the secret key hasn't been passed, generate it and the public key  */
                                crypto_kem_keypair(iface->public_key, iface->secret_key);
                                lua_pop(L, 1);
                                return 0;
                        }
                        else
                        {
                                strncpy(aux_secret_key, lua_tostring(L, -1), CRYPTO_SECRETKEYBYTES * 2);

                                iface->secret_key = mzalloc(CRYPTO_SECRETKEYBYTES);
                                if (hex_to_bytes(aux_secret_key, iface->secret_key, CRYPTO_SECRETKEYBYTES) != 0)
                                {
                                        return -1;
                                }

                                lua_pop(L, 1);
                        }
                }
                else
                {
                        flog(LOG_ERR, "enc_mode not supported");
                        return -1;
                }
        }
        return 0;
}

/**
 * @brief Parse the config file and load in the ifaces list.
 *
 * @param filename the config file to be parsed
 * @param ifaces the list of ifaces to be filled
 */
int config_load(const char *filename, struct list_head *ifaces)
{
        flog(LOG_INFO, "config loading: %s", filename);
        struct iface *iface;
        lua_State *L;
        int rc;

        L = luaL_newstate();
        if (!L)
                return -1;

        luaopen_base(L);
        luaopen_io(L);
        luaopen_string(L);
        luaopen_math(L);

        if (luaL_loadfile(L, filename) || lua_pcall(L, 0, 0, 0))
        {
                flog(LOG_ERR, "cannot run configuration file: %s",
                     lua_tostring(L, -1));
                return -1;
        }

        lua_getglobal(L, "ifaces");
        if (!lua_istable(L, -1))
                return -1;

        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
                iface = iface_create();
                if (!iface)
                {
                        lua_close(L);
                        return -1;
                }

                lua_getfield(L, -1, "ifname");
                if (!lua_isstring(L, -1))
                {
                        iface_free(iface);
                        lua_close(L);
                        return -1;
                }

                strncpy(iface->ifname, lua_tostring(L, -1), IFNAMSIZ);
                lua_pop(L, 1);
#if 1
                /* TODO check why we need that to all? */
                rc = set_interface_var("all",
                                       PROC_SYS_IP6_IFACE_FORWARDING,
                                       "forwarding", 1);
#else
                rc = set_interface_var(iface->ifname,
                                       PROC_SYS_IP6_IFACE_FORWARDING,
                                       "forwarding", 1);
#endif
                if (rc == -1)
                {
                        flog(LOG_ERR, "Failed to set forwarding");
                        iface_free(iface);
                        lua_close(L);
                        return -1;
                }

                iface->ifindex = if_nametoindex(iface->ifname);
                if (iface->ifindex == 0)
                {
                        flog(LOG_ERR, "%s not found: %s", iface->ifname, strerror(errno));
                        iface_free(iface);
                        lua_close(L);
                        return -1;
                }

                nl_get_llinfo(iface->ifindex, &iface->llinfo);

                rc = get_iface_addrs(iface->ifname, &iface->ifaddr, &iface->ifaddrs);
                if (rc == -1)
                {
                        iface_free(iface);
                        lua_close(L);
                        return rc;
                }

                /* TODO because compression might be different here... */
                iface->ifaddr_src = &iface->ifaddr;
                iface->ifaddrs_count = rc;

                if (config_encryption(L, iface) != 0)
                {
                        iface_free(iface);
                        lua_close(L);
                        return -1;
                }

                lua_getfield(L, -1, "dodag_root");
                if (!lua_isboolean(L, -1))
                {
                        iface_free(iface);
                        lua_close(L);
                        return -1;
                }

                iface->dodag_root = lua_toboolean(L, -1);
                lua_pop(L, 1);

                if (iface->dodag_root)
                {
                        rc = config_load_instances(L, iface);
                        if (rc == -1)
                                return rc;
                }

                lua_pop(L, 1);
                DL_APPEND(ifaces->head, &iface->list);
        }

        lua_pop(L, 1);
        lua_close(L);

        flog(LOG_INFO, "config successful parsed");

        return 0;
}

void config_free(struct list_head *ifaces)
{
        struct list *e, *tmp;
        struct iface *iface;

        DL_FOREACH_SAFE(ifaces->head, e, tmp)
        {
                iface = container_of(e, struct iface, list);
                iface_free(iface);

                DL_DELETE(ifaces->head, e);
        }
}
