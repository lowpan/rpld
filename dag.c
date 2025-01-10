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

#include <stddef.h>

#include "helpers.h"
#include "netlink.h"
#include "buffer.h"
#include "rpl.h"
#include "dag.h"
#include "config.h"
#include "crypto/aes/tiny-AES-c-master/aes.h"

#include "crypto/kyber/ref/kem.h"
#include "crypto/kyber/ref/indcpa.h"

u_int8_t shared_secret[CRYPTO_BYTES];

struct peer *dag_peer_create(const struct in6_addr *addr)
{
        struct peer *peer;

        peer = mzalloc(sizeof(*peer));
        if (!peer)
                return NULL;

        memcpy(&peer->addr, addr, sizeof(peer->addr));
        peer->rank = UINT16_MAX;

        return peer;
}

struct child *dag_child_create(const struct in6_addr *addr,
                               const struct in6_addr *from)
{
        struct child *peer;

        peer = mzalloc(sizeof(*peer));
        if (!peer)
                return NULL;

        memcpy(&peer->addr, addr, sizeof(peer->addr));
        memcpy(&peer->from, from, sizeof(peer->from));

        return peer;
}

bool dag_is_peer(const struct peer *peer, const struct in6_addr *addr)
{
        if (!peer || !addr)
                return false;

        return !memcmp(&peer->addr, addr, sizeof(peer->addr));
}

bool dag_is_child(const struct child *peer, const struct in6_addr *addr)
{
        if (!peer || !addr)
                return false;

        return !memcmp(&peer->addr, addr, sizeof(peer->addr));
}

static struct child *dag_lookup_child(const struct dag *dag,
                                      const struct in6_addr *addr)
{
        struct child *peer;
        struct list *p;

        DL_FOREACH(dag->childs.head, p)
        {
                peer = container_of(p, struct child, list);
                if (dag_is_child(peer, addr))
                        return peer;
        }

        return NULL;
}

struct child *dag_lookup_child_or_create(struct dag *dag,
                                         const struct in6_addr *addr,
                                         const struct in6_addr *from)
{
        struct child *peer;

        peer = dag_lookup_child(dag, addr);
        if (peer)
                return peer;

        peer = dag_child_create(addr, from);
        if (peer)
                DL_APPEND(dag->childs.head, &peer->list);

        return peer;
}

static struct rpl *dag_lookup_rpl(const struct iface *iface,
                                  uint8_t instance_id)
{
        struct rpl *rpl;
        struct list *r;

        DL_FOREACH(iface->rpls.head, r)
        {
                rpl = container_of(r, struct rpl, list);
                if (rpl->instance_id == instance_id)
                        return rpl;
        }

        return NULL;
}

static struct dag *dag_lookup_dodag(const struct rpl *rpl,
                                    const struct in6_addr *dodagid)
{
        struct dag *dag;
        struct list *d;

        DL_FOREACH(rpl->dags.head, d)
        {
                dag = container_of(d, struct dag, list);

                if (!memcmp(&dag->dodagid, dodagid, sizeof(dag->dodagid)))
                        return dag;
        }

        return NULL;
}

struct dag *dag_lookup(const struct iface *iface, uint8_t instance_id,
                       const struct in6_addr *dodagid)
{
        struct rpl *rpl;

        rpl = dag_lookup_rpl(iface, instance_id);
        if (!rpl)
                return NULL;

        return dag_lookup_dodag(rpl, dodagid);
}

static struct rpl *dag_rpl_create(uint8_t instance_id)
{
        struct rpl *rpl;

        rpl = mzalloc(sizeof(*rpl));
        if (!rpl)
                return NULL;

        rpl->instance_id = instance_id;
        return rpl;
}

struct dag_daoack *dag_lookup_daoack(const struct dag *dag, uint8_t dsn)
{
        struct dag_daoack *daoack;
        struct list *d;

        DL_FOREACH(dag->pending_acks.head, d)
        {
                daoack = container_of(d, struct dag_daoack, list);

                if (daoack->dsn == dsn)
                        return daoack;
        }

        return NULL;
}

int dag_daoack_insert(struct dag *dag, uint8_t dsn)
{
        struct dag_daoack *daoack;

        daoack = mzalloc(sizeof(*daoack));
        if (!daoack)
                return -1;

        DL_APPEND(dag->pending_acks.head, &daoack->list);
        return 0;
}

void dag_init_timer(struct dag *dag);

static int dag_init(struct dag *dag, const struct iface *iface,
                    const struct rpl *rpl, const struct in6_addr *dodagid,
                    ev_tstamp trickle_t, uint16_t my_rank, uint8_t version,
                    const struct in6_prefix *dest)
{
        /* TODO dest is currently necessary */
        if (!dag || !iface || !rpl || !dest)
                return -1;

        memset(dag, 0, sizeof(*dag));

        dag->iface = iface;
        dag->rpl = rpl;
        dag->dest = *dest;
        dag->dodagid = *dodagid;

        dag->version = version;
        dag->my_rank = my_rank;
        dag->trickle_t = DEFAULT_TICKLE_T;

        dag_init_timer(dag);

        return 0;
}

struct dag *dag_create(struct iface *iface, uint8_t instanceid,
                       const struct in6_addr *dodagid, ev_tstamp trickle_t,
                       uint16_t my_rank, uint8_t version,
                       const struct in6_prefix *dest)
{
        bool append_rpl = false;
        struct rpl *rpl;
        struct dag *dag;
        int rc;

        rpl = dag_lookup_rpl(iface, instanceid);
        if (!rpl)
        {
                rpl = dag_rpl_create(instanceid);
                if (!rpl)
                        return NULL;

                append_rpl = true;
        }

        /* sanity check because it's just a list
         * we must avoid duplicate entries
         */
        if (!append_rpl)
        {
                dag = dag_lookup_dodag(rpl, dodagid);
                if (dag)
                {
                        free(rpl);
                        return NULL;
                }
        }

        dag = mzalloc(sizeof(*dag));
        if (!dag)
        {
                free(rpl);
                return NULL;
        }

        rc = dag_init(dag, iface, rpl, dodagid, trickle_t,
                      my_rank, version, dest);
        if (rc != 0)
        {
                free(dag);
                free(rpl);
                return NULL;
        }

        if (append_rpl)
                DL_APPEND(iface->rpls.head, &rpl->list);

        DL_APPEND(rpl->dags.head, &dag->list);
        return dag;
}

void dag_free(struct dag *dag)
{
        free(dag);
}

static int append_destprefix(const struct dag *dag, struct safe_buffer *sb)
{
        struct rpl_dio_destprefix diodp = {};
        uint8_t len;

        len = sizeof(diodp) - sizeof(diodp.rpl_dio_prefix) +
              bits_to_bytes(dag->dest.len);

        diodp.rpl_dio_type = 0x3;
        //      diodp.rpl_dio_prf = RPL_DIO_PREFIX_AUTONOMOUS_ADDR_CONFIG_FLAG;
        /* TODO crazy calculation here */
        diodp.rpl_dio_len = len - 2;
        diodp.rpl_dio_prefixlen = dag->dest.len;
        diodp.rpl_dio_prefix = dag->dest.prefix;
        diodp.rpl_dio_route_lifetime = UINT32_MAX;
        safe_buffer_append(sb, &diodp, len);

        return 0;
}

static void dag_build_icmp(struct safe_buffer *sb, uint8_t code)
{
        struct icmp6_hdr nd_rpl_hdr = {
            .icmp6_type = ND_RPL_MESSAGE,
            .icmp6_code = code,
        };

        /* TODO 4 is a hack */
        safe_buffer_append(sb, &nd_rpl_hdr, sizeof(nd_rpl_hdr) - 4);
}

void dag_log_dodagid(struct dag *dag)
{

        char dodagid_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &dag->dodagid, dodagid_str, sizeof(dodagid_str));
        flog(LOG_INFO, "DODAGID: %s", dodagid_str);
}

void dodagid_to_hex(struct dag *dag, char *dodagid_hex)
{
        for (int i = 0; i < 16; i++)
        {
                sprintf(&dodagid_hex[i * 2], "%02x", ((uint8_t *)&dag->dodagid)[i]);
        }
        dodagid_hex[32] = '\0';
        //  flog(LOG_INFO, "DODAGID em hexadecimal: %s", dodagid_hex);
}

uint8_t *dag_encrypt_dodagid(const char *dodagid_hex)
{
        uint8_t aes_key[16];
        memcpy(aes_key, shared_secret, 16);

        struct AES_ctx ctx;
        AES_init_ctx(&ctx, aes_key);

        flog(LOG_INFO, "Chave AES inicializada com sucesso");

        uint8_t data_to_encrypt[16];
        for (int i = 0; i < 16; i++)
        {
                sscanf(&dodagid_hex[i * 2], "%02hhx", &data_to_encrypt[i]);
        }

        AES_ECB_encrypt(&ctx, data_to_encrypt);

        static uint8_t encrypted_data[16];
        memcpy(encrypted_data, data_to_encrypt, 16);

        flog(LOG_INFO, "Criptografia do DODAGID concluída");

        flog(LOG_INFO, "DODAGID criptografado: ");
        for (int i = 0; i < 16; i++)
        {
                flog(LOG_INFO, "%02x", encrypted_data[i]);
        }

        return encrypted_data;
}

void dag_build_dio(struct dag *dag, struct safe_buffer *sb)
{
        struct nd_rpl_dio dio = {};

        dag_build_icmp(sb, ND_RPL_DAG_IO);

        dio.rpl_instanceid = dag->rpl->instance_id;
        dio.rpl_version = dag->version;
        dio.rpl_dtsn = dag->dtsn++;
        flog(LOG_INFO, "my_rank %d", dag->my_rank);
        dio.rpl_dagrank = htons(dag->my_rank);
        dio.rpl_mopprf = ND_RPL_DIO_GROUNDED | RPL_DIO_STORING_NO_MULTICAST << 3;
        dio.rpl_dagid = dag->dodagid;

        // dag_log_dodagid(dag);

        // char dodagid_hex[33];
        // dodagid_to_hex(dag, dodagid_hex);

        // uint8_t *encrypted_dodagid = dag_encrypt_dodagid(dodagid_hex);

        // memcpy(dio.rpl_dagid.s6_addr, encrypted_dodagid, 16);

        safe_buffer_append(sb, &dio, sizeof(dio));
        append_destprefix(dag, sb);
}

void dag_process_dio(struct dag *dag)
{
        struct in6_addr addr;
        int rc;

        rc = gen_stateless_addr(&dag->dest, &dag->iface->llinfo,
                                &addr);
        if (rc == -1)
                return;

        rc = nl_add_addr(dag->iface->ifindex, &addr);
        if (rc == -1 && errno != EEXIST)
        {
                flog(LOG_ERR, "error add nl %d", errno);
                return;
        }
        rc = nl_del_route_via(dag->iface->ifindex, &dag->dest, NULL);
        if (rc == -1)
        {
                flog(LOG_ERR, "error del nl %d, %s", errno, strerror(errno));
                return;
        }

        memcpy(&dag->self, &addr, sizeof(dag->self));
}

void encrypt_dio(struct nd_rpl_dio *dio, struct nd_rpl_padn **padns, uint8_t num_padns, uint8_t *encrypted_data)
{
        flog(LOG_INFO, "encrypt_dio");
        uint8_t data_to_encrypt[32];
        memcpy(data_to_encrypt, dio, offsetof(struct nd_rpl_dio, rpl_dagid));
        
        size_t offset = offsetof(struct nd_rpl_dio, rpl_dagid);
        for (size_t i = 0; i < num_padns; i++) {
            memcpy(data_to_encrypt + offset, padns[i]->padding, padns[i]->option_length);
            offset += padns[i]->option_length;
        }
        memcpy(data_to_encrypt + offset, dio->rpl_dagid.s6_addr, sizeof(dio->rpl_dagid.s6_addr));
        
        const uint8_t aes_key[16];
        memcpy(aes_key, shared_secret, 16);
        // log_hex("encrypt_dio AES key", aes_key, 16);

        struct AES_ctx ctx;
        AES_init_ctx(&ctx, aes_key);

        // log_hex("DIO to encrypt", data_to_encrypt, 32);
        AES_ECB_encrypt(&ctx, data_to_encrypt);
        AES_ECB_encrypt(&ctx, data_to_encrypt + 16);
        // log_hex("DIO encrypted", data_to_encrypt, 32);

        memcpy(encrypted_data, data_to_encrypt, sizeof(data_to_encrypt));
}

void dag_build_dio_sec(struct dag *dag, struct safe_buffer *sb)
{
        struct nd_rpl_security dio_sec = {};
        struct nd_rpl_dio dio = {};
        size_t offset = offsetof(struct nd_rpl_dio, rpl_dagid);

        size_t num_padns = 2;
        struct nd_rpl_padn *padns[num_padns];

        uint8_t padding_sizes[] = {5, 3};

        for (size_t i = 0; i < num_padns; i++) {
            padns[i] = create_padn(padding_sizes[i]);
        }

        dag_build_icmp(sb, ND_RPL_SEC_DAG_IO);

        dio.rpl_instanceid = dag->rpl->instance_id;
        dio.rpl_version = dag->version;
        dio.rpl_dtsn = dag->dtsn++;
        flog(LOG_INFO, "my_rank %d", dag->my_rank);
        dio.rpl_dagrank = htons(dag->my_rank);
        dio.rpl_mopprf = ND_RPL_DIO_GROUNDED | RPL_DIO_STORING_NO_MULTICAST << 3;
        dio.rpl_dagid = dag->dodagid;

        uint8_t encrypted_dio[32];
        encrypt_dio(&dio, padns, num_padns, encrypted_dio);

        memcpy(&dio, encrypted_dio, offsetof(struct nd_rpl_dio, rpl_dagid));
        for (size_t i = 0; i < num_padns; i++) {
            memcpy(padns[i]->padding, encrypted_dio + offset, padns[i]->option_length);
            offset += padns[i]->option_length;
        }

        memcpy(dio.rpl_dagid.s6_addr, encrypted_dio + offset, 16);

        safe_buffer_append(sb, &dio_sec, sizeof(dio_sec) + 1);
        safe_buffer_append(sb, &dio, sizeof(dio));
        append_destprefix(dag, sb);
        for (size_t i = 0; i < num_padns; i++) {
            safe_buffer_append(sb, padns[i], sizeof(padns[i]->option_type) + sizeof(padns[i]->option_length) + padding_sizes[i]);
        }
}

void dag_process_dio_sec(struct dag *dag)
{
        struct in6_addr addr;
        int rc;

        rc = gen_stateless_addr(&dag->dest, &dag->iface->llinfo,
                                &addr);
        if (rc == -1)
                return;

        rc = nl_add_addr(dag->iface->ifindex, &addr);
        if (rc == -1 && errno != EEXIST)
        {
                flog(LOG_ERR, "error add nl %d", errno);
                return;
        }
        rc = nl_del_route_via(dag->iface->ifindex, &dag->dest, NULL);
        if (rc == -1)
        {
                flog(LOG_ERR, "error del nl %d, %s", errno, strerror(errno));
                return;
        }

        memcpy(&dag->self, &addr, sizeof(dag->self));
}

void dag_build_dao_ack(struct dag *dag, struct safe_buffer *sb)
{
        struct nd_rpl_daoack dao = {};

        dag_build_icmp(sb, ND_RPL_DAO_ACK);

        dao.rpl_instanceid = dag->rpl->instance_id;
        dao.rpl_flags |= RPL_DAO_K_MASK;
        dao.rpl_flags |= RPL_DAO_D_MASK;
        dao.rpl_daoseq = dag->dsn;
        dao.rpl_dagid = dag->dodagid;

        // dag_log_dodagid(dag);

        // char dodagid_hex[33];
        // dodagid_to_hex(dag, dodagid_hex);

        // uint8_t *encrypted_dodagid = dag_encrypt_dodagid(dodagid_hex);

        // memcpy(dao.rpl_dagid.s6_addr, encrypted_dodagid, 16);

        safe_buffer_append(sb, &dao, sizeof(dao));
        flog(LOG_INFO, "build dao");
}

void encrypt_daoack_sec(struct nd_rpl_daoack *dao, struct nd_rpl_padn **padns, uint8_t num_padns, uint8_t *encrypted_data)
{
        flog(LOG_INFO, "encrypt_daoack_sec");
        uint8_t data_to_encrypt[32];
        memcpy(data_to_encrypt, &dao->rpl_instanceid, sizeof(dao->rpl_instanceid));  
        memcpy(data_to_encrypt + 1, &dao->rpl_daoseq, sizeof(dao->rpl_daoseq));   
        memcpy(data_to_encrypt + 2, &dao->rpl_status, sizeof(dao->rpl_status)); 

        size_t offset = 3;
        for (size_t i = 0; i < num_padns; i++) {
            memcpy(data_to_encrypt + offset, padns[i]->padding, padns[i]->option_length);
            offset += padns[i]->option_length;
        }
        memcpy(data_to_encrypt + offset, dao->rpl_dagid.s6_addr, 16);

        const uint8_t aes_key[16];
        memcpy(aes_key, shared_secret, 16);
        // log_hex("encrypt_daoack_sec AES key", aes_key, 16);

        struct AES_ctx ctx;
        AES_init_ctx(&ctx, aes_key);

        // log_hex("DAO ACK to encrypt", data_to_encrypt, 32);
        AES_ECB_encrypt(&ctx, data_to_encrypt);
        AES_ECB_encrypt(&ctx, data_to_encrypt + 16);
        // log_hex("DAO ACK encrypted", data_to_encrypt, 32);

        memcpy(encrypted_data, data_to_encrypt, sizeof(data_to_encrypt));
}

void dag_build_dao_ack_sec(struct dag *dag, struct safe_buffer *sb)
{
        struct nd_rpl_security dao_sec = {};
        struct nd_rpl_daoack dao = {};
        size_t num_padns = 3;
        struct nd_rpl_padn *padns[num_padns];
        size_t offset = 3;
        uint8_t padding_sizes[] = {5, 5, 3};

        for (size_t i = 0; i < num_padns; i++) {
            padns[i] = create_padn(padding_sizes[i]);
        }

        dag_build_icmp(sb, ND_RPL_SEC_DAG_ACK);

        dao.rpl_instanceid = dag->rpl->instance_id;
        dao.rpl_flags |= RPL_DAO_K_MASK;
        dao.rpl_flags |= RPL_DAO_D_MASK;
        dao.rpl_daoseq = dag->dsn;
        dao.rpl_dagid = dag->dodagid;

        uint8_t encrypted_daoack[32];
        encrypt_daoack_sec(&dao, padns, num_padns, encrypted_daoack);

        memcpy(&dao.rpl_instanceid, encrypted_daoack, sizeof(dao.rpl_instanceid)); 
        memcpy(&dao.rpl_daoseq, encrypted_daoack + 1, sizeof(dao.rpl_daoseq));
        memcpy(&dao.rpl_status, encrypted_daoack + 2, sizeof(dao.rpl_status));
        
        for (size_t i = 0; i < num_padns; i++) {
            memcpy(padns[i]->padding, encrypted_daoack + offset, padns[i]->option_length);
            offset += padns[i]->option_length;
        }
        memcpy(dao.rpl_dagid.s6_addr, encrypted_daoack + offset, 16);

        safe_buffer_append(sb, &dao_sec, sizeof(dao_sec) + 1);
        safe_buffer_append(sb, &dao, sizeof(dao));
        
        for (size_t i = 0; i < num_padns; i++) {
            safe_buffer_append(sb, padns[i], sizeof(padns[i]->option_type) + sizeof(padns[i]->option_length) + padding_sizes[i]);
        }

        flog(LOG_INFO, "build dao_ack_sec");
}

static int append_target(const struct in6_prefix *prefix,
                         struct safe_buffer *sb)
{
        struct rpl_dao_target target = {};
        uint8_t len;

        len = sizeof(target) - sizeof(target.rpl_dao_prefix) +
              bits_to_bytes(prefix->len);

        target.rpl_dao_type = RPL_DAO_RPLTARGET;
        /* TODO crazy calculation here */
        target.rpl_dao_len = 18;
        target.rpl_dao_prefixlen = prefix->len;
        target.rpl_dao_prefix = prefix->prefix;
        safe_buffer_append(sb, &target, len);

        return 0;
}

void dag_build_dao(struct dag *dag, struct safe_buffer *sb)
{
        struct nd_rpl_daoack daoack = {};
        struct in6_prefix prefix;
        const struct child *child;
        const struct list *c;

        dag_build_icmp(sb, ND_RPL_DAO);

        daoack.rpl_instanceid = dag->rpl->instance_id;
        daoack.rpl_flags |= RPL_DAO_D_MASK;
        daoack.rpl_dagid = dag->dodagid;

        // char dodagid_hex[33];
        // dodagid_to_hex(dag, dodagid_hex);

        // uint8_t *encrypted_dodagid = dag_encrypt_dodagid(dodagid_hex);

        // memcpy(daoack.rpl_dagid.s6_addr, encrypted_dodagid, 16);

        safe_buffer_append(sb, &daoack, sizeof(daoack));
        prefix.prefix = dag->self;
        prefix.len = 128;
        append_target(&prefix, sb);

        DL_FOREACH(dag->childs.head, c)
        {
                child = container_of(c, struct child, list);
                prefix.prefix = child->addr;
                prefix.len = 128;

                append_target(&prefix, sb);
        }

        dag_daoack_insert(dag, dag->dsn);
        daoack.rpl_daoseq = dag->dsn++;
        flog(LOG_INFO, "build dao");
}

void encrypt_dao(struct nd_rpl_dao *dao, struct nd_rpl_padn **padns, struct nd_rpl_pad1 **pad1, uint8_t num_padns, uint8_t *encrypted_data)
{
        flog(LOG_INFO, "encrypt_dao");
        uint8_t data_to_encrypt[32];
        size_t offset = 3;
        memcpy(data_to_encrypt, &dao->rpl_instanceid, sizeof(dao->rpl_instanceid));  
        memcpy(data_to_encrypt + 1, &dao->rpl_resv, sizeof(dao->rpl_resv));   
        memcpy(data_to_encrypt + 2, &dao->rpl_daoseq, sizeof(dao->rpl_daoseq));
        for (size_t i = 0; i < num_padns; i++) {
            memcpy(data_to_encrypt + offset, padns[i]->padding, padns[i]->option_length);
            offset += padns[i]->option_length;
        }

        if (&pad1 != 1)
            memcpy(data_to_encrypt + offset, &pad1, sizeof(pad1));

        memcpy(data_to_encrypt + offset, dao->rpl_dagid.s6_addr, 16);

        const uint8_t aes_key[16];
        memcpy(aes_key, shared_secret, 16);
        // log_hex("encrypt_dao AES key", aes_key, 16);

        struct AES_ctx ctx;
        AES_init_ctx(&ctx, aes_key);

        // log_hex("DAO to encrypt", data_to_encrypt, 32);
        AES_ECB_encrypt(&ctx, data_to_encrypt);
        AES_ECB_encrypt(&ctx, data_to_encrypt + 16);

        memcpy(encrypted_data, data_to_encrypt, sizeof(data_to_encrypt));
        // log_hex("DAO encrypted", encrypted_data, 32);
}

void free_padn(struct nd_rpl_padn *padn) {
    if (padn) {
        free(padn->padding);
        free(padn);
    }
}

struct nd_rpl_padn *create_padn(uint8_t length) {
    struct nd_rpl_padn *padn = malloc(sizeof(struct nd_rpl_padn));
    if (!padn) {
        perror("Falha ao alocar PADN");
        exit(EXIT_FAILURE);
    }

    padn->option_type = 0x01;
    padn->option_length = length;
    memset(padn->padding, 0, length);

    if (!padn->padding) {
        perror("Falha ao alocar padding");
        free(padn);
        exit(EXIT_FAILURE);
    }

    //memset(padn->padding, 0, length);

    return padn;
}

struct padding_result calculate_padding_dao(size_t struct_size) {
    const size_t MAX_PADN_SIZE = 5;
    const size_t BASE_SIZE = 32;
    const size_t EXPANSION_SIZE = 16;
    
    size_t total_size = (struct_size > BASE_SIZE) 
                        ? BASE_SIZE + ((struct_size - BASE_SIZE + EXPANSION_SIZE - 1) / EXPANSION_SIZE) * EXPANSION_SIZE 
                        : BASE_SIZE;

    size_t padding_needed = total_size - struct_size;
    size_t num_padns = (padding_needed + MAX_PADN_SIZE - 1) / MAX_PADN_SIZE; // Arredondar para cima
    
    // Alocar memória dinamicamente para padding_sizes
    uint8_t *padding_sizes = (uint8_t *)malloc(num_padns * sizeof(uint8_t));
    struct padding_result result;
    
    memset(padding_sizes, 0, num_padns * sizeof(uint8_t));
    size_t remaining_padding = padding_needed;
    for (size_t i = 0; i < num_padns; i++) {
        size_t padding_value = (remaining_padding >= MAX_PADN_SIZE) ? MAX_PADN_SIZE : remaining_padding;
        
        if (padding_value == 1)            
            padding_sizes[i] = 1;
        else{
            padding_sizes[i] = padding_value;
            remaining_padding -= padding_value;
        }
    }

    result.num_padns = num_padns;
    result.padding_sizes = padding_sizes;
    result.total_size = total_size;

    for (size_t i = 0; i < num_padns; i++) {
        if (padding_sizes[i] > 1)
            flog(LOG_INFO, "PadN[%zu]: %d bytes", i, padding_sizes[i]);
        else
            flog(LOG_INFO, "Pad1: 1 byte");
    }
            
    return result;
}

void dag_build_dao_sec(struct dag *dag, struct safe_buffer *sb)
{
        struct nd_rpl_security dao_sec = {};
        struct nd_rpl_dao dao = {};
        struct in6_prefix prefix;
        const struct child *child;
        const struct list *c;

        struct padding_result result = calculate_padding_dao(sizeof(dao) - 1);
        
        struct nd_rpl_padn *padns[result.num_padns];
        struct nd_rpl_pad1 *pad1 = 1 ;
        for (size_t i = 0; i < result.num_padns; i++) {
            if (result.padding_sizes[i] > 1)
                padns[i] = create_padn(result.padding_sizes[i]);
            else{
                result.num_padns --;
                pad1 = 0x00;            
            }
        }

        dag_build_icmp(sb, ND_RPL_SEC_DAG);

        dao.rpl_instanceid = dag->rpl->instance_id;
        dao.rpl_flags |= RPL_DAO_D_MASK;
        dao.rpl_dagid = dag->dodagid;

        uint8_t encrypted_dao[result.total_size];
        encrypt_dao(&dao, padns, pad1, result.num_padns, encrypted_dao);

        memcpy(&dao.rpl_instanceid, encrypted_dao, sizeof(dao.rpl_instanceid)); 
        memcpy(&dao.rpl_resv, encrypted_dao + 1, sizeof(dao.rpl_resv));    
        memcpy(&dao.rpl_daoseq, encrypted_dao + 2, sizeof(dao.rpl_daoseq));  

        size_t offset = 3;
        for (size_t i = 0; i < result.num_padns; i++) {
            memcpy(padns[i]->padding, encrypted_dao + offset, padns[i]->option_length);
            offset += padns[i]->option_length;
        }
        memcpy(dao.rpl_dagid.s6_addr, encrypted_dao + offset, 16);
        
        safe_buffer_append(sb, &dao_sec, sizeof(dao_sec) + 1);
        safe_buffer_append(sb, &dao, sizeof(dao));
        prefix.prefix = dag->self;
        prefix.len = 128;
        append_target(&prefix, sb);

        DL_FOREACH(dag->childs.head, c)
        {
                child = container_of(c, struct child, list);
                prefix.prefix = child->addr;
                prefix.len = 128;

                append_target(&prefix, sb);
        }

        dag_daoack_insert(dag, dag->dsn);
        dao.rpl_daoseq = dag->dsn++;

        for (size_t i = 0; i < result.num_padns; i++) {
            safe_buffer_append(sb, padns[i], sizeof(padns[i]->option_type) + sizeof(padns[i]->option_length) + result.padding_sizes[i]);
        }
        if (pad1 != 1){
            safe_buffer_append(sb, &pad1, 1);
        }

        for (size_t i = 0; i < result.num_padns; i++) {
           // free_padn(padns[i]);
        }

        free(result.padding_sizes);

        flog(LOG_INFO, "build dao_sec");
}

void dag_build_dis(struct safe_buffer *sb)
{
        struct nd_rpl_dis dis = {};

        dag_build_icmp(sb, ND_RPL_DAG_IS);

        safe_buffer_append(sb, &dis, sizeof(dis));
        flog(LOG_INFO, "build dis");
}

void encrypt_dis(struct nd_rpl_dis *dis, struct nd_rpl_padn **padns, uint8_t num_padns, uint8_t *encrypted_data)
{
        flog(LOG_INFO, "encrypt_dis");
        uint8_t data_to_encrypt[16];
        memcpy(data_to_encrypt, dis, 2);
     
        size_t offset = 2;
        for (size_t i = 0; i < num_padns; i++) {
            memcpy(data_to_encrypt + offset, padns[i]->padding, padns[i]->option_length);
            offset += padns[i]->option_length;
        }
        const uint8_t aes_key[16];
        memcpy(aes_key, shared_secret, 16);
        // log_hex("encrypt_dis AES key", aes_key, 16);

        struct AES_ctx ctx;
        AES_init_ctx(&ctx, aes_key);

        // log_hex("DIS to encrypt", data_to_encrypt, 16);
        AES_ECB_encrypt(&ctx, data_to_encrypt);
        // log_hex("DIS encrypted", data_to_encrypt, 16);

        memcpy(encrypted_data, data_to_encrypt, sizeof(data_to_encrypt));
}

void dag_build_dis_sec(struct safe_buffer *sb)
{
    struct nd_rpl_security dis_sec = {};
    struct nd_rpl_dis dis = {};
    size_t num_padns = 3;
    struct nd_rpl_padn *padns[num_padns];
    size_t offset = 2;
    uint8_t padding_sizes[] = {5, 5, 4};

    for (size_t i = 0; i < num_padns; i++) {
        padns[i] = create_padn(padding_sizes[i]);
    }

    dag_build_icmp(sb, ND_RPL_SEC_DAG_IS);

    uint8_t encrypted_dis[16];
    encrypt_dis(&dis, padns, num_padns, encrypted_dis);

    safe_buffer_append(sb, &dis_sec, sizeof(dis_sec) + 1);
 
    memcpy(&dis, encrypted_dis, 2);
    for (size_t i = 0; i < num_padns; i++) {
        memcpy(padns[i]->padding, encrypted_dis + offset, padns[i]->option_length);
        offset += padns[i]->option_length;
    }

    safe_buffer_append(sb, &dis, sizeof(dis) -1);

    for (size_t i = 0; i < num_padns; i++) {
        safe_buffer_append(sb, padns[i], sizeof(padns[i]->option_type) + sizeof(padns[i]->option_length) + padding_sizes[i]);
    }

    flog(LOG_INFO, "build dis_sec");
}

void dag_build_pk(struct safe_buffer *sb, struct iface *iface)
{
        dag_build_icmp(sb, ND_RPL_SEC_PK_EXCH);

        if (iface->enc_mode == ENC_MODE_RSA)
        {
                // struct key_class rec_pk_class;
                // uint8_to_key_class(iface->public_key, &rec_pk_class);
                // flog(LOG_INFO, "Sending public key: %llu %llu", rec_pk_class.modulus, rec_pk_class.exponent);
                safe_buffer_append(sb, iface->public_key, RSA_KEY_SIZE_BYTES);
        }
        else if (iface->enc_mode == ENC_MODE_KYBER)
        {
                safe_buffer_append(sb, iface->public_key, CRYPTO_PUBLICKEYBYTES);
        }
}

void dag_build_ct(struct safe_buffer *sb, const u_int8_t *rec_pk, int mode)
{
        dag_build_icmp(sb, ND_RPL_SEC_CT_EXCH);

        // Shared Secret with 32 bytes in hexadecimal: 89E9D140FD7371107BBEBCF61E4390C56B8933145F864B02387D3FD2D9982202
        // Shared Secret with 16 bytes in hexadecimal: 89E9D140FD7371107BBEBCF61E4390C5
        const char *ss = "89E9D140FD7371107BBEBCF61E4390C5";
        if (mode == ENC_MODE_RSA)
        {
                memcpy(shared_secret, ss, RSA_SS_SIZE_BYTES);

                struct key_class rec_pk_class;
                uint8_to_key_class(rec_pk, &rec_pk_class);
                const long long *encrypted_ss = rsa_encrypt(ss, RSA_SS_SIZE_BYTES, &rec_pk_class);

                log_hex("Encapsulated Shared Secret: ", shared_secret, RSA_SS_SIZE_BYTES);
                safe_buffer_append(sb, encrypted_ss, RSA_CIPHERTEXT_SIZE_BYTES);
        }
        else if (mode == ENC_MODE_KYBER)
        {
                memcpy(shared_secret, ss, KYBER_SSBYTES);

                u_int8_t cipher_text[KYBER_CIPHERTEXTBYTES];
                uint8_t coins[KYBER_SYMBYTES];
                randombytes(coins, KYBER_SYMBYTES);
                indcpa_enc(cipher_text, shared_secret, rec_pk, coins);
                
                // crypto_kem_enc(cipher_text, shared_secret, rec_pk);
                log_hex("Encapsulated Shared Secret: ", shared_secret, CRYPTO_BYTES);
                safe_buffer_append(sb, cipher_text, KYBER_CIPHERTEXTBYTES);
        }
}
