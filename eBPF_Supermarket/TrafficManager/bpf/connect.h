#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef EPERM
# define EPERM		1
#endif
#ifndef ENOENT
# define ENOENT		2
#endif
#ifndef ENXIO
# define ENXIO		6
#endif
#ifndef ENOMEM
# define ENOMEM		12
#endif
#ifndef EFAULT
# define EFAULT		14
#endif
#ifndef EINVAL
# define EINVAL		22
#endif
#ifndef ENOTSUP
# define ENOTSUP	95
#endif
#ifndef EADDRINUSE
# define EADDRINUSE	98
#endif
#ifndef ENOTSUPP
# define ENOTSUPP	524
#endif
#ifndef ENETRESET
# define ENETRESET 3434
#endif

#define SYS_PROCEED 1

#define LB_SERVICE_MAP_MAX_ENTRIES	65536
#define LB_BACKENDS_MAP_MAX_ENTRIES	65536

// sudo cat /sys/kernel/debug/tracing/trace_pipe

#define print_ip_formatted(ip)                          \
({                                                      \
    bpf_printk("ip1: %d.%d",                            \
                ip%256, (ip/256)%256);                  \
    bpf_printk("ip2: %d.%d\n",                          \
                (ip/65536)%256, (ip/16711680)%256);     \
})

struct lb4_key {
	__be32 address;		/* Service virtual IPv4 address */
	__be16 dport;		/* L4 port filter, if unset, all ports apply */
	__u16 backend_slot;	/* Backend iterator, 0 indicates the svc frontend */
	__u8 proto;		    /* L4 protocol, currently not used (set to 0) */
	__u8 scope;		    /* LB_LOOKUP_SCOPE_* for externalTrafficPolicy=Local */
	__u8 pad[2];
};

struct lb4_service {
    __u32 backend_id;	    /* Backend ID in lb4_backends */
	__u16 count;
	__u8  pad[2];
};

struct lb4_backend {
	__be32 address;		/* Service endpoint IPv4 address */
	__be16 port;		/* L4 port filter */
	__u8 proto;		    /* L4 protocol, currently not used (set to 0) */
	__u8 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb4_key);
	__type(value, struct lb4_service);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB_SERVICE_MAP_MAX_ENTRIES);
} LB4_SERVICES_MAP_V2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct lb4_backend);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB_BACKENDS_MAP_MAX_ENTRIES);
} LB4_BACKEND_MAP_V2 SEC(".maps");

static __always_inline __be32 ctx_get_dst_ip(const struct bpf_sock_addr *ctx)
{
    volatile __u32 dst_ip = ctx->user_ip4;
    return (__be32)dst_ip;
}

static __always_inline __be16 ctx_get_dst_port(const struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;
	return (__be16)dport;
}

static __always_inline void ctx_set_dst_ip(struct bpf_sock_addr *ctx, __be32 dst_ip)
{
	ctx->user_ip4 = (__u32)dst_ip;
}

static __always_inline void ctx_set_dst_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}

static __always_inline __be16 ctx_get_src_port(const struct bpf_sock *ctx)
{
	volatile __u16 sport = (__u16)ctx->src_port;
	return (__be16)bpf_htons(sport);
}

static __always_inline struct lb4_service *lb4_lookup_service(struct lb4_key *key)
{
	struct lb4_service *svc;

	svc = bpf_map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
    if (svc)
        return svc;

	return NULL;
}

static __always_inline __u64 sock_select_random_slot(int sbc)
{
    int slot_index = bpf_get_prandom_u32() % sbc;
	return slot_index + 1;
}

static __always_inline struct lb4_service *lookup_lb4_backend_slot(struct lb4_key *key)
{
	return bpf_map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
}

static __always_inline struct lb4_backend *lookup_lb4_backend(__u32 backend_id)
{
	return bpf_map_lookup_elem(&LB4_BACKEND_MAP_V2, &backend_id);
}
