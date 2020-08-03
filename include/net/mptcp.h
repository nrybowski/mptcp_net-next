/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multipath TCP
 *
 * Copyright (c) 2017 - 2019, Intel Corporation.
 */

#ifndef __NET_MPTCP_H
#define __NET_MPTCP_H

#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>

struct seq_file;

/* MPTCP sk_buff extension data */
struct mptcp_ext {
	union {
		u64	data_ack;
		u32	data_ack32;
	};
	u64		data_seq;
	u32		subflow_seq;
	u16		data_len;
	u8		use_map:1,
			dsn64:1,
			data_fin:1,
			use_ack:1,
			ack64:1,
			mpc_map:1,
			__unused:2;
	/* one byte hole */
};

struct mptcp_out_options {
#if IS_ENABLED(CONFIG_MPTCP)
	u16 suboptions;
	u64 sndr_key;
	u64 rcvr_key;
	union {
		struct in_addr addr;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		struct in6_addr addr6;
#endif
	};
	u8 addr_id;
	u64 ahmac;
	u8 rm_id;
	u8 join_id;
	u8 backup;
	u32 nonce;
	u64 thmac;
	u32 token;
	u8 hmac[20];
	struct mptcp_ext ext_copy;
#endif
};

struct mptcp_addr_info {
	sa_family_t		family;
	__be16			port;
	u8			id;
	union {
		struct in_addr addr;
#if IS_ENABLED(CONFIG_MPTCP_IPV6)
		struct in6_addr addr6;
#endif
	};
};

struct mptcp_pm_data {
	struct mptcp_addr_info local;
	struct mptcp_addr_info remote;

	spinlock_t	lock;		/*protects the whole PM data */

	bool		addr_signal;
	bool		server_side;
	bool		work_pending;
	bool		accept_addr;
	bool		accept_subflow;
	u8		add_addr_signaled;
	u8		add_addr_accepted;
	u8		local_addr_used;
	u8		subflows;
	u8		add_addr_signal_max;
	u8		add_addr_accept_max;
	u8		local_addr_max;
	u8		subflows_max;
	u8		status;
};

/* MPTCP connection sock */
struct mptcp_sock {
	/* inet_connection_sock must be the first member */
	struct inet_connection_sock sk;
	u64		local_key;
	u64		remote_key;
	u64		write_seq;
	u64		ack_seq;
	u64		rcv_data_fin_seq;
	atomic64_t	snd_una;
	unsigned long	timer_ival;
	u32		token;
	unsigned long	flags;
	bool		can_ack;
	bool		fully_established;
	bool		rcv_data_fin;
	bool		snd_data_fin_enable;
	spinlock_t	join_list_lock;
	struct work_struct work;
	struct list_head conn_list;
	struct list_head rtx_queue;
	struct list_head join_list;
	struct skb_ext	*cached_ext;	/* for the next sendmsg */
	struct socket	*subflow; /* outgoing connect/listener/!mp_capable */
	struct sock	*first;
	struct mptcp_pm_data	pm;
	struct {
		u32	space;	/* bytes copied in last measurement window */
		u32	copied; /* bytes copied in this measurement window */
		u64	time;	/* start time of measurement window */
		u64	rtt_us; /* last maximum rtt of subflows */
	} rcvq_space;
};

#define MPTCPOPT_HMAC_LEN	20

/* MPTCP subflow context */
struct mptcp_subflow_context {
	struct	list_head node;/* conn_list of subflows */
	u64	local_key;
	u64	remote_key;
	u64	idsn;
	u64	map_seq;
	u32	snd_isn;
	u32	token;
	u32	rel_write_seq;
	u32	map_subflow_seq;
	u32	ssn_offset;
	u32	map_data_len;
	u32	request_mptcp : 1,  /* send MP_CAPABLE */
		request_join : 1,   /* send MP_JOIN */
		request_bkup : 1,
		mp_capable : 1,	    /* remote is MPTCP capable */
		mp_join : 1,	    /* remote is JOINing */
		fully_established : 1,	    /* path validated */
		pm_notified : 1,    /* PM hook called for established status */
		conn_finished : 1,
		map_valid : 1,
		mpc_map : 1,
		backup : 1,
		data_avail : 1,
		rx_eof : 1,
		use_64bit_ack : 1, /* Set when we received a 64-bit DSN */
		can_ack : 1;	    /* only after processing the remote a key */
	u32	remote_nonce;
	u64	thmac;
	u32	local_nonce;
	u32	remote_token;
	u8	hmac[MPTCPOPT_HMAC_LEN];
	u8	local_id;
	u8	remote_id;

	struct	sock *tcp_sock;	    /* tcp sk backpointer */
	struct	sock *conn;	    /* parent mptcp_sock */
	const	struct inet_connection_sock_af_ops *icsk_af_ops;
	void	(*tcp_data_ready)(struct sock *sk);
	void	(*tcp_state_change)(struct sock *sk);
	void	(*tcp_write_space)(struct sock *sk);

	struct	rcu_head rcu;
};

#ifdef CONFIG_MPTCP
extern struct request_sock_ops mptcp_subflow_request_sock_ops;

void mptcp_init(void);

static inline bool sk_is_mptcp(const struct sock *sk)
{
	return tcp_sk(sk)->is_mptcp;
}

static inline bool rsk_is_mptcp(const struct request_sock *req)
{
	return tcp_rsk(req)->is_mptcp;
}

static inline bool rsk_drop_req(const struct request_sock *req)
{
	return tcp_rsk(req)->is_mptcp && tcp_rsk(req)->drop_req;
}

void mptcp_space(const struct sock *ssk, int *space, int *full_space);
bool mptcp_syn_options(struct sock *sk, const struct sk_buff *skb,
		       unsigned int *size, struct mptcp_out_options *opts);
bool mptcp_synack_options(const struct request_sock *req, unsigned int *size,
			  struct mptcp_out_options *opts);
bool mptcp_established_options(struct sock *sk, struct sk_buff *skb,
			       unsigned int *size, unsigned int remaining,
			       struct mptcp_out_options *opts);
void mptcp_incoming_options(struct sock *sk, struct sk_buff *skb,
			    struct tcp_options_received *opt_rx);

void mptcp_write_options(__be32 *ptr, struct mptcp_out_options *opts);

/* move the skb extension owership, with the assumption that 'to' is
 * newly allocated
 */
static inline void mptcp_skb_ext_move(struct sk_buff *to,
				      struct sk_buff *from)
{
	if (!skb_ext_exist(from, SKB_EXT_MPTCP))
		return;

	if (WARN_ON_ONCE(to->active_extensions))
		skb_ext_put(to);

	to->active_extensions = from->active_extensions;
	to->extensions = from->extensions;
	from->active_extensions = 0;
}

static inline bool mptcp_ext_matches(const struct mptcp_ext *to_ext,
				     const struct mptcp_ext *from_ext)
{
	/* MPTCP always clears the ext when adding it to the skb, so
	 * holes do not bother us here
	 */
	return !from_ext ||
	       (to_ext && from_ext &&
	        !memcmp(from_ext, to_ext, sizeof(struct mptcp_ext)));
}

/* check if skbs can be collapsed.
 * MPTCP collapse is allowed if neither @to or @from carry an mptcp data
 * mapping, or if the extension of @to is the same as @from.
 * Collapsing is not possible if @to lacks an extension, but @from carries one.
 */
static inline bool mptcp_skb_can_collapse(const struct sk_buff *to,
					  const struct sk_buff *from)
{
	return mptcp_ext_matches(skb_ext_find(to, SKB_EXT_MPTCP),
				 skb_ext_find(from, SKB_EXT_MPTCP));
}

void mptcp_seq_show(struct seq_file *seq);
int mptcp_subflow_init_cookie_req(struct request_sock *req,
				  const struct sock *sk_listener,
				  struct sk_buff *skb);

static inline struct mptcp_subflow_context *
mptcp_subflow_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* Use RCU on icsk_ulp_data only for sock diag code */
	return (__force struct mptcp_subflow_context *)icsk->icsk_ulp_data;
}

#else

static inline void mptcp_init(void)
{
}

static inline bool sk_is_mptcp(const struct sock *sk)
{
	return false;
}

static inline bool rsk_is_mptcp(const struct request_sock *req)
{
	return false;
}

static inline bool rsk_drop_req(const struct request_sock *req)
{
	return false;
}

static inline void mptcp_parse_option(const struct sk_buff *skb,
				      const unsigned char *ptr, int opsize,
				      struct tcp_options_received *opt_rx)
{
}

static inline bool mptcp_syn_options(struct sock *sk, const struct sk_buff *skb,
				     unsigned int *size,
				     struct mptcp_out_options *opts)
{
	return false;
}

static inline bool mptcp_synack_options(const struct request_sock *req,
					unsigned int *size,
					struct mptcp_out_options *opts)
{
	return false;
}

static inline bool mptcp_established_options(struct sock *sk,
					     struct sk_buff *skb,
					     unsigned int *size,
					     unsigned int remaining,
					     struct mptcp_out_options *opts)
{
	return false;
}

static inline void mptcp_incoming_options(struct sock *sk,
					  struct sk_buff *skb,
					  struct tcp_options_received *opt_rx)
{
}

static inline void mptcp_skb_ext_move(struct sk_buff *to,
				      const struct sk_buff *from)
{
}

static inline bool mptcp_skb_can_collapse(const struct sk_buff *to,
					  const struct sk_buff *from)
{
	return true;
}

static inline void mptcp_space(const struct sock *ssk, int *s, int *fs) { }
static inline void mptcp_seq_show(struct seq_file *seq) { }

static inline int mptcp_subflow_init_cookie_req(struct request_sock *req,
						const struct sock *sk_listener,
						struct sk_buff *skb)
{
	return 0; /* TCP fallback */
}

static inline struct mptcp_subflow_context *
mptcp_subflow_ctx(const struct sock *sk)
{
	return NULL;
}
#endif /* CONFIG_MPTCP */

#if IS_ENABLED(CONFIG_MPTCP_IPV6)
int mptcpv6_init(void);
void mptcpv6_handle_mapped(struct sock *sk, bool mapped);
#elif IS_ENABLED(CONFIG_IPV6)
static inline int mptcpv6_init(void) { return 0; }
static inline void mptcpv6_handle_mapped(struct sock *sk, bool mapped) { }
#endif

#endif /* __NET_MPTCP_H */
