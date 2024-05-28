/* SPDX-License-Identifier: GPL-2.0-only
 *
 * add a netlat to monitor tcp -package latency
 *
 * Author: mengensun <mengensun@tencent.com>
 * Copyright (C) 2024 Tencent, Inc
 */

#ifndef H______NETLAT
#define H______NETLAT

#ifdef CONFIG_NETLAT

#define QUEUE_FLAG_OFO 0x1
#define QUEUE_FLAG_RCV 0x2

int netlat_net_init(void);
void netlat_net_exit(void);
void netlat_ack_check(struct sock *sk, struct sk_buff *skb);
void netlat_copy_rtxq_skb(struct sock *sk, struct sk_buff *dst, struct sk_buff *src);
void netlat_tcp_enrtxqueue(struct sock *sk, struct sk_buff *skb);
#define netlat_check(oldest, sk, skb) \
do { \
	if (oldest) { \
		netlat_ack_check(sk, skb); \
		oldest = false; \
	} \
} while (0)

void netlat_queue_check(struct sock *sk, struct sk_buff *skb, int flags);
void netlat_pick_check(struct sock *sk, struct sk_buff *skb);

#else /* CONFIG_NETLAT */
static __always_inline int netlat_net_init(void) { return 0; };
static __always_inline void netlat_net_exit(void) { };
static __always_inline void netlat_ack_check(struct sock *sk,
					     struct sk_buff *skb) { };
static __always_inline void netlat_copy_rtxq_skb(struct sock *sk,
						 struct sk_buff *dst,
						 struct sk_buff *src) { };
static __always_inline void netlat_tcp_enrtxqueue(struct sock *sk,
						  struct sk_buff *skb) { };
#define netlat_check(oldest, sk, skb)

#define QUEUE_FLAG_OFO 0x1
#define QUEUE_FLAG_RCV 0x2
#define netlat_queue_check(sk, skb, flags)

#define netlat_pick_check(sk, skb)
#endif /* !CONFIG_NETLAT */
#endif
