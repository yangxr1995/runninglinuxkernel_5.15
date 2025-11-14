// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_fq.c Fair Queue Packet Scheduler (per flow pacing)
 *
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 *  Meant to be mostly used for locally generated traffic :
 *  Fast classification depends on skb->sk being set before reaching us.
 *  If not, (router workload), we use rxhash as fallback, with 32 bits wide hash.
 *  All packets belonging to a socket are considered as a 'flow'.
 *
 *  Flows are dynamically allocated and stored in a hash table of RB trees
 *  They are also part of one Round Robin 'queues' (new or old flows)
 *
 *  Burst avoidance (aka pacing) capability :
 *
 *  Transport (eg TCP) can set in sk->sk_pacing_rate a rate, enqueue a
 *  bunch of packets, and this packet scheduler adds delay between
 *  packets to respect rate limitation.
 *
 *  enqueue() :
 *   - lookup one RB tree (out of 1024 or more) to find the flow.
 *     If non existent flow, create it, add it to the tree.
 *     Add skb to the per flow list of skb (fifo).
 *   - Use a special fifo for high prio packets
 *
 *  dequeue() : serves flows in Round Robin
 *  Note : When a flow becomes empty, we do not immediately remove it from
 *  rb trees, for performance reasons (its expected to send additional packets,
 *  or SLAB cache will reuse socket for another flow)
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/hash.h>
#include <linux/prefetch.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

struct fq_skb_cb {
	u64	        time_to_send;
};

static inline struct fq_skb_cb *fq_skb_cb(struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct fq_skb_cb));
	return (struct fq_skb_cb *)qdisc_skb_cb(skb)->data;
}

/*
 * Per flow structure, dynamically allocated.
 * If packets have monotically increasing time_to_send, they are placed in O(1)
 * in linear list (head,tail), otherwise are placed in a rbtree (t_root).
 */
struct fq_flow {
/* First cache line : used in fq_gc(), fq_enqueue(), fq_dequeue() */
	struct rb_root	t_root;
	struct sk_buff	*head;		/* list of skbs for this flow : first skb */
	union {
		struct sk_buff *tail;	/* last skb in the list */
		unsigned long  age;	/* (jiffies | 1UL) when flow was emptied, for gc */
	};
	struct rb_node	fq_node;	/* anchor in fq_root[] trees */
	struct sock	*sk;
	u32		socket_hash;	/* sk_hash */
	int		qlen;		/* number of packets in flow queue */

/* Second cache line, used in fq_dequeue() */
	int		credit;
	/* 32bit hole on 64bit arches */

	struct fq_flow *next;		/* next pointer in RR lists */

	struct rb_node  rate_node;	/* anchor in q->delayed tree */
	u64		time_next_packet;
} ____cacheline_aligned_in_smp;

struct fq_flow_head {
	struct fq_flow *first;
	struct fq_flow *last;
};

struct fq_sched_data {
	struct fq_flow_head new_flows;

	struct fq_flow_head old_flows;

	struct rb_root	delayed;	/* for rate limited flows */
	u64		time_next_delayed_flow;
	u64		ktime_cache;	/* copy of last ktime_get_ns() */
	unsigned long	unthrottle_latency_ns;

	struct fq_flow	internal;	/* for non classified or high prio packets */
	u32		quantum;
	u32		initial_quantum;
	u32		flow_refill_delay;
	u32		flow_plimit;	/* max packets per flow */
	unsigned long	flow_max_rate;	/* optional max rate per flow */
	u64		ce_threshold;
	u64		horizon;	/* horizon in ns */
	u32		orphan_mask;	/* mask for orphaned skb */
	u32		low_rate_threshold;
	struct rb_root	*fq_root;
	u8		rate_enable;
	u8		fq_trees_log;
	u8		horizon_drop;
	u32		flows;
	u32		inactive_flows;
	u32		throttled_flows;

	u64		stat_gc_flows;
	u64		stat_internal_packets;
	u64		stat_throttled;
	u64		stat_ce_mark;
	u64		stat_horizon_drops;
	u64		stat_horizon_caps;
	u64		stat_flows_plimit;
	u64		stat_pkts_too_long;
	u64		stat_allocation_errors;

	u32		timer_slack; /* hrtimer slack in ns */
	struct qdisc_watchdog watchdog;
};

/*
 * f->tail and f->age share the same location.
 * We can use the low order bit to differentiate if this location points
 * to a sk_buff or contains a jiffies value, if we force this value to be odd.
 * This assumes f->tail low order bit must be 0 since alignof(struct sk_buff) >= 2
 */
// union {
//     struct sk_buff *tail;    // 指向流队列的最后一个数据包
//     unsigned long  age;      // 流变为非活跃状态的时间戳
// 通过最低有效位区分数据类型：
//   偶数地址（最低位为0：指向`struct sk_buff`的指针
//   奇数地址（最低位为1：表示`jiffies`时间戳
static void fq_flow_set_detached(struct fq_flow *f)
{
	f->age = jiffies | 1UL;
}

static bool fq_flow_is_detached(const struct fq_flow *f)
{
	return !!(f->age & 1UL);
}

/* special value to mark a throttled flow (not on old/new list) */
static struct fq_flow throttled;

static bool fq_flow_is_throttled(const struct fq_flow *f)
{
	return f->next == &throttled;
}

static void fq_flow_add_tail(struct fq_flow_head *head, struct fq_flow *flow)
{
	if (head->first)
		head->last->next = flow;
	else
		head->first = flow;
	head->last = flow;
	flow->next = NULL;
}

static void fq_flow_unset_throttled(struct fq_sched_data *q, struct fq_flow *f)
{
    // **操作：** 从红黑树中移除该流的rate_node节点
    // - `q->delayed`：存储所有节流流的红黑树，按`time_next_packet`排序
    // - `f->rate_node`：该流在红黑树中的锚点
    //
    // **目的：** 将流从节流队列中完全移除，不再受时间限制
	rb_erase(&f->rate_node, &q->delayed);
	q->throttled_flows--;
    // **操作：** 将流添加到`old_flows`队列的末尾
    // - `old_flows`：已经获得过服务的流的队列
    // - `fq_flow_add_tail`：标准的链表尾部插入操作
	fq_flow_add_tail(&q->old_flows, f);
}

// 将需要节流的流加入按时间排序的红黑树，等待合适的时机重新调度。
static void fq_flow_set_throttled(struct fq_sched_data *q, struct fq_flow *f)
{
    // `q->delayed`：存储所有被节流流的红黑树
    // 排序规则：按`time_next_packet`（下次发送时间）排序
	struct rb_node **p = &q->delayed.rb_node, *parent = NULL;

	while (*p) {
		struct fq_flow *aux;

		parent = *p;
		aux = rb_entry(parent, struct fq_flow, rate_node);
		if (f->time_next_packet >= aux->time_next_packet)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
	rb_link_node(&f->rate_node, parent, p);
	rb_insert_color(&f->rate_node, &q->delayed);
	q->throttled_flows++;
	q->stat_throttled++;

    // 节流状态标记
    // - `&throttled`：特殊的全局节流标记对象
    // - 用于判断流是否已处于节流状态
    // - 用于`fq_flow_is_throttled()`判断
	f->next = &throttled;
    // ## 5. 更新下一个节流流时间
    // 以最小的延迟发送时间为队列的延迟发送时间
	if (q->time_next_delayed_flow > f->time_next_packet) {
		q->time_next_delayed_flow = f->time_next_packet;
        trace_printk("%s:%d:q->time_next_delayed_flow:[%llx]",
                __func__, __LINE__, q->time_next_delayed_flow);
    }
}


static struct kmem_cache *fq_flow_cachep __read_mostly;


/* limit number of collected flows per round */
#define FQ_GC_MAX 8
#define FQ_GC_AGE (3*HZ)

static bool fq_gc_candidate(const struct fq_flow *f)
{
	return fq_flow_is_detached(f) &&
	       time_after(jiffies, f->age + FQ_GC_AGE);
}

static void fq_gc(struct fq_sched_data *q,
		  struct rb_root *root,
		  struct sock *sk)
{
	struct rb_node **p, *parent;
	void *tofree[FQ_GC_MAX];
	struct fq_flow *f;
	int i, fcnt = 0;

	p = &root->rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct fq_flow, fq_node);
		if (f->sk == sk)
			break;

		if (fq_gc_candidate(f)) {
			tofree[fcnt++] = f;
			if (fcnt == FQ_GC_MAX)
				break;
		}

		if (f->sk > sk)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}

	if (!fcnt)
		return;

	for (i = fcnt; i > 0; ) {
		f = tofree[--i];
		rb_erase(&f->fq_node, root);
	}
	q->flows -= fcnt;
	q->inactive_flows -= fcnt;
	q->stat_gc_flows += fcnt;

	kmem_cache_free_bulk(fq_flow_cachep, fcnt, tofree);
}

// 将数据包分类到对应的网络流，实现基于流的公平调度。
static struct fq_flow *fq_classify(struct sk_buff *skb, struct fq_sched_data *q)
{
	struct rb_node **p, *parent;
	struct sock *sk = skb->sk;
	struct rb_root *root;
	struct fq_flow *f;

	/* warning: no starvation prevention... */
    // ## 1. 控制数据包处理
    // **功能：** 优先处理控制数据包
    // - `TC_PRIO_CONTROL`：最高优先级控制流量（如路由协议）
    // - 直接放入内部队列（高优先级通道）
    // - 不参与公平调度，避免饥饿
	if (unlikely((skb->priority & TC_PRIO_MAX) == TC_PRIO_CONTROL))
		return &q->internal;

	/* SYNACK messages are attached to a TCP_NEW_SYN_RECV request socket
	 * or a listener (SYNCOOKIE mode)
	 * 1) request sockets are not full blown,
	 *    they do not contain sk_pacing_rate
	 * 2) They are not part of a 'flow' yet
	 * 3) We do not want to rate limit them (eg SYNFLOOD attack),
	 *    especially if the listener set SO_MAX_PACING_RATE
	 * 4) We pretend they are orphaned
	 */
    // ## 2. 特殊Socket处理
    // ### 2.1 无Socket或监听Socket
    // - `!sk`：数据包没有关联的Socket（如路由器转发的数据包）
    // - `sk_listener(sk)`：Socket处于监听状态（服务器端接受连接的Socket）
	if (!sk || sk_listener(sk)) {
       // 1. **生成哈希键值：**
       // - `skb_get_hash(skb)`：获取数据包的哈希值（基于5元组：源IP、目的IP、源端口、目的端口、协议）
       // - `& q->orphan_mask`：掩码操作，确保哈希值在有效范围内
		unsigned long hash = skb_get_hash(skb) & q->orphan_mask;

		/* By forcing low order bit to 1, we make sure to not
		 * collide with a local flow (socket pointers are word aligned)
		 */
        // 2. **创建伪Socket指针：**
        // - **为什么这样做？** 防止与真实的Socket指针冲突（真实指针是字对齐的，最低几位通常为0）
		sk = (struct sock *)((hash << 1) | 1UL);
        // - 将数据包标记为"孤儿"，不再与原始Socket关联
		skb_orphan(skb);
	} else if (sk->sk_state == TCP_CLOSE) {
        // ### 2.2 关闭状态Socket
		unsigned long hash = skb_get_hash(skb) & q->orphan_mask;
		/*
		 * Sockets in TCP_CLOSE are non connected.
		 * Typical use case is UDP sockets, they can send packets
		 * with sendto() to many different destinations.
		 * We probably could use a generic bit advertising
		 * non connected sockets, instead of sk_state == TCP_CLOSE,
		 * if we care enough.
		 */
		sk = (struct sock *)((hash << 1) | 1UL);
	}

    // ## 3. 红黑树根节点定位
    //
    // ## 两级查找机制
    // ### 第1步：哈希定位红黑树
    // ### 第2步：红黑树查找具体流
    // ## 为什么这样设计？
    // ### 1. **性能优势**
    // 这种设计在现代网络环境中表现**优秀**，既保证了查找效率，又控制了内存使用！
	root = &q->fq_root[hash_ptr(sk, q->fq_trees_log)];

    // ## 4. 垃圾回收检查
    // **触发条件：**
    // - 当前流数量超过哈希表容量的75%
    // - 非活跃流数量超过总流数的50%
    //
    // **回收策略：** 释放非活跃流，节省内存
	if (q->flows >= (2U << q->fq_trees_log) &&
	    q->inactive_flows > q->flows/2)
		fq_gc(q, root, sk);

	p = &root->rb_node;
	parent = NULL;
    // ## 5. 红黑树查找现有流
	while (*p) {
		parent = *p;

		f = rb_entry(parent, struct fq_flow, fq_node);
		if (f->sk == sk) {
            // 找到现有流
			/* socket might have been reallocated, so check
			 * if its sk_hash is the same.
			 * It not, we need to refill credit with
			 * initial quantum
			 */
			if (unlikely(skb->sk == sk &&
				     f->socket_hash != sk->sk_hash)) {
                // **Socket重新分配检测：**
                // - 问题：Socket可能被回收重新分配给新连接
                // - 检测：比较`f->socket_hash`和`sk->sk_hash`
                // - 处理：
                //   - 重置信用额度
                //   - 重新启用速率控制
                //   - 解除节流状态
                //   - 重置发送时间
				f->credit = q->initial_quantum;
				f->socket_hash = sk->sk_hash;
				if (q->rate_enable)
					smp_store_release(&sk->sk_pacing_status,
							  SK_PACING_FQ);
				if (fq_flow_is_throttled(f))
					fq_flow_unset_throttled(q, f);
				f->time_next_packet = 0ULL;
			}
			return f;
		}
		if (f->sk > sk)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}

    // ## 6. 现有流不存在，创建新流
	f = kmem_cache_zalloc(fq_flow_cachep, GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!f)) {
		q->stat_allocation_errors++;
		return &q->internal;
	}
	/* f->t_root is already zeroed after kmem_cache_zalloc() */

    // ### 6.1 新流初始化
	fq_flow_set_detached(f);
	f->sk = sk;
	if (skb->sk == sk) {
		f->socket_hash = sk->sk_hash;
		if (q->rate_enable)
			smp_store_release(&sk->sk_pacing_status,
					  SK_PACING_FQ);
	}
	f->credit = q->initial_quantum;

	rb_link_node(&f->fq_node, parent, p);
	rb_insert_color(&f->fq_node, root);

	q->flows++;
	q->inactive_flows++;
	return f;
}

static struct sk_buff *fq_peek(struct fq_flow *flow)
{
	struct sk_buff *skb = skb_rb_first(&flow->t_root);
	struct sk_buff *head = flow->head;

    // 若红黑树没有数据包，则返回队列的数据包
	if (!skb)
		return head;

    // 若队列没有数据包，则返回红黑树的数据包
	if (!head)
		return skb;

    // 若都有数据包，则返回时间较小的数据包
	if (fq_skb_cb(skb)->time_to_send < fq_skb_cb(head)->time_to_send)
		return skb;
	return head;
}

static void fq_erase_head(struct Qdisc *sch, struct fq_flow *flow,
			  struct sk_buff *skb)
{
	if (skb == flow->head) {
		flow->head = skb->next;
	} else {
		rb_erase(&skb->rbnode, &flow->t_root);
		skb->dev = qdisc_dev(sch);
	}
}

/* Remove one skb from flow queue.
 * This skb must be the return value of prior fq_peek().
 */
static void fq_dequeue_skb(struct Qdisc *sch, struct fq_flow *flow,
			   struct sk_buff *skb)
{
	fq_erase_head(sch, flow, skb);
	skb_mark_not_on_list(skb);
	flow->qlen--;
	qdisc_qstats_backlog_dec(sch, skb);
	sch->q.qlen--;
}

// 将数据包按发送时间排序插入到流队列中，采用**链表+红黑树**的混合数据结构。
static void flow_queue_add(struct fq_flow *flow, struct sk_buff *skb)
{
	struct rb_node **p, *parent;
	struct sk_buff *head, *aux;

    // ## 1. 获取流队列头部
	head = flow->head;
    // ## 2. 插入顺序正确，使用链表插入
    // 空队列 或 时间戳顺序正确 
    // 则直接队列尾部
	if (!head ||
	    fq_skb_cb(skb)->time_to_send >= fq_skb_cb(flow->tail)->time_to_send) {
		if (!head)
			flow->head = skb;
		else
			flow->tail->next = skb;
		flow->tail = skb;
		skb->next = NULL;
		return;
	}

    // 当时间戳顺序不正确时（即新数据包应该插在队列中间），使用红黑树：
	p = &flow->t_root.rb_node;
	parent = NULL;

    // ### 3.2 红黑树查找
    // **直到找到插入位置：**
    // - `*p`为NULL（叶子节点的空位置）
    // - `parent`为插入位置的父节点
	while (*p) {
		parent = *p;
		aux = rb_to_skb(parent);
		if (fq_skb_cb(skb)->time_to_send >= fq_skb_cb(aux)->time_to_send)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
    // ## 4. 红黑树插入操作
    // - `rb_link_node`：将新节点链接到红黑树中
    // - `rb_insert_color`：调整颜色以维护红黑树性质
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, &flow->t_root);
}

static bool fq_packet_beyond_horizon(const struct sk_buff *skb,
				    const struct fq_sched_data *q)
{
	return unlikely((s64)skb->tstamp > (s64)(q->ktime_cache + q->horizon));
}

static int fq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		      struct sk_buff **to_free)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct fq_flow *f;

    trace_printk("%s:%d:q->time_next_delayed_flow:[%llx]",
            __func__, __LINE__, q->time_next_delayed_flow);

	if (unlikely(sch->q.qlen >= sch->limit))
		return qdisc_drop(skb, sch, to_free);

    // ## 2. 数据包时间戳处理
    // skb->tstamp:
    // - **到达时间**：记录数据包到达网络栈的时间
    // - **离开时间**：记录数据包离开网络栈的时间
    // - **发送时间**：记录数据包的最早发送时间
	if (!skb->tstamp) {
        // **设置发送时间：**
        // - 如果数据包没有时间戳，使用当前时间
        // - `ktime_get_ns()`：获取当前纳秒级时间
        // - `q->ktime_cache`：缓存时间值，避免频繁调用
		fq_skb_cb(skb)->time_to_send = q->ktime_cache = ktime_get_ns();
	} else {
		/* Check if packet timestamp is too far in the future.
		 * Try first if our cached value, to avoid ktime_get_ns()
		 * cost in most cases.
		 */
        // 检查时间戳是否超出配置范围
        // - `horizon`：时间范围限制（默认10秒）
        // - **两种处理策略**：
        //   1. **丢弃策略**：`horizon_drop = 1`时丢弃
        //   2. **截断策略**：将时间戳调整到允许范围内
		if (fq_packet_beyond_horizon(skb, q)) {
			/* Refresh our cache and check another time */
			q->ktime_cache = ktime_get_ns();
			if (fq_packet_beyond_horizon(skb, q)) {
				if (q->horizon_drop) {
					q->stat_horizon_drops++;
					return qdisc_drop(skb, sch, to_free);
				}
				q->stat_horizon_caps++;
				skb->tstamp = q->ktime_cache + q->horizon;
			}
		}
		fq_skb_cb(skb)->time_to_send = skb->tstamp;
	}

    // ## 3. 流分类
    // **流分类功能：**
    // - 根据数据包特征（套接字、IP地址等）分配到对应流
    // - 如果流不存在则创建新流
    // - 实现流之间的公平隔离
	f = fq_classify(skb, q);
    // ## 4. 流队列长度限制
	if (unlikely(f->qlen >= q->flow_plimit && f != &q->internal)) {
		q->stat_flows_plimit++;
		return qdisc_drop(skb, sch, to_free);
	}

    // ## 5. 队列状态更新
	f->qlen++;
	qdisc_qstats_backlog_inc(sch, skb);
    // ### 5.2 非活跃流重新激活
    // **重新激活流：**
    // - `fq_flow_is_detached()`：检查流是否处于非活跃状态
    // - **重新加入调度**：
    //   - 将流添加到`new_flows`队列
    //   - 重新填充信用额度（credit）
    // - **信用额度管理**：
    //   - `flow_refill_delay`：重新填充延迟（默认40ms）
    //   - `quantum`：基本信用额度
	if (fq_flow_is_detached(f)) {
        // 新建立的流，会在这里添加flow(这些flow是已就绪的)
		fq_flow_add_tail(&q->new_flows, f); 
		if (time_after(jiffies, f->age + q->flow_refill_delay))
			f->credit = max_t(u32, f->credit, q->quantum);
		q->inactive_flows--;
	}

	/* Note: this overwrites f->age */
    // ## 6. 数据包排队
    // ### 6.1 添加到流队列
    // **排队逻辑：**
    // - 按发送时间排序插入数据包
    // - 覆盖流的`age`字段（正常情况下使用`time_after`检查）
	flow_queue_add(f, skb);

    // ### 6.2 内部流特殊处理
    // - 内部流处理高优先级或未分类数据包
	if (unlikely(f == &q->internal)) {
		q->stat_internal_packets++;
	}
	sch->q.qlen++;

	return NET_XMIT_SUCCESS;
}

static void fq_check_throttled(struct fq_sched_data *q, u64 now)
{
	unsigned long sample;
	struct rb_node *p;

    // **功能：** 检查是否需要立即处理节流流
    // - `q->time_next_delayed_flow`：下一个节流流允许发送的时间
    // - 如果当前时间早于该时间，说明还没有流可以解除节流状态
    // - 直接返回，避免不必要的处理
	if (q->time_next_delayed_flow > now)
		return;

	/* Update unthrottle latency EWMA.
	 * This is cheap and can help diagnosing timer/latency problems.
	 */
    // ## 2. 更新未节流延迟统计（EWMA）
	sample = (unsigned long)(now - q->time_next_delayed_flow);
	q->unthrottle_latency_ns -= q->unthrottle_latency_ns >> 3;
	q->unthrottle_latency_ns += sample >> 3;

    // ## 3. 重置下一次检查时间
	q->time_next_delayed_flow = ~0ULL;
    trace_printk("%s:%d:q->time_next_delayed_flow:[%llx]",
            __func__, __LINE__, q->time_next_delayed_flow);

    // ## 4. 处理节流流队列
    // - `rb_first(&q->delayed)`：获取时间最早的节流流
    // - 按照`time_next_packet`从小到大排序
	while ((p = rb_first(&q->delayed)) != NULL) {
		struct fq_flow *f = rb_entry(p, struct fq_flow, rate_node);

        // 1. **流尚未到期：**
        //    - 如果当前流的时间还没到，说明后续流也不会到
        //    - 设置下一次检查时间为该流的`time_next_packet`
        //    - 跳出循环，避免处理后续的流
		if (f->time_next_packet > now) {
			q->time_next_delayed_flow = f->time_next_packet;
            trace_printk("%s:%d:q->time_next_delayed_flow:[%llx]",
                    __func__, __LINE__, q->time_next_delayed_flow);

			break;
		}
        // 2. **流可以解除节流：**
        //    - 将流从节流状态中移除
        //    - 重新加入到调度循环中
        //    - 流可以继续发送数据包
		fq_flow_unset_throttled(q, f);
	}
}

// ### new_flows 队列
// **特征：**
// - 新建立的流（首次发送数据包）
// - 之前空闲后重新活跃的流
// - 在调度中**优先级更高**
//
// **作用：**
// - 确保新流能够快速获得服务
// - 避免新建立的连接（如TCP握手）被延迟
//
// ### old_flows 队列  
// **特征：**
// - 已经获得过服务的流
// - 在调度中**优先级较低**
// - 按照轮询方式处理
//
// **作用：**
// - 维护现有流的连续性
// - 确保稳定的数据传输
//
// **关键原则：** **新流优先，旧流轮询**
//
// ### 1. 防饥饿机制
// **问题：** 如果流一直有数据，它的信用额度会一直用不完
// **解决方案：** 将持续活跃的流移到`old_flows`，让新流有机会获得服务
static struct sk_buff *fq_dequeue(struct Qdisc *sch)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct fq_flow_head *head;
	struct sk_buff *skb;
	struct fq_flow *f;
	unsigned long rate;
	u32 plen;
	u64 now;

    trace_printk("%s:%d:q->time_next_delayed_flow:[%llx]",
            __func__, __LINE__, q->time_next_delayed_flow);
	if (!sch->q.qlen)
		return NULL;

    // 优先处理内部队列和高优先级数据包。
	skb = fq_peek(&q->internal);
	if (unlikely(skb)) {
		fq_dequeue_skb(sch, &q->internal, skb);
		goto out;
	}

    // 获得当前时间
	q->ktime_cache = now = ktime_get_ns();
    // 检查节流树，将不需要节流的流加入 old_flows
	fq_check_throttled(q, now);

    // ### 调度优先顺序
    // **关键原则：** **新流优先，旧流轮询**
    //
    // - 首先尝试处理新流（new_flows）
    // - 如果没有新流，则处理旧流（old_flows）
    // - 如果都没有，设置定时器并返回
begin:
	head = &q->new_flows;
	if (!head->first) {
		head = &q->old_flows;
		if (!head->first) {
			if (q->time_next_delayed_flow != ~0ULL)
				qdisc_watchdog_schedule_range_ns(&q->watchdog,
							q->time_next_delayed_flow,
							q->timer_slack);
			return NULL;
		}
	}
	f = head->first;

    // 每个流都有信用额度（credit），当信用额度不足时：
    // - 重新填充信用额度
    // - 将处理过的流移到旧流队列
    // - 重新开始调度
	if (f->credit <= 0) {
		f->credit += q->quantum;
		head->first = f->next;
		fq_flow_add_tail(&q->old_flows, f);
		goto begin;
	}

    // - 获取流中的第一个数据包
    // - 计算下一个可发送的时间
    // - 如果时间未到，则将流标记为节流状态
    // - 设置ECN（显式拥塞通知）标记
    
    // 从当前流`f`中获取第一个待发送的数据包（但不实际出队）。
	skb = fq_peek(f);
	if (skb) {
        // ## 2. 计算下一个数据包的发送时间
        // - `fq_skb_cb(skb)->time_to_send`：数据包本身的发送时间戳
        // - `f->time_next_packet`：流级别的下一个发送时间
        //
        // 取最大值确保：
        // - 数据包不会早于其时间戳发送
        // - 不会违反流的速率限制
		u64 time_next_packet = max_t(u64, fq_skb_cb(skb)->time_to_send,
					     f->time_next_packet);

        // ## 3. 时序检查和流量节流
        // **如果当前时间早于允许的发送时间：**
        // 设置这个流的发送时间，并重新加入节流队列(delayed树)
		if (now < time_next_packet) {
			head->first = f->next;
			f->time_next_packet = time_next_packet;
			fq_flow_set_throttled(q, f);
			goto begin;
		}
        // ## 4. 内存预取优化
        // 预取数据包的结尾部分到CPU缓存，提高后续访问性能。
		prefetch(&skb->end);
        // ## 5. ECN（显式拥塞通知）标记
        // **如果数据包延迟超过阈值：**
        // - 当前时间 - 计划发送时间 - 拥塞阈值 > 0
        // - 说明网络可能存在拥塞
        // - 设置ECN的CE（拥塞体验）标记
        // - 统计计数
        //
        // 这实现了**拥塞感知**，向接收方报告网络拥塞状况。
		if ((s64)(now - time_next_packet - q->ce_threshold) > 0) {
			INET_ECN_set_ce(skb);
			q->stat_ce_mark++;
		}
        // ## 6. 实际出队数据包
        // 真正从队列中移除数据包，并更新统计信息。
		fq_dequeue_skb(sch, f, skb);
	} else {
        // ## 7. 空流处理分支
        // - 从队列中移除该流
        //
        // - **防止饥饿机制**：
        //   - 如果该流来自新流队列且有旧流，将其移到旧流队列
        //   - 否则标记为非活跃状态
        //
        // 这确保所有流都有机会被处理，防止某些流长期得不到服务。
		head->first = f->next;
		/* force a pass through old_flows to prevent starvation */
        // **问题：** 如果流一直有数据，它的信用额度会一直用不完
        // **解决方案：** 将持续活跃的流移到`old_flows`，让新流有机会获得服务
		if ((head == &q->new_flows) && q->old_flows.first) {
			fq_flow_add_tail(&q->old_flows, f);
		} else {
			fq_flow_set_detached(f);
			q->inactive_flows++;
		}
		goto begin;
	}
    // ## 8. 信用额度计算
    // - 获取数据包长度
    // - 从流的信用额度中减去这个长度
    //
    // 信用额度控制每个流可以发送的字节数，防止单个流占用过多带宽。
	plen = qdisc_pkt_len(skb);
	f->credit -= plen;

    // ## 9. 速率限制开关
    // 如果速率限制被禁用，直接跳过后续的速率控制逻辑。
	if (!q->rate_enable)
		goto out;

    // ## 10. 获取速率限制值
    // 获取流的最大速率限制。
	rate = q->flow_max_rate;

	/* If EDT time was provided for this skb, we need to
	 * update f->time_next_packet only if this qdisc enforces
	 * a flow max rate.
	 */
    // ## 11. 套接字速率考虑
    // **如果没有外部时间戳：**
    // - 取套接字速率和流速率的最小值（更严格的限制）
    // - **低速率处理**：
    //   - 如果速率低于阈值，将信用额度设为0，防止过度节流
    // - **数据包大小调整**：
    //   - 确保数据包大小不小于quantum，保证公平性
    //   - 如果还有信用额度，直接发送（避免不必要的延迟）
	if (!skb->tstamp) {
		if (skb->sk)
			rate = min(skb->sk->sk_pacing_rate, rate);

		if (rate <= q->low_rate_threshold) {
			f->credit = 0;
		} else {
			plen = max(plen, q->quantum);
			if (f->credit > 0)
				goto out;
		}
	}
    // 根据流量速率限制计算下一个数据包的发送时间。
	if (rate != ~0UL) {
        // 计算以 rate 为发送速率时，
        // 发送 qlen 长度的数据需要多长时间len
        // len 单位为纳秒
        //
        // **计算发送延迟时间：**
        // - `plen`：数据包长度（字节）
        // - `NSEC_PER_SEC`：每秒的纳秒数（10^9）
        // - `len = plen * NSEC_PER_SEC`：数据包的发送时间（以纳秒为单位）
        // - `len = len / rate`：除以速率限制得到延迟时间
        //
        // **例如：**
        // - 数据包1000字节，速率限制1000字节/秒
        // - `len = 1000 * 10^9 / 1000 = 10^9`纳秒 = 1秒
		u64 len = (u64)plen * NSEC_PER_SEC;

		if (likely(rate))
			len = div64_ul(len, rate);
		/* Since socket rate can change later,
		 * clamp the delay to 1 second.
		 * Really, providers of too big packets should be fixed !
		 */
        // ## 2. 延迟时间限制（防止过大延迟）
        // 如果发送时间超过1s，则限制最大发送时间为1s
        // **为什么要限制延迟？**
        // - 速率限制可能非常严格（比如极低速率）
        // - 这会导致过大的延迟时间
        // - 限制到最大1秒，避免极端情况
		if (unlikely(len > NSEC_PER_SEC)) {
			len = NSEC_PER_SEC;
			q->stat_pkts_too_long++;
		}
		/* Account for schedule/timers drifts.
		 * f->time_next_packet was set when prior packet was sent,
		 * and current time (@now) can be too late by tens of us.
		 */
        // ## 3. 时钟漂移补偿
        // **补偿原理：**
        // - `f->time_next_packet`：上次计算的下一次发送时间
        // - `now - f->time_next_packet`：当前时间与计划时间的差值（时钟漂移）
        // - `len/2`：最多补偿一半的延迟时间
        //
        // **补偿目的：**
        // - 系统可能有定时器精度问题
        // - 内核调度延迟
        // - CPU负载导致的处理延迟
        //
        // **补偿效果：**
        // - 如果当前时间已经超过计划发送时间，说明系统有延迟
        // - 适当减少下一次延迟，避免累积延迟
        // - 但不补偿全部时间（只补偿一半），保持一定的保守性
		if (f->time_next_packet)
			len -= min(len/2, now - f->time_next_packet);

        // ## 4. 设置下一次发送时间
        // **设置下次允许发送的时间：**
        // - 当前时间 + 计算的延迟时间
        // - 这个时间会被下一次调度检查使用
        // - 确保严格按照速率限制发送
		f->time_next_packet = now + len;
	}
out:
    // ## 5. 统计更新和返回
    // **统计更新：**
    // - `qdisc_bstats_update`：更新基本的队列统计信息
    // - 记录发送的字节数和数据包数
	qdisc_bstats_update(sch, skb);
	return skb;
}

static void fq_flow_purge(struct fq_flow *flow)
{
	struct rb_node *p = rb_first(&flow->t_root);

	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);
		rb_erase(&skb->rbnode, &flow->t_root);
		rtnl_kfree_skbs(skb, skb);
	}
	rtnl_kfree_skbs(flow->head, flow->tail);
	flow->head = NULL;
	flow->qlen = 0;
}

// 释放所有数据包，清除所有流，重置调度器状态。
static void fq_reset(struct Qdisc *sch)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct rb_root *root;
	struct rb_node *p;
	struct fq_flow *f;
	unsigned int idx;

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

    // ## 2. 清空内部流
    // **清空内部队列：**
    // - 处理高优先级控制数据包队列
    // - `internal`流专门用于控制流量
	fq_flow_purge(&q->internal);

	if (!q->fq_root)
		return;

	for (idx = 0; idx < (1U << q->fq_trees_log); idx++) {
		root = &q->fq_root[idx];
        // ## 4. 处理每个哈希桶的流
		while ((p = rb_first(root)) != NULL) {
			f = rb_entry(p, struct fq_flow, fq_node);
			rb_erase(p, root);

			fq_flow_purge(f);

			kmem_cache_free(fq_flow_cachep, f);
		}
	}
	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;
	q->delayed		= RB_ROOT;
	q->flows		= 0;
	q->inactive_flows	= 0;
	q->throttled_flows	= 0;
}

static void fq_rehash(struct fq_sched_data *q,
		      struct rb_root *old_array, u32 old_log,
		      struct rb_root *new_array, u32 new_log)
{
	struct rb_node *op, **np, *parent;
	struct rb_root *oroot, *nroot;
	struct fq_flow *of, *nf;
	int fcnt = 0;
	u32 idx;

	for (idx = 0; idx < (1U << old_log); idx++) {
		oroot = &old_array[idx];
		while ((op = rb_first(oroot)) != NULL) {
			rb_erase(op, oroot);
			of = rb_entry(op, struct fq_flow, fq_node);
			if (fq_gc_candidate(of)) {
				fcnt++;
				kmem_cache_free(fq_flow_cachep, of);
				continue;
			}
			nroot = &new_array[hash_ptr(of->sk, new_log)];

			np = &nroot->rb_node;
			parent = NULL;
			while (*np) {
				parent = *np;

				nf = rb_entry(parent, struct fq_flow, fq_node);
				BUG_ON(nf->sk == of->sk);

				if (nf->sk > of->sk)
					np = &parent->rb_right;
				else
					np = &parent->rb_left;
			}

			rb_link_node(&of->fq_node, parent, np);
			rb_insert_color(&of->fq_node, nroot);
		}
	}
	q->flows -= fcnt;
	q->inactive_flows -= fcnt;
	q->stat_gc_flows += fcnt;
}

static void fq_free(void *addr)
{
	kvfree(addr);
}

static int fq_resize(struct Qdisc *sch, u32 log)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct rb_root *array;
	void *old_fq_root;
	u32 idx;

	if (q->fq_root && log == q->fq_trees_log)
		return 0;

	/* If XPS was setup, we can allocate memory on right NUMA node */
	array = kvmalloc_node(sizeof(struct rb_root) << log, GFP_KERNEL | __GFP_RETRY_MAYFAIL,
			      netdev_queue_numa_node_read(sch->dev_queue));
	if (!array)
		return -ENOMEM;

	for (idx = 0; idx < (1U << log); idx++)
		array[idx] = RB_ROOT;

	sch_tree_lock(sch);

	old_fq_root = q->fq_root;
	if (old_fq_root)
		fq_rehash(q, old_fq_root, q->fq_trees_log, array, log);

	q->fq_root = array;
	q->fq_trees_log = log;

	sch_tree_unlock(sch);

	fq_free(old_fq_root);

	return 0;
}

static const struct nla_policy fq_policy[TCA_FQ_MAX + 1] = {
	[TCA_FQ_UNSPEC]			= { .strict_start_type = TCA_FQ_TIMER_SLACK },

	[TCA_FQ_PLIMIT]			= { .type = NLA_U32 },
	[TCA_FQ_FLOW_PLIMIT]		= { .type = NLA_U32 },
	[TCA_FQ_QUANTUM]		= { .type = NLA_U32 },
	[TCA_FQ_INITIAL_QUANTUM]	= { .type = NLA_U32 },
	[TCA_FQ_RATE_ENABLE]		= { .type = NLA_U32 },
	[TCA_FQ_FLOW_DEFAULT_RATE]	= { .type = NLA_U32 },
	[TCA_FQ_FLOW_MAX_RATE]		= { .type = NLA_U32 },
	[TCA_FQ_BUCKETS_LOG]		= { .type = NLA_U32 },
	[TCA_FQ_FLOW_REFILL_DELAY]	= { .type = NLA_U32 },
	[TCA_FQ_ORPHAN_MASK]		= { .type = NLA_U32 },
	[TCA_FQ_LOW_RATE_THRESHOLD]	= { .type = NLA_U32 },
	[TCA_FQ_CE_THRESHOLD]		= { .type = NLA_U32 },
	[TCA_FQ_TIMER_SLACK]		= { .type = NLA_U32 },
	[TCA_FQ_HORIZON]		= { .type = NLA_U32 },
	[TCA_FQ_HORIZON_DROP]		= { .type = NLA_U8 },
};

static int fq_change(struct Qdisc *sch, struct nlattr *opt,
		     struct netlink_ext_ack *extack)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_FQ_MAX + 1];
	int err, drop_count = 0;
	unsigned drop_len = 0;
	u32 fq_log;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_FQ_MAX, opt, fq_policy,
					  NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	fq_log = q->fq_trees_log;

	if (tb[TCA_FQ_BUCKETS_LOG]) {
		u32 nval = nla_get_u32(tb[TCA_FQ_BUCKETS_LOG]);

		if (nval >= 1 && nval <= ilog2(256*1024))
			fq_log = nval;
		else
			err = -EINVAL;
	}
	if (tb[TCA_FQ_PLIMIT])
		sch->limit = nla_get_u32(tb[TCA_FQ_PLIMIT]);

	if (tb[TCA_FQ_FLOW_PLIMIT])
		q->flow_plimit = nla_get_u32(tb[TCA_FQ_FLOW_PLIMIT]);

	if (tb[TCA_FQ_QUANTUM]) {
		u32 quantum = nla_get_u32(tb[TCA_FQ_QUANTUM]);

		if (quantum > 0 && quantum <= (1 << 20)) {
			q->quantum = quantum;
		} else {
			NL_SET_ERR_MSG_MOD(extack, "invalid quantum");
			err = -EINVAL;
		}
	}

	if (tb[TCA_FQ_INITIAL_QUANTUM])
		q->initial_quantum = nla_get_u32(tb[TCA_FQ_INITIAL_QUANTUM]);

	if (tb[TCA_FQ_FLOW_DEFAULT_RATE])
		pr_warn_ratelimited("sch_fq: defrate %u ignored.\n",
				    nla_get_u32(tb[TCA_FQ_FLOW_DEFAULT_RATE]));

	if (tb[TCA_FQ_FLOW_MAX_RATE]) {
		u32 rate = nla_get_u32(tb[TCA_FQ_FLOW_MAX_RATE]);

		q->flow_max_rate = (rate == ~0U) ? ~0UL : rate;
	}
	if (tb[TCA_FQ_LOW_RATE_THRESHOLD])
		q->low_rate_threshold =
			nla_get_u32(tb[TCA_FQ_LOW_RATE_THRESHOLD]);

	if (tb[TCA_FQ_RATE_ENABLE]) {
		u32 enable = nla_get_u32(tb[TCA_FQ_RATE_ENABLE]);

		if (enable <= 1)
			q->rate_enable = enable;
		else
			err = -EINVAL;
	}

	if (tb[TCA_FQ_FLOW_REFILL_DELAY]) {
		u32 usecs_delay = nla_get_u32(tb[TCA_FQ_FLOW_REFILL_DELAY]) ;

		q->flow_refill_delay = usecs_to_jiffies(usecs_delay);
	}

	if (tb[TCA_FQ_ORPHAN_MASK])
		q->orphan_mask = nla_get_u32(tb[TCA_FQ_ORPHAN_MASK]);

	if (tb[TCA_FQ_CE_THRESHOLD])
		q->ce_threshold = (u64)NSEC_PER_USEC *
				  nla_get_u32(tb[TCA_FQ_CE_THRESHOLD]);

	if (tb[TCA_FQ_TIMER_SLACK])
		q->timer_slack = nla_get_u32(tb[TCA_FQ_TIMER_SLACK]);

	if (tb[TCA_FQ_HORIZON])
		q->horizon = (u64)NSEC_PER_USEC *
				  nla_get_u32(tb[TCA_FQ_HORIZON]);

	if (tb[TCA_FQ_HORIZON_DROP])
		q->horizon_drop = nla_get_u8(tb[TCA_FQ_HORIZON_DROP]);

	if (!err) {

		sch_tree_unlock(sch);
		err = fq_resize(sch, fq_log);
		sch_tree_lock(sch);
	}
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = fq_dequeue(sch);

		if (!skb)
			break;
		drop_len += qdisc_pkt_len(skb);
		rtnl_kfree_skbs(skb, skb);
		drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, drop_count, drop_len);

	sch_tree_unlock(sch);
	return err;
}

static void fq_destroy(struct Qdisc *sch)
{
	struct fq_sched_data *q = qdisc_priv(sch);

	fq_reset(sch);
	fq_free(q->fq_root);
	qdisc_watchdog_cancel(&q->watchdog);
}

static int fq_init(struct Qdisc *sch, struct nlattr *opt,
		   struct netlink_ext_ack *extack)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	int err;

	sch->limit		= 10000;
	q->flow_plimit		= 100;
	q->quantum		= 2 * psched_mtu(qdisc_dev(sch));
	q->initial_quantum	= 10 * psched_mtu(qdisc_dev(sch));
	q->flow_refill_delay	= msecs_to_jiffies(40);
	q->flow_max_rate	= ~0UL;
	q->time_next_delayed_flow = ~0ULL;
	q->rate_enable		= 1;
	q->new_flows.first	= NULL;
	q->old_flows.first	= NULL;
	q->delayed		= RB_ROOT;
	q->fq_root		= NULL;
	q->fq_trees_log		= ilog2(1024);
	q->orphan_mask		= 1024 - 1;
	q->low_rate_threshold	= 550000 / 8;

	q->timer_slack = 10 * NSEC_PER_USEC; /* 10 usec of hrtimer slack */

	q->horizon = 10ULL * NSEC_PER_SEC; /* 10 seconds */
	q->horizon_drop = 1; /* by default, drop packets beyond horizon */

	/* Default ce_threshold of 4294 seconds */
	q->ce_threshold		= (u64)NSEC_PER_USEC * ~0U;

	qdisc_watchdog_init_clockid(&q->watchdog, sch, CLOCK_MONOTONIC);

	if (opt)
		err = fq_change(sch, opt, extack);
	else
		err = fq_resize(sch, q->fq_trees_log);

	return err;
}

static int fq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	u64 ce_threshold = q->ce_threshold;
	u64 horizon = q->horizon;
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	/* TCA_FQ_FLOW_DEFAULT_RATE is not used anymore */

	do_div(ce_threshold, NSEC_PER_USEC);
	do_div(horizon, NSEC_PER_USEC);

	if (nla_put_u32(skb, TCA_FQ_PLIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_FQ_FLOW_PLIMIT, q->flow_plimit) ||
	    nla_put_u32(skb, TCA_FQ_QUANTUM, q->quantum) ||
	    nla_put_u32(skb, TCA_FQ_INITIAL_QUANTUM, q->initial_quantum) ||
	    nla_put_u32(skb, TCA_FQ_RATE_ENABLE, q->rate_enable) ||
	    nla_put_u32(skb, TCA_FQ_FLOW_MAX_RATE,
			min_t(unsigned long, q->flow_max_rate, ~0U)) ||
	    nla_put_u32(skb, TCA_FQ_FLOW_REFILL_DELAY,
			jiffies_to_usecs(q->flow_refill_delay)) ||
	    nla_put_u32(skb, TCA_FQ_ORPHAN_MASK, q->orphan_mask) ||
	    nla_put_u32(skb, TCA_FQ_LOW_RATE_THRESHOLD,
			q->low_rate_threshold) ||
	    nla_put_u32(skb, TCA_FQ_CE_THRESHOLD, (u32)ce_threshold) ||
	    nla_put_u32(skb, TCA_FQ_BUCKETS_LOG, q->fq_trees_log) ||
	    nla_put_u32(skb, TCA_FQ_TIMER_SLACK, q->timer_slack) ||
	    nla_put_u32(skb, TCA_FQ_HORIZON, (u32)horizon) ||
	    nla_put_u8(skb, TCA_FQ_HORIZON_DROP, q->horizon_drop))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int fq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct fq_sched_data *q = qdisc_priv(sch);
	struct tc_fq_qd_stats st;

	sch_tree_lock(sch);

	st.gc_flows		  = q->stat_gc_flows;
	st.highprio_packets	  = q->stat_internal_packets;
	st.tcp_retrans		  = 0;
	st.throttled		  = q->stat_throttled;
	st.flows_plimit		  = q->stat_flows_plimit;
	st.pkts_too_long	  = q->stat_pkts_too_long;
	st.allocation_errors	  = q->stat_allocation_errors;
	st.time_next_delayed_flow = q->time_next_delayed_flow + q->timer_slack -
				    ktime_get_ns();
	st.flows		  = q->flows;
	st.inactive_flows	  = q->inactive_flows;
	st.throttled_flows	  = q->throttled_flows;
	st.unthrottle_latency_ns  = min_t(unsigned long,
					  q->unthrottle_latency_ns, ~0U);
	st.ce_mark		  = q->stat_ce_mark;
	st.horizon_drops	  = q->stat_horizon_drops;
	st.horizon_caps		  = q->stat_horizon_caps;
	sch_tree_unlock(sch);

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct Qdisc_ops fq_qdisc_ops __read_mostly = {
	.id		=	"fq",
	.priv_size	=	sizeof(struct fq_sched_data),

	.enqueue	=	fq_enqueue,
	.dequeue	=	fq_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	fq_init,
	.reset		=	fq_reset,
	.destroy	=	fq_destroy,
	.change		=	fq_change,
	.dump		=	fq_dump,
	.dump_stats	=	fq_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init fq_module_init(void)
{
	int ret;

	fq_flow_cachep = kmem_cache_create("fq_flow_cache",
					   sizeof(struct fq_flow),
					   0, 0, NULL);
	if (!fq_flow_cachep)
		return -ENOMEM;

	ret = register_qdisc(&fq_qdisc_ops);
	if (ret)
		kmem_cache_destroy(fq_flow_cachep);
	return ret;
}

static void __exit fq_module_exit(void)
{
	unregister_qdisc(&fq_qdisc_ops);
	kmem_cache_destroy(fq_flow_cachep);
}

module_init(fq_module_init)
module_exit(fq_module_exit)
MODULE_AUTHOR("Eric Dumazet");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fair Queue Packet Scheduler");
