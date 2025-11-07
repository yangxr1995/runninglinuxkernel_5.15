// SPDX-License-Identifier: GPL-2.0-only
#include <net/tcp.h>

/* The bandwidth estimator estimates the rate at which the network
 * can currently deliver outbound data packets for this flow. At a high
 * level, it operates by taking a delivery rate sample for each ACK.
 *
 * A rate sample records the rate at which the network delivered packets
 * for this flow, calculated over the time interval between the transmission
 * of a data packet and the acknowledgment of that packet.
 *
 * Specifically, over the interval between each transmit and corresponding ACK,
 * the estimator generates a delivery rate sample. Typically it uses the rate
 * at which packets were acknowledged. However, the approach of using only the
 * acknowledgment rate faces a challenge under the prevalent ACK decimation or
 * compression: packets can temporarily appear to be delivered much quicker
 * than the bottleneck rate. Since it is physically impossible to do that in a
 * sustained fashion, when the estimator notices that the ACK rate is faster
 * than the transmit rate, it uses the latter:
 *
 *    send_rate = #pkts_delivered/(last_snd_time - first_snd_time)
 *    ack_rate  = #pkts_delivered/(last_ack_time - first_ack_time)
 *    bw = min(send_rate, ack_rate)
 *
 * Notice the estimator essentially estimates the goodput, not always the
 * network bottleneck link rate when the sending or receiving is limited by
 * other factors like applications or receiver window limits.  The estimator
 * deliberately avoids using the inter-packet spacing approach because that
 * approach requires a large number of samples and sophisticated filtering.
 *
 * TCP flows can often be application-limited in request/response workloads.
 * The estimator marks a bandwidth sample as application-limited if there
 * was some moment during the sampled window of packets when there was no data
 * ready to send in the write queue.
 */

/* Snapshot the current delivery information in the skb, to generate
 * a rate sample later when the skb is (s)acked in tcp_rate_skb_delivered().
 */
// 在发送数据包时记录相关信息，以便后续计算网络传输速率。
void tcp_rate_skb_sent(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	 /* In general we need to start delivery rate samples from the
	  * time we received the most recent ACK, to ensure we include
	  * the full time the network needs to deliver all in-flight
	  * packets. If there are no packets in flight yet, then we
	  * know that any ACKs after now indicate that the network was
	  * able to deliver those packets completely in the sampling
	  * interval between now and the next ACK.
	  *
	  * Note that we use packets_out instead of tcp_packets_in_flight(tp)
	  * because the latter is a guess based on RTO and loss-marking
	  * heuristics. We don't want spurious RTOs or loss markings to cause
	  * a spuriously small time interval, causing a spuriously high
	  * bandwidth estimate.
	  */
    static int cycle_id = 0;
	if (!tp->packets_out) { // 当发送链路中没有在途数据包时, 表示这是一个新的发送周期的开始.
		u64 tstamp_us = tcp_skb_timestamp_us(skb); // 获得数据包的发送时间戳

		tp->first_tx_mstamp  = tstamp_us; // 以第一个数据包的发送时间做链路snd侧基准时间
		tp->delivered_mstamp = tstamp_us; // 以第一个数据包的发送时间做链路ack侧基准时间
        trace_printk("%d:%s:snd_phase_id[%d]start at first_tx_mstamp[%llu] tp->delivered_mstamp[%llu]\n", 
                current->pid, __FUNCTION__, ++cycle_id, tstamp_us, tstamp_us);
	}

    // 记录快照
	TCP_SKB_CB(skb)->tx.first_tx_mstamp	= tp->first_tx_mstamp; // snd侧基准时间
	TCP_SKB_CB(skb)->tx.delivered_mstamp	= tp->delivered_mstamp; // ack侧基准时间
	TCP_SKB_CB(skb)->tx.delivered		= tp->delivered; // 基准交付量
	TCP_SKB_CB(skb)->tx.is_app_limited	= tp->app_limited ? 1 : 0;
}

/* When an skb is sacked or acked, we fill in the rate sample with the (prior)
 * delivery information when the skb was last transmitted.
 *
 * If an ACK (s)acks multiple skbs (e.g., stretched-acks), this function is
 * called multiple times. We favor the information from the most recently
 * sent skb, i.e., the skb with the highest prior_delivered count.
 */
void tcp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb,
			    struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *scb = TCP_SKB_CB(skb); // 获得skb的快照

	if (!scb->tx.delivered_mstamp) // 过滤掉已经参与过样本计算的skb
		return;

    // 找到最大的交付基准
	if (!rs->prior_delivered || 
	    after(scb->tx.delivered, rs->prior_delivered)) {

        // 对交付基准和基准时间进行采样
		rs->prior_delivered  = scb->tx.delivered;
		rs->prior_mstamp     = scb->tx.delivered_mstamp;
		rs->is_app_limited   = scb->tx.is_app_limited;
		rs->is_retrans	     = scb->sacked & TCPCB_RETRANS;

		/* Record send time of most recently ACKed packet: */
		tp->first_tx_mstamp  = tcp_skb_timestamp_us(skb); // 以skb的发包时间作为新的snd阶段基准时间
		/* Find the duration of the "send phase" of this window: */
		rs->interval_us = tcp_stamp_us_delta(tp->first_tx_mstamp,  // 计算本周期发送阶段的间隔时间
						     scb->tx.first_tx_mstamp); // 以本skb的发送时间作为本周起的结束时间
                                                       // 间隔时间 = 结束时间 - 基准时间
	}
	/* Mark off the skb delivered once it's sacked to avoid being
	 * used again when it's cumulatively acked. For acked packets
	 * we don't need to reset since it'll be freed soon.
	 */
    // 一旦skb被标记为已确认（sacked），就将其标记为已交付，以避免在累积确认时再次使用。
    // 对于已确认的数据包，我们不需要重置，因为它们很快就会被释放。
	if (scb->sacked & TCPCB_SACKED_ACKED)
		scb->tx.delivered_mstamp = 0;
}

/* Update the connection delivery information and generate a rate sample. */
// 生成本周起的速率样本, 一个周期指(上次ACK, 本次ACK]
// delivered : 本周期内成功发包数量
// lost : 本周起内丢包数
// is_sack_renreg : 是否有SACK撤销
// sack_state.rate : 返回采样
// // tcp_ack
void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
		  bool is_sack_reneg, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 snd_us, ack_us;

	/* Clear app limited if bubble is acked and gone. */
    // 如果有链路气泡，需要等待导致气泡的报文(或之后的报文)的ACK抵达，链路中的气泡才排空
	if (tp->app_limited && after(tp->delivered, tp->app_limited))
		tp->app_limited = 0;

	/* TODO: there are multiple places throughout tcp_ack() to get
	 * current time. Refactor the code using a new "tcp_acktag_state"
	 * to carry current time, flags, stats like "tcp_sacktag_state".
	 */
    // 若ack有确认数据包，则以ack接受时间为下个ack阶段的基准时间
	if (delivered)
		tp->delivered_mstamp = tp->tcp_mstamp;

	rs->acked_sacked = delivered;	/* freshly ACKed or SACKed */
	rs->losses = lost;		/* freshly marked lost */
	/* Return an invalid sample if no timing information is available or
	 * in recovery from loss with SACK reneging. Rate samples taken during
	 * a SACK reneging event may overestimate bw by including packets that
	 * were SACKed before the reneg.
	 */
    // 若没有ack阶段基准时间或本次发送了SACK撤回，则无法产生样本
	if (!rs->prior_mstamp || is_sack_reneg) {
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}
    // 计算交付数
	rs->delivered   = tp->delivered - rs->prior_delivered;

	/* Model sending data and receiving ACKs as separate pipeline phases
	 * for a window. Usually the ACK phase is longer, but with ACK
	 * compression the send phase can be longer. To be safe we use the
	 * longer phase.
	 */
	snd_us = rs->interval_us; // snd阶段的时间:数据包发送的持续时间 /* send phase */
	ack_us = tcp_stamp_us_delta(tp->tcp_mstamp,
				    rs->prior_mstamp); // ack阶段的时间:最近的接受ack时间 - 上次的接受ack的时间
	rs->interval_us = max(snd_us, ack_us); // 以最大值做样本时间

	/* Record both segment send and ack receive intervals */
	rs->snd_interval_us = snd_us;
	rs->rcv_interval_us = ack_us;

	/* Normally we expect interval_us >= min-rtt.
	 * Note that rate may still be over-estimated when a spuriously
	 * retransmistted skb was first (s)acked because "interval_us"
	 * is under-estimated (up to an RTT). However continuously
	 * measuring the delivery rate during loss recovery is crucial
	 * for connections suffer heavy or prolonged losses.
	 */
    // 过滤错误样本
    // 错误重传后可能立即收到上个包的ACK，导致 interval_us < 链路最小RTT
	if (unlikely(rs->interval_us < tcp_min_rtt(tp))) {
		if (!rs->is_retrans)
			pr_debug("tcp rate: %ld %d %u %u %u\n",
				 rs->interval_us, rs->delivered,
				 inet_csk(sk)->icsk_ca_state,
				 tp->rx_opt.sack_ok, tcp_min_rtt(tp));
		rs->interval_us = -1;
		return;
	}

	/* Record the last non-app-limited or the highest app-limited bw */
    // 更新链路速率
    // 样本应用受限时，只更新速率增加的情况: 样本速率(样本交付数/样本时间) >= 链路速率(链路交付数/链路带宽) 
    // 样本应用未受限，速率增加减少都被更新
	if (!rs->is_app_limited ||
	    ((u64)rs->delivered * tp->rate_interval_us >=
	     (u64)tp->rate_delivered * rs->interval_us)) {
		tp->rate_delivered = rs->delivered;
		tp->rate_interval_us = rs->interval_us;
		tp->rate_app_limited = rs->is_app_limited;
	}
}

/* If a gap is detected between sends, mark the socket application-limited. */
void tcp_rate_check_app_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

    // 当4个受限条件都满足，则标记应用受限
	if (// 1. 发送缓冲区中剩余数据不足一个数据包
	    tp->write_seq - tp->snd_nxt < tp->mss_cache &&
        // 2. qdisc 或 NIC tx队列中没有待发送数据包
	    sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) &&
        // 3. 飞行中的数据包数量小于拥塞窗口大小
	    tcp_packets_in_flight(tp) < tp->snd_cwnd &&
        // 4. 所有丢失数据包都已被重传
	    tp->lost_out <= tp->retrans_out)
        // 如果当前有已交付或在途的数据包，使用该数量作为app_limited值
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
}
EXPORT_SYMBOL_GPL(tcp_rate_check_app_limited);
