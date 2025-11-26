# trace-cmd record -p function_graph -l tcp_ack -l tcp_sendmsg_locked

set -ex

mount -t tracefs nodev /sys/kernel/tracing/
echo 40960 > /sys/kernel/tracing/buffer_size_kb
echo 0 > /sys/kernel/tracing/tracing_on
echo function_graph > /sys/kernel/tracing/current_tracer
# echo 'bbr_main' >> /sys/kernel/tracing/set_ftrace_filter
# echo 'bbr_check_full_bw_reached' >> /sys/kernel/tracing/set_ftrace_filter
# echo 'bbr_update_bw' >> /sys/kernel/tracing/set_ftrace_filter
# echo 'bbr_set_pacing_rate' >> /sys/kernel/tracing/set_ftrace_filter
# echo 'bbr_init_pacing_rate_from_rtt' >> /sys/kernel/tracing/set_ftrace_filter
echo 'tcp_rate_skb_sent'  >> /sys/kernel/tracing/set_ftrace_filter
echo 'tcp_rate_gen' >> /sys/kernel/tracing/set_ftrace_filter
echo 'tcp_rate_check_app_limited' >> /sys/kernel/tracing/set_ftrace_filter
echo 1 > /sys/kernel/tracing/tracing_on

