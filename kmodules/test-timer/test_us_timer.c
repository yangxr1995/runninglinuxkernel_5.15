#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#define NSEC_PER_SEC 1000000000L
#define USEC_PER_SEC 1000000L
#define TEST_ITERATIONS 1000

// 获取微秒级时间戳
static inline long long get_us_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
}

// 获取纳秒级时间戳
static inline long long get_ns_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

// 测试gettimeofday的精度
void test_gettimeofday_precision(void) {
    long long prev_time = get_us_time();
    long long min_diff = LLONG_MAX;
    long long max_diff = 0;
    long long diff_sum = 0;
    int zero_diff_count = 0;

    printf("=== 测试 gettimeofday() 微秒级精度 ===\n");
    printf("进行 %d 次连续调用...\n", TEST_ITERATIONS);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        long long current_time = get_us_time();
        long long diff = current_time - prev_time;

        if (diff < min_diff) min_diff = diff;
        if (diff > max_diff) max_diff = diff;
        if (diff == 0) zero_diff_count++;
        diff_sum += diff;
        prev_time = current_time;
    }

    double avg_diff = (double)diff_sum / TEST_ITERATIONS;

    printf("最小时间间隔: %lld 微秒\n", min_diff);
    printf("最大时间间隔: %lld 微秒\n", max_diff);
    printf("平均时间间隔: %.2f 微秒\n", avg_diff);
    printf("零间隔次数: %d (%.2f%%)\n", zero_diff_count, (double)zero_diff_count / TEST_ITERATIONS * 100);

    if (min_diff == 0 && zero_diff_count > TEST_ITERATIONS * 0.5) {
        printf("⚠️  警告: 超过50%%的调用返回相同时间戳，精度可能不足1微秒\n");
    } else if (min_diff >= 1) {
        printf("✓ 精度至少达到 1 微秒\n");
    }
    printf("\n");
}

// 测试clock_gettime的精度
void test_clock_gettime_precision(void) {
    struct timespec prev_ts;
    struct timespec current_ts;
    clock_gettime(CLOCK_MONOTONIC, &prev_ts);

    long long min_diff = LLONG_MAX;
    long long max_diff = 0;
    long long diff_sum = 0;
    int zero_diff_count = 0;

    printf("=== 测试 clock_gettime() 纳秒级精度 ===\n");
    printf("进行 %d 次连续调用...\n", TEST_ITERATIONS);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &current_ts);
        long long diff_ns = (current_ts.tv_sec - prev_ts.tv_sec) * NSEC_PER_SEC +
                           (current_ts.tv_nsec - prev_ts.tv_nsec);

        if (diff_ns < min_diff) min_diff = diff_ns;
        if (diff_ns > max_diff) max_diff = diff_ns;
        if (diff_ns == 0) zero_diff_count++;
        diff_sum += diff_ns;
        prev_ts = current_ts;
    }

    double avg_diff = (double)diff_sum / TEST_ITERATIONS;

    printf("最小时间间隔: %lld 纳秒 (%.2f 微秒)\n", min_diff, min_diff / 1000.0);
    printf("最大时间间隔: %lld 纳秒 (%.2f 微秒)\n", max_diff, max_diff / 1000.0);
    printf("平均时间间隔: %.2f 纳秒 (%.2f 微秒)\n", avg_diff, avg_diff / 1000.0);
    printf("零间隔次数: %d (%.2f%%)\n", zero_diff_count, (double)zero_diff_count / TEST_ITERATIONS * 100);

    if (min_diff < 1000) {
        printf("✓ 精度达到纳秒级 (小于1微秒)\n");
    } else if (min_diff < 10000) {
        printf("✓ 精度达到微秒级\n");
    }
    printf("\n");
}

// 测试短时间延迟的准确性
void test_delay_accuracy(void) {
    long long target_delays[] = {1, 10, 100, 1000, 10000}; // 微秒
    int num_targets = sizeof(target_delays) / sizeof(target_delays[0]);

    printf("=== 测试延迟定时器准确性 ===\n");
    printf("目标延迟范围: 1 - 10000 微秒\n\n");

    for (int t = 0; t < num_targets; t++) {
        long long target_us = target_delays[t];
        long long total_error = 0;
        long long max_error = 0;
        long long min_error = LLONG_MAX;

        for (int i = 0; i < 10; i++) {
            long long start = get_us_time();

            // 使用usleep进行延迟
            usleep(target_us);

            long long end = get_us_time();
            long long actual_delay = end - start;
            long long error = llabs(actual_delay - target_us);
            long long error_percent = (error * 100) / target_us;

            total_error += error;
            if (error > max_error) max_error = error;
            if (error < min_error) min_error = error;
        }

        double avg_error = (double)total_error / 10;
        printf("目标延迟: %4lld 微秒 | ", target_us);
        printf("平均误差: %5.1f 微秒 (%.1f%%) | ", avg_error, (avg_error * 100) / target_us);
        printf("最大误差: %4lld 微秒 | ", max_error);
        printf("最小误差: %4lld 微秒 | ", min_error);

        if (avg_error < target_us * 0.1) {
            printf("✓ 优秀 (<10%%)\n");
        } else if (avg_error < target_us * 0.2) {
            printf("✓ 良好 (<20%%)\n");
        } else {
            printf("⚠️  较差 (>20%%)\n");
        }
    }
    printf("\n");
}

// 获取系统时钟分辨率
void check_clock_resolution(void) {
    struct timespec res;

    printf("=== 系统时钟分辨率信息 ===\n");

    if (clock_getres(CLOCK_MONOTONIC, &res) == 0) {
        long long res_ns = res.tv_sec * NSEC_PER_SEC + res.tv_nsec;
        printf("CLOCK_MONOTONIC 分辨率: %ld 秒 %ld 纳秒\n", res.tv_sec, res.tv_nsec);
        printf("                      总计: %lld 纳秒 (%.3f 微秒)\n",
               res_ns, res_ns / 1000.0);
    } else {
        perror("clock_getres");
    }

    if (clock_getres(CLOCK_REALTIME, &res) == 0) {
        long long res_ns = res.tv_sec * NSEC_PER_SEC + res.tv_nsec;
        printf("CLOCK_REALTIME 分辨率:  %ld 秒 %ld 纳秒\n", res.tv_sec, res.tv_nsec);
        printf("                      总计: %lld 纳秒 (%.3f 微秒)\n",
               res_ns, res_ns / 1000.0);
    } else {
        perror("clock_getres");
    }
    printf("\n");
}

// 测试高精度定时器
void test_high_precision_timer(void) {
    printf("=== 测试高精度定时器延迟 ===\n");
    printf("测试高精度循环延迟 (500微秒目标)...\n\n");

    long long target_us = 500;
    long long total_error = 0;
    long long max_error = 0;
    long long min_error = LLONG_MAX;
    double std_dev = 0;
    long long errors[20];

    for (int i = 0; i < 20; i++) {
        long long start = get_us_time();

        // 高精度延迟循环
        volatile long long counter = 0;
        long long target_ticks = target_us * 100; // 假设每微秒100次循环
        while (counter++ < target_ticks);

        long long end = get_us_time();
        long long actual_delay = end - start;
        long long error = llabs(actual_delay - target_us);
        errors[i] = error;

        total_error += error;
        if (error > max_error) max_error = error;
        if (error < min_error) min_error = error;
    }

    double avg_error = (double)total_error / 20;
    // 计算标准差
    double variance = 0;
    for (int i = 0; i < 20; i++) {
        variance += pow(errors[i] - avg_error, 2);
    }
    std_dev = sqrt(variance / 20);

    printf("高精度循环测试结果 (20次测试):\n");
    printf("  平均误差: %.2f 微秒\n", avg_error);
    printf("  最大误差: %lld 微秒\n", max_error);
    printf("  最小误差: %lld 微秒\n", min_error);
    printf("  标准差: %.2f 微秒\n", std_dev);
    printf("  变异系数: %.2f%%\n", (std_dev / avg_error) * 100);

    if (std_dev < 10) {
        printf("✓ 定时器稳定性优秀 (标准差 < 10微秒)\n");
    } else if (std_dev < 50) {
        printf("✓ 定时器稳定性良好 (标准差 < 50微秒)\n");
    } else {
        printf("⚠️  定时器稳定性一般 (标准差 >= 50微秒)\n");
    }
    printf("\n");
}

int main(void) {
    printf("╔═══════════════════════════════════════════╗\n");
    printf("║   Linux 微秒级定时器精度测试程序 v1.0      ║\n");
    printf("╚═══════════════════════════════════════════╝\n\n");

    check_clock_resolution();
    test_gettimeofday_precision();
    test_clock_gettime_precision();
    test_delay_accuracy();
    test_high_precision_timer();

    printf("╔═══════════════════════════════════════════╗\n");
    printf("║              测试完成                     ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    return 0;
}
