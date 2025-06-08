#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/perf_event.h>
#include <linux/kernel.h>
#include <linux/hw_breakpoint.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ptrace.h>

#include <linux/kfifo.h>
#include <linux/percpu.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/smp.h>

#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/pgtable.h>
#include <linux/page-flags.h>
#include <linux/interrupt.h>  // tasklet

#define MY_USING_PMU

#define PMU_FIFO_SIZE 5120
#define TIMER_INTERVAL_MS (1000/18)

const int mem_store    = 0x82d0;
const int mem_load     = 0x81d0;
const int mem_any      = 0x83d0;

#ifdef MY_USING_PMU
static struct perf_event *pebs_event[16] = {NULL};

struct percpu_kfifo {
    struct kfifo fifo;
    char buffer[PMU_FIFO_SIZE];
    struct tasklet_struct tasklet;
};

static DEFINE_PER_CPU(struct percpu_kfifo, percpu_fifo);

static void perf_event_handler(struct perf_event *event,
                               struct perf_sample_data *data,
                               struct pt_regs *regs)
{
    u64 phy = data->phys_addr;

    struct percpu_kfifo *buffer = this_cpu_ptr(&percpu_fifo);

    // circular buffer!
    if (kfifo_avail(&buffer->fifo) < sizeof(u64)) {
        kfifo_skip_count(&buffer->fifo, sizeof(u64));
    }

    kfifo_in(&buffer->fifo, (void*) &phy, sizeof(u64));

    if(kfifo_avail(&buffer->fifo) >= PMU_FIFO_SIZE * 7 / 10) {
        tasklet_schedule(&buffer->tasklet);
    }
}

static void perf_init(void) {

    struct perf_event_attr pebs_attr = {};
    memset(&pebs_attr, 0, sizeof(pebs_attr));

    // 表示config是用raw event id設定
    pebs_attr.type = PERF_TYPE_RAW;

    pebs_attr.size = sizeof(struct perf_event_attr);

    // mem-loads: 0xcd, mem-stores: 0xd0
    // (umask << 8) | event-id
    // cat /sys/bus/event_source/devices/cpu/events/mem-loads
    pebs_attr.config = mem_any;

    // 多少個事件紀錄一次
    pebs_attr.sample_period = 8000;

    // ip, addr, phys_addr
    // pebs_attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR;
    pebs_attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR | PERF_SAMPLE_PHYS_ADDR;

    // exclude kernel
    pebs_attr.exclude_kernel = 1;

    // enable PEBS （不需要ip的話可以不用那麼精確）
    pebs_attr.precise_ip = 2;

    // mem-any per-cpu
    for(int i = 0; i < 8; ++i) {
        pebs_event[i] = perf_event_create_kernel_counter(&pebs_attr, i, NULL, perf_event_handler, NULL);
        if (IS_ERR(pebs_event[i])) {
            pr_err("Failed to create PEBS event\n");
            // return PTR_ERR(pebs_event[i]);
        }
    }
}

static void consume_fifo(struct percpu_kfifo *pkfifo, int cpu)
{
    u64 val;
    unsigned int copied;

    while (kfifo_len(&pkfifo->fifo) >= sizeof(u64)) {
        copied = kfifo_out(&pkfifo->fifo, (unsigned char*)&val, sizeof(u64));
        if (copied != sizeof(u64))
            break;

        struct page *page = pfn_to_page(PHYS_PFN(val));
        struct folio *folio = page_folio(page); 
        folio_set_active(folio);

        // pr_info("CPU %d consumed value: %llu\n", cpu, val);
    }
}

// tasklet callback function
static void consume_fifo_tasklet(unsigned long data)
{
    struct percpu_kfifo *pkfifo = (struct percpu_kfifo *)data;
    int cpu = smp_processor_id();

    pr_info("CPU %d tasklet running...\n", cpu);
    consume_fifo(pkfifo, cpu);
}

static void init_percpu_fifo(void *info)
{
    struct percpu_kfifo *pkfifo = this_cpu_ptr(&percpu_fifo);
    kfifo_init(&pkfifo->fifo, pkfifo->buffer, PMU_FIFO_SIZE);

    // 初始化 tasklet，data 帶 pkfifo 指標
    tasklet_init(&pkfifo->tasklet, consume_fifo_tasklet, (unsigned long)pkfifo);
}

static void exit_tasklet(void *info)
{
    struct percpu_kfifo *pkfifo = this_cpu_ptr(&percpu_fifo);
    tasklet_kill(&pkfifo->tasklet);
}

static int perf_thread_fn(void *data)
{
    perf_init();
    on_each_cpu(init_percpu_fifo, NULL, 1);

    while (!kthread_should_stop()) {
        ssleep(10);
        // printk(KERN_EMERG "<D> kthread running...\n");
    }

    on_each_cpu(exit_tasklet, NULL, 1);


    for(int i = 0; i < 16; ++i) {
        if(pebs_event[i]) {
            perf_event_release_kernel(pebs_event[i]);
        }
    }

    pr_info("perf_kthread: exiting\n");
    return 0;
}

#endif

static void pmu_reader_init(void) {

#ifdef MY_USING_PMU
    static struct task_struct *perf_kthread;

    printk(KERN_EMERG "<D> kthread init...\n");
    perf_kthread = kthread_run(perf_thread_fn, NULL, "pmu_reader_kthread");
    if (IS_ERR(perf_kthread)) {
        pr_err("<D> Failed to create perf kthread\n");
    }
#endif

}

