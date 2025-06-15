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

const int mem_store    = 0x82d0;
const int mem_load     = 0x81d0;
const int mem_any      = 0x83d0;

#ifdef MY_USING_PMU
static struct perf_event *pebs_event[16] = {NULL};

struct percpu_kfifo {
    struct kfifo fifo;
    char buffer[PMU_FIFO_SIZE];
    struct tasklet_struct tasklet;
    int scheduled;
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
        pr_warn("PMU buffer full, skipping data\n");
    }

    kfifo_in(&buffer->fifo, (void*) &phy, sizeof(u64));

    // 70% full, schedule tasklet
    if(kfifo_avail(&buffer->fifo) >= PMU_FIFO_SIZE * 7 / 10 && !buffer->scheduled) {
        buffer->scheduled = 1;
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
    pebs_attr.sample_period = 10000;

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
        }
    }
}

static void consume_fifo(struct percpu_kfifo *pkfifo, int cpu) {
    u64 val;
    unsigned int copied;

    while (kfifo_len(&pkfifo->fifo) >= sizeof(u64)) {
        copied = kfifo_out(&pkfifo->fifo, (unsigned char*)&val, sizeof(u64));
        if (copied != sizeof(u64))
            break;

        struct page *page = pfn_to_page(PHYS_PFN(val));
        struct folio *folio = page_folio(page); 
        folio_set_active(folio);
    }
}

// tasklet callback function
static void consume_fifo_tasklet(unsigned long data)
{
    struct percpu_kfifo *pkfifo = (struct percpu_kfifo *)data;
    int cpu = smp_processor_id();

    pkfifo->scheduled = 0; // reset scheduled flag
    // pr_info("PMU tasklet running on CPU %d\n", cpu);
    consume_fifo(pkfifo, cpu);
}

static void init_percpu_fifo(void *info)
{
    struct percpu_kfifo *pkfifo = this_cpu_ptr(&percpu_fifo);
    kfifo_init(&pkfifo->fifo, pkfifo->buffer, PMU_FIFO_SIZE);

    // init tasklet
    tasklet_init(&pkfifo->tasklet, consume_fifo_tasklet, (unsigned long)pkfifo);
}

#endif


static void pmu_reader_init(void) {

#ifdef MY_USING_PMU
    pr_info("PMU reader starts init\n");
    perf_init();
    on_each_cpu(init_percpu_fifo, NULL, 1);
#endif

}

