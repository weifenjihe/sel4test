/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <autoconf.h>
#include <stdio.h>
#include <sel4/sel4.h>
#include <sel4/types.h>
#include <arch_stdio.h>
#include <string.h>
#include <assert.h>
#include <sel4utils/mapping.h>
#include <sel4utils/vspace.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vspace/vspace.h>
#include <vspace/arch/page.h>
#include <sel4platsupport/bootinfo.h>
#include "msg.h"
#include <simple/simple.h>
#include <simple-default/simple-default.h>
#include <vka/cspacepath_t.h>
#include <allocman/allocman.h>
#include <allocman/bootstrap.h>
#include <allocman/cspace/simple1level.h>
#include <allocman/vka.h>
#include <sel4utils/sel4_zf_logif.h>
#include <sel4utils/helpers.h>
#include <sel4utils/page_dma.h>

// ---------- 新增: 基础内存管理全局 ----------
#define ALLOCMAN_POOL_SIZE (1 << 20) /* 1MB pool */

static char allocman_buf[ALLOCMAN_POOL_SIZE];
static allocman_t *g_allocman;
static vka_t g_vka;
static vspace_t g_vspace;
static simple_t g_simple;
static sel4utils_alloc_data_t g_alloc_data;
static seL4_BootInfo *g_bootinfo;
static seL4_CPtr g_pd_cap; // 保存页目录cap

// 目标物理区与虚拟映射布局
#define SHM_PADDR_DATA      0xDE000000UL
#define SHM_SIZE_DATA       0x00400000UL  /* 4MB */
#define SHM_PADDR_QUEUE_BLK 0xDE400000UL  /* 128KB device untyped */
#define SHM_SIZE_QUEUE_BLK  0x00020000UL  /* 128KB */
#define SHM_PADDR_ROOT_Q    0xDE400000UL
#define SHM_PADDR_SEL4_Q    0xDE410000UL  /* offset 0x10000 */
#define SHM_PAGE_SIZE       0x1000UL

// 选定虚拟地址起点(任意未使用区域)  data占4MB, 队列各1页
#define SHM_VADDR_BASE      ((void*)0x20000000UL)
#define SHM_VADDR_DATA      (SHM_VADDR_BASE)
#define SHM_VADDR_ROOT_Q    ((void*)((uintptr_t)SHM_VADDR_BASE + SHM_SIZE_DATA))
#define SHM_VADDR_SEL4_Q    ((void*)((uintptr_t)SHM_VADDR_ROOT_Q + SHM_PAGE_SIZE))

// 消息队列初始化标记
#define INIT_MARK_INITIALIZED  (0xEEEEEEEEU) /* 已正确初始化 */

// 记录映射结果
static void *g_data_vaddr = NULL;
static struct AmpMsgQueue *g_root_q_vaddr = NULL;
static struct AmpMsgQueue *g_sel4_q_vaddr = NULL;

// 初始化 simple/vka/vspace
static int init_mm_subsystem(void) {
    g_bootinfo = platsupport_get_bootinfo();
    if (!g_bootinfo) {
        printf("[mm] bootinfo NULL\n");
        return -1;
    }
    simple_default_init_bootinfo(&g_simple, g_bootinfo);
    g_allocman = bootstrap_use_current_simple(&g_simple, ALLOCMAN_POOL_SIZE, allocman_buf);
    if (!g_allocman) {
        printf("[mm] allocman init fail\n");
        return -1;
    }
    allocman_make_vka(&g_vka, g_allocman);
    seL4_CPtr pd_cap = simple_get_pd(&g_simple);
    if (pd_cap == seL4_CapNull) {
        printf("[mm] failed to get PD cap\n");
        return -1;
    }
    g_pd_cap = pd_cap;
    int err = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&g_vspace, &g_alloc_data, pd_cap, &g_vka, g_bootinfo);
    if (err) {
        printf("[mm] vspace bootstrap err=%d\n", err);
        return -1;
    }
    return 0;
}

// 查找包含指定物理区的device untyped (返回cap索引与起始paddr)
static int find_device_untyped(uintptr_t paddr, size_t size, seL4_CPtr *out_cap, uintptr_t *out_start) {
    for (int i = g_bootinfo->untyped.start; i < g_bootinfo->untyped.end; i++) {
        seL4_UntypedDesc *d = &g_bootinfo->untypedList[i - g_bootinfo->untyped.start];
        uintptr_t us = d->paddr;
        uintptr_t ue = us + (1UL << d->sizeBits);
        if (d->isDevice && paddr >= us && (paddr + size) <= ue) {
            *out_cap = i;
            *out_start = us;
            return 0;
        }
    }
    return -1;
}


/* 通过 vka 分配若干个 4K frame */
static int allocate_frames_via_vka(size_t pages_needed, seL4_CPtr *out_caps, size_t caps_buf_len)
{
    if (!out_caps) {
        printf("[alloc_vka] invalid out_caps\n");
        return -1;
    }
    if (pages_needed > caps_buf_len) {
        printf("[alloc_vka] caps_buf too small need=%zu have=%zu\n", pages_needed, caps_buf_len);
        return -1;
    }

    for (size_t p = 0; p < pages_needed; p++) {
        vka_object_t frame_obj = { 0 };
        int r = vka_alloc_frame(&g_vka, seL4_PageBits, &frame_obj);
        if (r != 0 || frame_obj.cptr == 0) {
            printf("[alloc_vka] vka_alloc_frame fail idx=%zu r=%d cptr=%lu\n",
                   p, r, (unsigned long)frame_obj.cptr);
            return -1;
        }
        out_caps[p] = frame_obj.cptr;
    }
    return 0;
}



/* 单页映射 */
static int map_one_page(seL4_CPtr frame_cap, void *vaddr)
{
    seL4_CapRights_t rights = seL4_AllRights;
#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
    int cacheable = 0; // 设备内存禁用cache
#else
    int cacheable = 0;
#endif
    int err = sel4utils_map_page_leaky(&g_vka, g_pd_cap, frame_cap, vaddr, rights, cacheable);
    if (err) {
        printf("[map] map page vaddr=%p err=%d\n", vaddr, err);
    }
    return err;
}
/* ---------- 修改 map_queue_pages 使用新的 allocate_frames_via_vka ---------- */
/* 映射队列页: root_queue & sel4_queue */
static int map_queue_pages(void)
{
    const size_t pages_total = (SHM_SIZE_QUEUE_BLK + SHM_PAGE_SIZE - 1) / SHM_PAGE_SIZE; /* 128KB -> 32 */
    static seL4_CPtr caps[64];

    if (pages_total > sizeof(caps)/sizeof(caps[0])) {
        printf("[queue] caps buffer too small\n");
        return -1;
    }

    if (allocate_frames_via_vka(pages_total, caps, sizeof(caps)/sizeof(caps[0])) != 0) {
        printf("[queue] allocate_frames_via_vka failed\n");
        return -1;
    }

    size_t root_offset_pages = (SHM_PADDR_ROOT_Q - SHM_PADDR_QUEUE_BLK) / SHM_PAGE_SIZE; /* expect 0 */
    size_t sel4_offset_pages = (SHM_PADDR_SEL4_Q - SHM_PADDR_QUEUE_BLK) / SHM_PAGE_SIZE; /* expect 16 */

    if (map_one_page(caps[root_offset_pages], SHM_VADDR_ROOT_Q)) return -1;
    if (map_one_page(caps[sel4_offset_pages], SHM_VADDR_SEL4_Q)) return -1;

    g_root_q_vaddr = (struct AmpMsgQueue *)SHM_VADDR_ROOT_Q;
    g_sel4_q_vaddr = (struct AmpMsgQueue *)SHM_VADDR_SEL4_Q;
    printf("[queue] mapped root_q -> %p , sel4_q -> %p\n",
           g_root_q_vaddr, g_sel4_q_vaddr);
    return 0;
}
/* ---------- 修改 map_data_region 使用新的 allocate_frames_via_vka ---------- */
/* 映射4MB数据区 */
static int map_data_region(void)
{
    const size_t pages = (SHM_SIZE_DATA + SHM_PAGE_SIZE - 1) / SHM_PAGE_SIZE; // 向上取整
    static seL4_CPtr caps[1200];

    if (pages > sizeof(caps)/sizeof(caps[0])) {
        printf("[data] pages too many %zu\n", pages);
        return -1;
    }

    if (allocate_frames_via_vka(pages, caps, sizeof(caps)/sizeof(caps[0])) != 0) {
        printf("[data] allocate_frames_via_vka failed\n");
        return -1;
    }

    for (size_t i = 0; i < pages; i++) {
        void *vaddr = (void *)((uintptr_t)SHM_VADDR_DATA + i * SHM_PAGE_SIZE);
        if (map_one_page(caps[i], vaddr)) return -1;
    }
    g_data_vaddr = SHM_VADDR_DATA;
    printf("[data] mapped 0x%lx bytes at %p\n",
           (unsigned long)SHM_SIZE_DATA, g_data_vaddr);
    return 0;
}


// 高层封装: 完整映射
static int map_all_shared_regions(void) {
    if (map_data_region()) return -1;
    if (map_queue_pages()) return -1;
    return 0;
}

// 消息实体结构（与你的Linux代码保持一致）
struct MsgEntry {
    struct Msg msg;
    unsigned short nxt_idx;
};

// AMP消息队列结构（与你的Linux代码保持一致）
struct AmpMsgQueue {
    unsigned int working_mark;
    unsigned short buf_size;
    unsigned short empty_h;
    unsigned short wait_h;
    unsigned short proc_ing_h;
};

void __plat_putchar(int c);
static size_t write_buf(void *data, size_t count)
{
    char *buf = data;
    for (int i = 0; i < count; i++) {
        __plat_putchar(buf[i]);
    }
    return count;
}

// 辅助：打印全部untyped并判断是否覆盖/重叠目标区域
static void dump_untyped_info(void) {
    seL4_BootInfo *bootinfo = platsupport_get_bootinfo();
    if (!bootinfo) {
        printf("[untyped] Cannot get bootinfo\n");
        return;
    }
    struct {
        const char *name; uintptr_t start; size_t size;
    } targets[] = {
        {"data_buffer", 0xde000000UL, 0x400000},
        {"root_queue",  0xde400000UL, 0x1000},
        {"sel4_queue",  0xde410000UL, 0x1000},
    };
    size_t target_cnt = sizeof(targets)/sizeof(targets[0]);
    printf("\n=== Dump All Untyped Descriptors ===\n");
    printf("Index   PAddr Range                        Size        Dev  Contains           OverlapTargets\n");
    for (int i = bootinfo->untyped.start; i < bootinfo->untyped.end; i++) {
        seL4_UntypedDesc *d = &bootinfo->untypedList[i - bootinfo->untyped.start];
        uintptr_t us = d->paddr;
        uintptr_t ue = us + (1UL << d->sizeBits);
        char contain_buf[64] = {0};
        char overlap_buf[64] = {0};
        int cb_ofs = 0, ob_ofs = 0;
        for (size_t t = 0; t < target_cnt; t++) {
            uintptr_t ts = targets[t].start;
            uintptr_t te = ts + targets[t].size;
            int contains = (ts >= us && te <= ue);
            int overlap = !(te <= us || ts >= ue);
            if (contains) {
                int w = snprintf(contain_buf + cb_ofs, sizeof(contain_buf) - cb_ofs, "%s,", targets[t].name);
                if (w > 0) cb_ofs += w;
            }
            if (overlap) {
                int w = snprintf(overlap_buf + ob_ofs, sizeof(overlap_buf) - ob_ofs, "%s,", targets[t].name);
                if (w > 0) ob_ofs += w;
            }
        }
        if (cb_ofs == 0) strcpy(contain_buf, "-"); else contain_buf[cb_ofs-1] = 0;
        if (ob_ofs == 0) strcpy(overlap_buf, "-"); else overlap_buf[ob_ofs-1] = 0;
        printf("[%4d]  0x%010lx - 0x%010lx  2^%-2d %-3s  %-17s  %s\n", i, us, ue, d->sizeBits,
               d->isDevice ? "DEV" : "RAM", contain_buf, overlap_buf);
    }
    printf("Legend: Contains=目标区完全包含; OverlapTargets=任意交叠\n");
}

int main(void)
{
    sel4muslcsys_register_stdio_write_fn(write_buf);
    printf("<<seL4: Shared Memory Mapping (Capability-based)>>\n");
    printf("===============================================\n");

    if (init_mm_subsystem()) {
        printf("[fatal] init_mm_subsystem failed\n");
        return -1;
    }

    dump_untyped_info();

    if (map_all_shared_regions() == 0) {
        printf("[ok] all shared regions mapped via capabilities\n");
        // 在 map_all_shared_regions() 成功后
        char *p = (char*) g_data_vaddr;
        printf("shm test before: p[0]=%02x p[1]=%02x p[2]=%02x p[3]=%02x\n",
            (unsigned char)p[0], (unsigned char)p[1], (unsigned char)p[2], (unsigned char)p[3]);
        p[0] = 'A'; p[1] = 'B'; p[2] = 'C'; p[3] = '\n';
        printf("shm test after: p[0]=%02x p[1]=%02x p[2]=%02x p[3]=%02x\n",
       (unsigned char)p[0], (unsigned char)p[1], (unsigned char)p[2], (unsigned char)p[3]);

        // 初始化共享数据与队列
        strcpy((char*)g_data_vaddr, "seL4 shared memory ready (cap-mapped)!");
        g_sel4_q_vaddr->working_mark = INIT_MARK_INITIALIZED;
        g_sel4_q_vaddr->buf_size = 16;
        g_sel4_q_vaddr->empty_h = 0;
        g_sel4_q_vaddr->wait_h = 0;
        g_sel4_q_vaddr->proc_ing_h = 0;
        printf("data_vaddr=%p msg='%s'\n", g_data_vaddr, (char*)g_data_vaddr);
        printf("root_q=%p sel4_q=%p\n", g_root_q_vaddr, g_sel4_q_vaddr);
    } else {
        printf("[err] mapping shared regions failed; fallback demonstration\n");
    }

    return 0;
}