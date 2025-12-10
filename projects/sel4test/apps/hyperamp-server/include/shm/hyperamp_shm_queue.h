/**
 * @file hyperamp_shm_queue.h
 * @brief HyperAMP 共享内存队列 - seL4 版本
 * 
 * 这是精简的 seL4 版本,从 hvisor-tool 项目复制并修改而来。
 */

#ifndef HYPERAMP_SHM_QUEUE_SEL4_H
#define HYPERAMP_SHM_QUEUE_SEL4_H

#include <stdint.h>
#include <stddef.h>

/* ==================== 常量定义 ==================== */

#define HYPERAMP_ERROR_ADDR             UINT64_MAX
#define HYPERAMP_MAX_MAP_TABLE_ENTRIES  125  /* 使队列控制区正好 4KB (1页) */

#define HYPERAMP_OK                     0
#define HYPERAMP_ERROR                  (-1)

/* 内存映射模式 */
typedef enum {
    HYPERAMP_MAP_MODE_CONTIGUOUS_BOTH = 0,
    HYPERAMP_MAP_MODE_CONTIGUOUS_PHYS_DISCRETE_LOGICAL
} HyperampMapMode;

/* 消息常量 */
#define HYPERAMP_MSG_HDR_SIZE           8
#define HYPERAMP_MSG_MIN_SIZE           1
#define HYPERAMP_MSG_MAX_SIZE           4088
#define HYPERAMP_MSG_HDR_PLUS_MAX_SIZE  (HYPERAMP_MSG_HDR_SIZE + HYPERAMP_MSG_MAX_SIZE)

/* 队列魔数 */
#define HYPERAMP_QUEUE_MAGIC            0x48415150  // "HAQP"

/* ==================== 内存屏障和缓存操作 ==================== */

#if defined(__aarch64__) || defined(__arm__)
    #define HYPERAMP_DMB()   __asm__ volatile("dmb sy" ::: "memory")
    #define HYPERAMP_DSB()   __asm__ volatile("dsb sy" ::: "memory")
    #define HYPERAMP_ISB()   __asm__ volatile("isb" ::: "memory")
    
    /* 数据缓存清理 - 将缓存行刷新到主存 (用于共享内存写入) */
    static inline void hyperamp_cache_clean(volatile void *addr, size_t size) {
        volatile char *p = (volatile char *)addr;
        volatile char *end = p + size;
        /* ARM64 缓存行通常是 64 字节 */
        for (; p < end; p += 64) {
            __asm__ volatile("dc cvac, %0" : : "r"(p) : "memory");
        }
        __asm__ volatile("dsb sy" ::: "memory");
    }
    
    /* 数据缓存失效 - 丢弃缓存内容，强制从内存读取 (用于共享内存读取) */
    static inline void hyperamp_cache_invalidate(volatile void *addr, size_t size) {
        volatile char *p = (volatile char *)addr;
        volatile char *end = p + size;
        for (; p < end; p += 64) {
            __asm__ volatile("dc civac, %0" : : "r"(p) : "memory");
        }
        __asm__ volatile("dsb sy" ::: "memory");
    }
#else
    #define HYPERAMP_DMB()   __asm__ volatile("mfence" ::: "memory")
    #define HYPERAMP_DSB()   __asm__ volatile("mfence" ::: "memory")
    #define HYPERAMP_ISB()   __asm__ volatile("" ::: "memory")
    
    static inline void hyperamp_cache_clean(volatile void *addr, size_t size) {
        (void)addr; (void)size;
        __asm__ volatile("mfence" ::: "memory");
    }
    
    static inline void hyperamp_cache_invalidate(volatile void *addr, size_t size) {
        (void)addr; (void)size;
        __asm__ volatile("mfence" ::: "memory");
    }
#endif

#define HYPERAMP_BARRIER()   do { HYPERAMP_DMB(); HYPERAMP_DSB(); } while(0)

/* ==================== 软件自旋锁 ==================== */

typedef struct {
    volatile uint32_t lock_value;
    volatile uint32_t owner_zone_id;
    volatile uint32_t lock_count;
    volatile uint32_t contention_count;
} __attribute__((packed)) HyperampSpinlock;

static inline void hyperamp_spinlock_init(volatile HyperampSpinlock *lock)
{
    if (!lock) return;
    
    volatile uint8_t *p = (volatile uint8_t *)lock;
    for (size_t i = 0; i < sizeof(HyperampSpinlock); i++) {
        p[i] = 0;
    }
    HYPERAMP_BARRIER();
}

static inline void hyperamp_spinlock_lock(volatile HyperampSpinlock *lock, uint32_t zone_id)
{
    if (!lock) return;
    
    int spin_count = 0;
    const int max_spin = 100000;
    
    while (1) {
        HYPERAMP_BARRIER();
        
        volatile uint32_t current = lock->lock_value;
        
        if (current == 0) {
            lock->lock_value = 1;
            HYPERAMP_BARRIER();
            
            volatile uint32_t verify = lock->lock_value;
            if (verify == 1) {
                lock->owner_zone_id = zone_id;
                lock->lock_count++;
                HYPERAMP_BARRIER();
                return;
            }
        }
        
        lock->contention_count++;
        spin_count++;
        
        if (spin_count > max_spin) {
            spin_count = 0;
#if defined(__aarch64__) || defined(__arm__)
            __asm__ volatile("yield" ::: "memory");
#else
            __asm__ volatile("pause" ::: "memory");
#endif
        }
        
        for (volatile int i = 0; i < 100; i++) {
            HYPERAMP_BARRIER();
        }
    }
}

static inline void hyperamp_spinlock_unlock(volatile HyperampSpinlock *lock)
{
    if (!lock) return;
    
    HYPERAMP_BARRIER();
    lock->owner_zone_id = 0;
    lock->lock_value = 0;
    HYPERAMP_BARRIER();
}

/* ==================== 地址映射表项 ==================== */

typedef struct {
    uint64_t virt_addr;
    uint64_t phy_addr;
} __attribute__((packed)) HyperampMapTableEntry;

/* ==================== 共享内存池队列 ==================== */

typedef struct {
    uint8_t  map_mode1;
    uint8_t  map_mode2;
    uint16_t header;
    uint16_t tail;
    uint16_t capacity;
    uint16_t block_size;
    uint16_t _reserved;
    
    uint64_t phy_addr;
    uint64_t virt_addr1;
    uint64_t virt_addr2;
    
    HyperampMapTableEntry table1[HYPERAMP_MAX_MAP_TABLE_ENTRIES];
    HyperampMapTableEntry table2[HYPERAMP_MAX_MAP_TABLE_ENTRIES];
    
    HyperampSpinlock queue_lock;
    
    uint32_t magic;
    uint32_t version;
    uint32_t enqueue_count;
    uint32_t dequeue_count;
    
} __attribute__((packed)) HyperampShmQueue;

/* ==================== 消息头结构 ==================== */

typedef struct {
    uint8_t  version;
    uint8_t  proxy_msg_type;
    uint16_t frontend_sess_id;
    uint16_t backend_sess_id;
    uint16_t payload_len;
} __attribute__((packed)) HyperampMsgHeader;

/* 消息类型 */
typedef enum {
    HYPERAMP_MSG_TYPE_DEV = 0,
    HYPERAMP_MSG_TYPE_STRGY = 1,
    HYPERAMP_MSG_TYPE_SESS = 2,
    HYPERAMP_MSG_TYPE_DATA = 3
} HyperampMsgType;

/* ==================== 安全内存操作 ==================== */

static inline void hyperamp_safe_memset(volatile void *dst, uint8_t val, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)dst;
    for (size_t i = 0; i < len; i++) {
        p[i] = val;
    }
    HYPERAMP_BARRIER();
}

static inline void hyperamp_safe_memcpy(volatile void *dst, const volatile void *src, size_t len)
{
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;
    for (size_t i = 0; i < len; i++) {
        d[i] = s[i];
    }
    HYPERAMP_BARRIER();
}

static inline uint16_t hyperamp_safe_read_u16(const volatile void *addr, size_t offset)
{
    const volatile uint8_t *p = (const volatile uint8_t *)addr;
    uint16_t val = 0;
    for (int i = 0; i < 2; i++) {
        val |= ((uint16_t)p[offset + i]) << (i * 8);
    }
    HYPERAMP_BARRIER();
    return val;
}

static inline uint32_t hyperamp_safe_read_u32(const volatile void *addr, size_t offset)
{
    const volatile uint8_t *p = (const volatile uint8_t *)addr;
    uint32_t val = 0;
    for (int i = 0; i < 4; i++) {
        val |= ((uint32_t)p[offset + i]) << (i * 8);
    }
    HYPERAMP_BARRIER();
    return val;
}

static inline uint64_t hyperamp_safe_read_u64(const volatile void *addr, size_t offset)
{
    const volatile uint8_t *p = (const volatile uint8_t *)addr;
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= ((uint64_t)p[offset + i]) << (i * 8);
    }
    HYPERAMP_BARRIER();
    return val;
}

/* ==================== 队列配置结构 ==================== */

/**
 * @brief 队列初始化配置
 */
typedef struct {
    uint16_t map_mode;      // 内存映射模式
    uint16_t capacity;      // 队列容量
    uint16_t block_size;    // 块大小
    uint16_t _reserved;
    uint64_t phy_addr;      // 物理地址
    uint64_t virt_addr;     // 虚拟地址
} HyperampQueueConfig;

/* ==================== 队列操作函数 (精简版,无 printf) ==================== */

/**
 * @brief 检查队列是否已初始化
 */
static inline int hyperamp_queue_is_initialized(volatile HyperampShmQueue *queue)
{
    if (!queue) return 0;
    
    HYPERAMP_BARRIER();
    
    // 不使用 magic 字段(offset 4052 > 4096,会跨页),改用 capacity 字段(offset 6)
    size_t capacity_offset = offsetof(HyperampShmQueue, capacity);
    volatile uint8_t *p = (volatile uint8_t *)queue;
    
    uint16_t capacity = 0;
    for (int i = 0; i < 2; i++) {
        capacity |= ((uint16_t)p[capacity_offset + i]) << (i * 8);
    }
    
    HYPERAMP_BARRIER();
    // 队列已初始化的标志: capacity > 0
    return (capacity > 0);
}

/**
 * @brief 入队操作
 */
static inline int hyperamp_queue_enqueue(volatile HyperampShmQueue *queue,
                                          uint32_t zone_id,
                                          const void *data,
                                          size_t data_len,
                                          volatile void *virt_base)
{
    if (!queue || !data || data_len == 0) return HYPERAMP_ERROR;
    
    // 安全读取 block_size 和 capacity
    uint16_t block_size = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, block_size));
    uint16_t capacity = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, capacity));
    
    if (data_len > block_size) return HYPERAMP_ERROR;
    
    // 获取锁
    hyperamp_spinlock_lock(&queue->queue_lock, zone_id);
    
    // 安全读取 header 和 tail
    uint16_t header = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, header));
    uint16_t tail = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, tail));
    
    // 计算新的 header
    uint16_t new_header = header + 1;
    if (new_header >= capacity) {
        new_header -= capacity;
    }
    
    // 检查队列是否满
    if (new_header == tail) {
        hyperamp_spinlock_unlock(&queue->queue_lock);
        return HYPERAMP_ERROR;
    }
    
    // 计算写入地址
    uint64_t write_addr = (uint64_t)virt_base + (uint64_t)(header + 1) * block_size;
    
    // 写入数据
    hyperamp_safe_memcpy((volatile void *)write_addr, data, data_len);
    
    // 更新 header (逐字节写入)
    volatile uint8_t *p = (volatile uint8_t *)queue;
    size_t header_offset = offsetof(HyperampShmQueue, header);
    p[header_offset] = new_header & 0xFF;
    p[header_offset + 1] = (new_header >> 8) & 0xFF;
    
    // 更新 enqueue_count (逐字节写入)
    size_t enqueue_offset = offsetof(HyperampShmQueue, enqueue_count);
    uint32_t enqueue_count = hyperamp_safe_read_u32(queue, enqueue_offset);
    enqueue_count++;
    for (int i = 0; i < 4; i++) {
        p[enqueue_offset + i] = (enqueue_count >> (i * 8)) & 0xFF;
    }
    
    HYPERAMP_BARRIER();
    
    /* 刷新写入的数据到内存 */
    hyperamp_cache_clean((volatile void *)write_addr, data_len);
    /* 刷新队列控制块到内存 */
    hyperamp_cache_clean((volatile void *)queue, 64); /* 只刷新前 64 字节控制字段 */
    
    // 释放锁
    hyperamp_spinlock_unlock(&queue->queue_lock);
    
    return HYPERAMP_OK;
}

/**
 * @brief 出队操作
 */
static inline int hyperamp_queue_dequeue(volatile HyperampShmQueue *queue,
                                          uint32_t zone_id,
                                          void *data,
                                          size_t max_len,
                                          size_t *actual_len,
                                          volatile void *virt_base)
{
    if (!queue || !data || max_len == 0) return HYPERAMP_ERROR;
    
    /* 在读取前失效缓存，确保读取到最新数据 */
    hyperamp_cache_invalidate((volatile void *)queue, 64);
    
    // 获取锁
    hyperamp_spinlock_lock(&queue->queue_lock, zone_id);
    
    // 安全读取 header, tail, block_size, capacity
    uint16_t header = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, header));
    uint16_t tail = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, tail));
    uint16_t block_size = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, block_size));
    uint16_t capacity = hyperamp_safe_read_u16(queue, offsetof(HyperampShmQueue, capacity));
    
    // 检查队列是否为空
    if (tail == header) {
        hyperamp_spinlock_unlock(&queue->queue_lock);
        return HYPERAMP_ERROR;
    }
    
    // 计算读取地址
    uint64_t read_addr = (uint64_t)virt_base + (uint64_t)(tail + 1) * block_size;
    
    /* 失效数据区缓存，确保读取到最新数据 */
    hyperamp_cache_invalidate((volatile void *)read_addr, block_size);
    
    // 计算实际读取长度
    size_t read_len = (max_len < block_size) ? max_len : block_size;
    
    // 读取数据
    hyperamp_safe_memcpy(data, (const volatile void *)read_addr, read_len);
    
    if (actual_len) {
        *actual_len = read_len;
    }
    
    // 更新 tail (逐字节写入)
    uint16_t new_tail = tail + 1;
    if (new_tail >= capacity) {
        new_tail -= capacity;
    }
    
    volatile uint8_t *p = (volatile uint8_t *)queue;
    size_t tail_offset = offsetof(HyperampShmQueue, tail);
    p[tail_offset] = new_tail & 0xFF;
    p[tail_offset + 1] = (new_tail >> 8) & 0xFF;
    
    // 更新 dequeue_count (逐字节写入)
    size_t dequeue_offset = offsetof(HyperampShmQueue, dequeue_count);
    uint32_t dequeue_count = hyperamp_safe_read_u32(queue, dequeue_offset);
    dequeue_count++;
    for (int i = 0; i < 4; i++) {
        p[dequeue_offset + i] = (dequeue_count >> (i * 8)) & 0xFF;
    }
    
    HYPERAMP_BARRIER();
    
    // 释放锁
    hyperamp_spinlock_unlock(&queue->queue_lock);
    
    return HYPERAMP_OK;
}

/**
 * @brief 初始化共享内存队列 (seL4 can now init queues itself!)
 * @param queue 队列指针
 * @param config 配置参数
 * @param is_creator 是否为队列创建者（创建者负责初始化所有字段）
 * @return HYPERAMP_OK 成功, HYPERAMP_ERROR 失败
 */
static inline int hyperamp_queue_init(volatile HyperampShmQueue *queue, 
                                       const HyperampQueueConfig *config,
                                       int is_creator)
{
    if (!queue || !config) return HYPERAMP_ERROR;
    if (config->block_size == 0 || config->capacity == 0) return HYPERAMP_ERROR;
    
    if (is_creator) {
        // 创建者：使用安全的逐字节写入方式
        volatile uint8_t *p = (volatile uint8_t *)queue;
        
        // 写入 map_mode1 和 map_mode2
        p[0] = config->map_mode;
        p[1] = config->map_mode;
        HYPERAMP_BARRIER();
        
        // 写入 header (uint16_t, offset 2)
        p[2] = 0;
        p[3] = 0;
        HYPERAMP_BARRIER();
        
        // 写入 tail (uint16_t, offset 4)
        p[4] = 0;
        p[5] = 0;
        HYPERAMP_BARRIER();
        
        // 写入 capacity (uint16_t, offset 6)
        uint16_t cap = config->capacity;
        p[6] = cap & 0xFF;
        p[7] = (cap >> 8) & 0xFF;
        HYPERAMP_BARRIER();
        
        // 写入 block_size (uint16_t, offset 8)
        uint16_t bs = config->block_size;
        p[8] = bs & 0xFF;
        p[9] = (bs >> 8) & 0xFF;
        HYPERAMP_BARRIER();
        
        // 写入 _reserved (uint16_t, offset 10)
        p[10] = 0;
        p[11] = 0;
        HYPERAMP_BARRIER();
        
        // 写入 phy_addr (uint64_t, offset 12) - 逐字节
        uint64_t pa = config->phy_addr;
        for (int i = 0; i < 8; i++) {
            p[12 + i] = (pa >> (i * 8)) & 0xFF;
        }
        HYPERAMP_BARRIER();
        
        // 写入 virt_addr1 (uint64_t, offset 20)
        uint64_t va = config->virt_addr;
        for (int i = 0; i < 8; i++) {
            p[20 + i] = (va >> (i * 8)) & 0xFF;
        }
        HYPERAMP_BARRIER();
        
        // 写入 virt_addr2 (uint64_t, offset 28) - 清零
        for (int i = 0; i < 8; i++) {
            p[28 + i] = 0;
        }
        HYPERAMP_BARRIER();
        
        // 初始化自旋锁
        size_t lock_offset = offsetof(HyperampShmQueue, queue_lock);
        volatile HyperampSpinlock *lock = (volatile HyperampSpinlock *)&p[lock_offset];
        hyperamp_spinlock_init(lock);
        
        // 写入 magic (uint32_t)
        size_t magic_offset = offsetof(HyperampShmQueue, magic);
        uint32_t magic = HYPERAMP_QUEUE_MAGIC;
        for (int i = 0; i < 4; i++) {
            p[magic_offset + i] = (magic >> (i * 8)) & 0xFF;
        }
        HYPERAMP_BARRIER();
        
        // 写入 version (uint32_t)
        uint32_t version = 1;
        for (int i = 0; i < 4; i++) {
            p[magic_offset + 4 + i] = (version >> (i * 8)) & 0xFF;
        }
        HYPERAMP_BARRIER();
        
        // 写入 enqueue_count (uint32_t) - 清零
        for (int i = 0; i < 4; i++) {
            p[magic_offset + 8 + i] = 0;
        }
        HYPERAMP_BARRIER();
        
        // 写入 dequeue_count (uint32_t) - 清零
        for (int i = 0; i < 4; i++) {
            p[magic_offset + 12 + i] = 0;
        }
        HYPERAMP_BARRIER();
        
        /* 关键：刷新整个队列结构到内存，确保其他 CPU/Zone 能看到 */
        hyperamp_cache_clean((volatile void *)queue, sizeof(HyperampShmQueue));
        
    } else {
        // 非创建者：只设置自己的虚拟地址
        queue->virt_addr2 = config->virt_addr;
        HYPERAMP_BARRIER();
    }
    
    return HYPERAMP_OK;
}

#endif /* HYPERAMP_SHM_QUEUE_SEL4_H */

