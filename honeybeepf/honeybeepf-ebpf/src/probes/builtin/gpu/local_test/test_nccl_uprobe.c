/*
 * HoneyBeePF NCCL Uprobe Test Suite
 * ==================================
 * GPU 없이 NCCL uprobe 동작을 검증하는 테스트 프로그램.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

/* ===== NCCL Type Definitions ===== */

/* ncclDataType_t - 이 값들이 uprobe에서 정확히 파싱되는지 확인 */
typedef enum {
    ncclInt8    = 0,
    ncclUint32  = 1,
    ncclInt32   = 2,
    ncclUint64  = 3,
    ncclInt64   = 4,
    ncclFloat16 = 5,
    ncclFloat32 = 6,
    ncclFloat64 = 7,
    ncclBfloat16 = 8,
} ncclDataType_t;

/* ncclRedOp_t */
typedef enum {
    ncclSum  = 0,
    ncclProd = 1,
    ncclMax  = 2,
    ncclMin  = 3,
    ncclAvg  = 4,
} ncclRedOp_t;

static const char* datatype_name(ncclDataType_t dt) {
    switch (dt) {
        case ncclInt8:     return "Int8";
        case ncclUint32:   return "Uint32";
        case ncclInt32:    return "Int32";
        case ncclUint64:   return "Uint64";
        case ncclInt64:    return "Int64";
        case ncclFloat16:  return "Float16";
        case ncclFloat32:  return "Float32";
        case ncclFloat64:  return "Float64";
        case ncclBfloat16: return "Bfloat16";
        default:           return "Unknown";
    }
}

static int datatype_size(ncclDataType_t dt) {
    switch (dt) {
        case ncclInt8:     return 1;
        case ncclUint32:   return 4;
        case ncclInt32:    return 4;
        case ncclUint64:   return 8;
        case ncclInt64:    return 8;
        case ncclFloat16:  return 2;
        case ncclFloat32:  return 4;
        case ncclFloat64:  return 8;
        case ncclBfloat16: return 2;
        default:           return 4;
    }
}

static const char* redop_name(ncclRedOp_t op) {
    switch (op) {
        case ncclSum:  return "Sum";
        case ncclProd: return "Prod";
        case ncclMax:  return "Max";
        case ncclMin:  return "Min";
        case ncclAvg:  return "Avg";
        default:       return "Unknown";
    }
}

/* ===== Function Pointer Types ===== */
typedef int (*fn_ncclGetVersion)(int* version);
typedef int (*fn_ncclGetUniqueId)(void* uniqueId);
typedef int (*fn_ncclCommInitRank)(void** comm, int nranks, void* commId, int rank);
typedef int (*fn_ncclCommDestroy)(void* comm);
typedef int (*fn_ncclAllReduce)(const void* sb, void* rb, size_t count,
                                ncclDataType_t dt, ncclRedOp_t op,
                                void* comm, void* stream);
typedef int (*fn_ncclBroadcast)(const void* sb, void* rb, size_t count,
                                ncclDataType_t dt, int root,
                                void* comm, void* stream);
typedef int (*fn_ncclAllGather)(const void* sb, void* rb, size_t count,
                                ncclDataType_t dt, void* comm, void* stream);
typedef int (*fn_ncclReduceScatter)(const void* sb, void* rb, size_t count,
                                    ncclDataType_t dt, ncclRedOp_t op,
                                    void* comm, void* stream);
typedef int (*fn_ncclSend)(const void* sb, size_t count, ncclDataType_t dt,
                           int peer, void* comm, void* stream);
typedef int (*fn_ncclRecv)(void* rb, size_t count, ncclDataType_t dt,
                           int peer, void* comm, void* stream);
typedef int (*fn_ncclGroupStart)(void);
typedef int (*fn_ncclGroupEnd)(void);

/* ===== Global State ===== */
static void* nccl_handle = NULL;
static fn_ncclGetVersion      p_ncclGetVersion;
static fn_ncclGetUniqueId     p_ncclGetUniqueId;
static fn_ncclCommInitRank    p_ncclCommInitRank;
static fn_ncclCommDestroy     p_ncclCommDestroy;
static fn_ncclAllReduce       p_ncclAllReduce;
static fn_ncclBroadcast       p_ncclBroadcast;
static fn_ncclAllGather       p_ncclAllGather;
static fn_ncclReduceScatter   p_ncclReduceScatter;
static fn_ncclSend            p_ncclSend;
static fn_ncclRecv            p_ncclRecv;
static fn_ncclGroupStart      p_ncclGroupStart;
static fn_ncclGroupEnd        p_ncclGroupEnd;

/* Fake comm for success-path tests */
static void* fake_comm = NULL;

static int test_passed = 0;
static int test_failed = 0;

/* ===== Helpers ===== */

#define ANSI_GREEN  "\033[32m"
#define ANSI_RED    "\033[31m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_CYAN   "\033[36m"
#define ANSI_BOLD   "\033[1m"
#define ANSI_RESET  "\033[0m"

#define LOG_SECTION(fmt, ...) \
    printf("\n" ANSI_BOLD ANSI_CYAN "═══ " fmt " ═══" ANSI_RESET "\n", ##__VA_ARGS__)

#define LOG_TEST(fmt, ...) \
    printf(ANSI_YELLOW "  ▶ " ANSI_RESET fmt "\n", ##__VA_ARGS__)

#define LOG_RESULT(fn_name, count, dt, ret) do { \
    const char* status = (ret != 0) ? ANSI_GREEN "UPROBE_OK" : ANSI_GREEN "SUCCESS"; \
    size_t bytes = (size_t)(count) * datatype_size(dt); \
    printf("    %s%-20s" ANSI_RESET " count=%-10zu dtype=%-10s bytes=%-12zu ret=%d %s(expected)%s\n", \
           ANSI_BOLD, fn_name, (size_t)(count), datatype_name(dt), bytes, ret, \
           ANSI_GREEN, ANSI_RESET); \
    test_passed++; \
} while(0)

static void* alloc_buffer(size_t size) {
    void* buf = calloc(1, size);
    if (!buf) {
        fprintf(stderr, "Failed to allocate %zu bytes\n", size);
        exit(1);
    }
    return buf;
}

/* ===== Test Suites ===== */

/*
 * Test 1: Basic Connectivity
 * - ncclGetVersion: GPU 없이도 성공하는 유일한 함수
 * - ncclCommInitRank: 초기화 시도 (실패 예상)
 */
static void test_basic_connectivity(void) {
    LOG_SECTION("Test 1: Basic Connectivity");

    /* ncclGetVersion */
    LOG_TEST("ncclGetVersion - should succeed without GPU");
    int version = 0;
    int ret = p_ncclGetVersion(&version);
    printf("    " ANSI_BOLD "ncclGetVersion" ANSI_RESET
           "       version=%d.%d.%d  ret=%d\n",
           version / 10000, (version / 100) % 100, version % 100, ret);
    test_passed++;

    /* ncclCommInitRank */
    LOG_TEST("ncclCommInitRank - init attempt (will fail without GPU)");
    void* comm = NULL;
    ret = p_ncclCommInitRank(&comm, 2, NULL, 0);
    printf("    " ANSI_BOLD "ncclCommInitRank" ANSI_RESET
           "     nranks=2 rank=0 ret=%d\n", ret);
    test_passed++;
}

/*
 * Test 2: AllReduce - 모든 datatype 조합
 * 실제 학습에서 가장 많이 호출되는 함수.
 * uprobe가 datatype 인자를 정확히 파싱하는지 검증.
 */
static void test_allreduce_datatypes(void) {
    LOG_SECTION("Test 2: AllReduce - Datatype Coverage");

    struct {
        ncclDataType_t dt;
        size_t count;
    } cases[] = {
        { ncclFloat32,  1024 },        /* 일반적인 FP32 gradient */
        { ncclFloat16,  2048 },        /* Mixed precision training */
        { ncclBfloat16, 4096 },        /* BF16 (A100+ 최적화) */
        { ncclFloat64,  512 },         /* Double precision (과학 계산) */
        { ncclInt8,     8192 },        /* Quantized model (INT8) */
        { ncclInt32,    1024 },        /* Index tensor */
        { ncclInt64,    256 },         /* Large index */
    };
    int ncases = sizeof(cases) / sizeof(cases[0]);

    size_t max_bytes = 8192 * 8;
    void* sendbuf = alloc_buffer(max_bytes);
    void* recvbuf = alloc_buffer(max_bytes);

    for (int i = 0; i < ncases; i++) {
        LOG_TEST("AllReduce with %s (count=%zu)",
                 datatype_name(cases[i].dt), cases[i].count);
        int ret = p_ncclAllReduce(sendbuf, recvbuf, cases[i].count,
                                   cases[i].dt, ncclSum, NULL, NULL);
        LOG_RESULT("ncclAllReduce", cases[i].count, cases[i].dt, ret);
        usleep(50000); /* 50ms 간격 - HoneyBeePF 로그 가독성 */
    }

    free(sendbuf);
    free(recvbuf);
}

/*
 * Test 3: AllReduce - 모든 reduction op
 * Sum, Prod, Max, Min, Avg 각각 테스트.
 */
static void test_allreduce_ops(void) {
    LOG_SECTION("Test 3: AllReduce - Reduction Operations");

    ncclRedOp_t ops[] = { ncclSum, ncclProd, ncclMax, ncclMin, ncclAvg };
    int nops = sizeof(ops) / sizeof(ops[0]);

    void* buf = alloc_buffer(4096);

    for (int i = 0; i < nops; i++) {
        LOG_TEST("AllReduce op=%s count=1024 dtype=Float32", redop_name(ops[i]));
        int ret = p_ncclAllReduce(buf, buf, 1024, ncclFloat32, ops[i], NULL, NULL);
        printf("    " ANSI_BOLD "ncclAllReduce" ANSI_RESET
               "        op=%-6s ret=%d\n", redop_name(ops[i]), ret);
        test_passed++;
        usleep(50000);
    }

    free(buf);
}

/*
 * Test 4: All Collective Operations
 * AllReduce 외의 collective도 전부 테스트.
 */
static void test_all_collectives(void) {
    LOG_SECTION("Test 4: All Collective Operations");

    void* sendbuf = alloc_buffer(65536);
    void* recvbuf = alloc_buffer(65536);

    /* Broadcast */
    LOG_TEST("ncclBroadcast - root=0, Float32");
    int ret = p_ncclBroadcast(sendbuf, recvbuf, 2048, ncclFloat32, 0, NULL, NULL);
    LOG_RESULT("ncclBroadcast", 2048, ncclFloat32, ret);
    usleep(50000);

    /* AllGather */
    LOG_TEST("ncclAllGather - Float16");
    ret = p_ncclAllGather(sendbuf, recvbuf, 4096, ncclFloat16, NULL, NULL);
    LOG_RESULT("ncclAllGather", 4096, ncclFloat16, ret);
    usleep(50000);

    /* ReduceScatter */
    LOG_TEST("ncclReduceScatter - Bfloat16, Sum");
    ret = p_ncclReduceScatter(sendbuf, recvbuf, 1024, ncclBfloat16, ncclSum, NULL, NULL);
    LOG_RESULT("ncclReduceScatter", 1024, ncclBfloat16, ret);
    usleep(50000);

    /* Send */
    LOG_TEST("ncclSend - peer=1, Float32");
    ret = p_ncclSend(sendbuf, 512, ncclFloat32, 1, NULL, NULL);
    printf("    " ANSI_BOLD "ncclSend" ANSI_RESET
           "             count=512   peer=1  ret=%d\n", ret);
    test_passed++;
    usleep(50000);

    /* Recv */
    LOG_TEST("ncclRecv - peer=0, Float32");
    ret = p_ncclRecv(recvbuf, 512, ncclFloat32, 0, NULL, NULL);
    printf("    " ANSI_BOLD "ncclRecv" ANSI_RESET
           "             count=512   peer=0  ret=%d\n", ret);
    test_passed++;
    usleep(50000);

    free(sendbuf);
    free(recvbuf);
}

/*
 * Test 5: Group Operations
 * ncclGroupStart/End로 여러 collective을 묶는 패턴.
 * 실제 학습에서는 Send/Recv를 그룹으로 묶어 파이프라인 병렬 처리.
 */
static void test_group_operations(void) {
    LOG_SECTION("Test 5: Group Operations (Pipeline Parallel Pattern)");

    void* buf = alloc_buffer(65536);

    LOG_TEST("Grouped Send+Recv (simulating pipeline parallel stage boundary)");

    int ret = p_ncclGroupStart();
    printf("    " ANSI_BOLD "ncclGroupStart" ANSI_RESET "       ret=%d\n", ret);
    test_passed++;

    /* Pipeline stage: send activation to next stage, recv gradient from next stage */
    ret = p_ncclSend(buf, 4096, ncclFloat16, 1, NULL, NULL);
    printf("    " ANSI_BOLD "  ncclSend" ANSI_RESET
           "           count=4096 peer=1 (activation →) ret=%d\n", ret);
    test_passed++;

    ret = p_ncclRecv(buf, 4096, ncclFloat16, 1, NULL, NULL);
    printf("    " ANSI_BOLD "  ncclRecv" ANSI_RESET
           "           count=4096 peer=1 (← gradient)   ret=%d\n", ret);
    test_passed++;

    ret = p_ncclGroupEnd();
    printf("    " ANSI_BOLD "ncclGroupEnd" ANSI_RESET "         ret=%d\n", ret);
    test_passed++;

    free(buf);
}

/*
 * Test 6: Simulated LLaMA 70B Training Step
 * 실제 LLaMA 70B 분산 학습의 한 step에서 발생하는 NCCL 호출 패턴 재현.
 *
 * 가정: 8 GPU Data Parallel + 2-way Tensor Parallel
 * 한 step:
 *   1. Forward pass 중 Tensor Parallel AllReduce (작은 크기, 빈번)
 *   2. Backward pass 중 gradient AllReduce (큰 크기)
 *   3. Optimizer step 후 parameter Broadcast
 */
static void test_simulate_llama_training(void) {
    LOG_SECTION("Test 6: Simulated LLaMA 70B Training Step");

    void* buf = alloc_buffer(256 * 1024 * 1024);  /* 256MB */

    printf("  " ANSI_YELLOW "Simulating one training step of LLaMA 70B" ANSI_RESET "\n");
    printf("  Config: 8 GPU Data Parallel, BF16 mixed precision\n\n");

    int ret;

    /* Phase 1: Forward - Tensor Parallel AllReduce */
    LOG_TEST("Phase 1: Forward Pass - Tensor Parallel AllReduce");
    printf("    (Multiple small AllReduce for attention output aggregation)\n");
    printf("    Using %s comm\n", fake_comm ? "valid" : "NULL");

    /* Attention layer output: hidden_size=8192, batch*seq=2048 */
    size_t attn_count = 8192 * 2048;  /* ~16M elements */
    for (int layer = 0; layer < 4; layer++) {  /* 4 layers simulated */
        ret = p_ncclAllReduce(buf, buf, attn_count, ncclBfloat16,
                               ncclSum, fake_comm, NULL);
        printf("    Layer %d AllReduce  count=%-10zu  size=%-8s  ret=%d\n",
               layer, attn_count,
               "32.00 MB", ret);
        test_passed++;
        usleep(10000);  /* 10ms */
    }

    /* Phase 2: Backward - Gradient AllReduce (가장 큰 통신) */
    LOG_TEST("Phase 2: Backward Pass - Gradient AllReduce");
    printf("    (Large AllReduce for gradient synchronization across 8 GPUs)\n");

    struct {
        const char* name;
        size_t count;
    } grad_layers[] = {
        { "embed_tokens",    32000 * 8192 },      /* ~262M elements = 500MB */
        { "self_attn.qkv",   8192 * 8192 * 3 },   /* ~201M elements */
        { "self_attn.o_proj", 8192 * 8192 },       /* ~67M elements */
        { "mlp.gate_proj",   8192 * 28672 },       /* ~235M elements */
        { "mlp.down_proj",   28672 * 8192 },       /* ~235M elements */
    };
    int nlayers = sizeof(grad_layers) / sizeof(grad_layers[0]);

    p_ncclGroupStart();
    printf("    " ANSI_BOLD "ncclGroupStart" ANSI_RESET " (batching gradient syncs)\n");

    for (int i = 0; i < nlayers; i++) {
        /* 큰 count는 축소 (메모리 제한) */
        size_t test_count = grad_layers[i].count;
        if (test_count > 16 * 1024 * 1024) {
            test_count = 16 * 1024 * 1024;  /* cap at 16M for test */
        }

        ret = p_ncclAllReduce(buf, buf, test_count, ncclBfloat16,
                               ncclSum, fake_comm, NULL);
        size_t bytes = test_count * 2;  /* BF16 = 2 bytes */
        printf("    %-20s count=%-10zu  size=%-10zu  ret=%d\n",
               grad_layers[i].name, test_count, bytes, ret);
        test_passed++;
        usleep(5000);
    }

    p_ncclGroupEnd();
    printf("    " ANSI_BOLD "ncclGroupEnd" ANSI_RESET "\n");
    test_passed += 2; /* group start/end */

    /* Phase 3: Parameter Broadcast (optimizer step 후) */
    LOG_TEST("Phase 3: Optimizer Step - Parameter Broadcast");
    printf("    (Updated parameters broadcast from rank 0)\n");

    ret = p_ncclBroadcast(buf, buf, 8192 * 8192, ncclBfloat16, 0, fake_comm, NULL);
    printf("    param_broadcast    count=%-10zu  size=%-10s  ret=%d\n",
           (size_t)(8192 * 8192), "128.00 MB", ret);
    test_passed++;

    printf("\n  " ANSI_GREEN "✓ Training step simulation complete" ANSI_RESET "\n");

    free(buf);
}

/*
 * Test 7: Burst Pattern Test
 * 짧은 시간에 대량의 NCCL 호출.
 * HoneyBeePF가 burst 상황에서 이벤트를 놓치지 않는지 확인.
 */
static void test_burst_pattern(void) {
    LOG_SECTION("Test 7: Burst Pattern (100 rapid calls)");

    void* buf = alloc_buffer(65536);
    int ret;

    printf("  Firing 100 ncclAllReduce calls in rapid succession...\n");

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < 100; i++) {
        ret = p_ncclAllReduce(buf, buf, 1024 + i * 100, ncclFloat32,
                               ncclSum, NULL, NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_nsec - start.tv_nsec) / 1000000.0;

    printf("  Completed 100 calls in %.2f ms (avg %.3f ms/call)\n",
           elapsed_ms, elapsed_ms / 100.0);
    printf("  " ANSI_YELLOW "→ Check HoneyBeePF: should see exactly 100 NCCL_AllReduce events"
           ANSI_RESET "\n");
    printf("  " ANSI_YELLOW "→ count should range from 1024 to 10924"
           ANSI_RESET "\n");
    test_passed += 100;

    free(buf);
}

/*
 * Test 8: Multi-threaded NCCL calls
 * 실제 환경에서는 여러 스레드가 동시에 NCCL 호출.
 * uprobe의 tid 기반 pending map이 정확히 동작하는지 확인.
 */
static void* thread_worker(void* arg) {
    int thread_id = *(int*)arg;
    void* buf = alloc_buffer(16384);

    for (int i = 0; i < 10; i++) {
        size_t count = (thread_id + 1) * 1000 + i * 100;
        int ret = p_ncclAllReduce(buf, buf, count, ncclFloat32,
                                   ncclSum, NULL, NULL);
        usleep(10000 + thread_id * 5000);  /* 스레드마다 다른 간격 */
    }

    free(buf);
    return NULL;
}

static void test_multithreaded(void) {
    LOG_SECTION("Test 8: Multi-threaded Concurrent Calls");

    printf("  Spawning 4 threads, each making 10 ncclAllReduce calls\n");
    printf("  Thread 0: count=1000-1900, Thread 1: count=2000-2900, ...\n\n");

    pthread_t threads[4];
    int thread_ids[4] = {0, 1, 2, 3};

    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, thread_worker, &thread_ids[i]);
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("  " ANSI_GREEN "✓ All threads completed" ANSI_RESET "\n");
    printf("  " ANSI_YELLOW "→ Check HoneyBeePF: should see 40 events total"
           ANSI_RESET "\n");
    printf("  " ANSI_YELLOW "→ Different PIDs (threads share PID but have different TIDs)"
           ANSI_RESET "\n");
    test_passed += 40;
}

/*
 * Test 9: Simulated Inference Serving Pattern
 * 학습과 다른 패턴: 작은 크기, 높은 빈도, latency sensitive
 */
static void test_inference_pattern(void) {
    LOG_SECTION("Test 9: Inference Serving Pattern");

    void* buf = alloc_buffer(32768);

    printf("  Simulating tensor parallel inference (small, frequent AllReduce)\n");
    printf("  Pattern: batch_size=1, seq_len=128, hidden=4096\n\n");

    /* Inference: 각 transformer layer마다 작은 AllReduce */
    for (int layer = 0; layer < 8; layer++) {
        /* Attention output AllReduce: [1, 128, 4096] = 524288 elements */
        int ret = p_ncclAllReduce(buf, buf, 4096, ncclFloat16,
                                   ncclSum, NULL, NULL);
        printf("    Layer %d attn    count=4096     size=8KB    ret=%d\n", layer, ret);

        /* MLP output AllReduce */
        ret = p_ncclAllReduce(buf, buf, 4096, ncclFloat16,
                               ncclSum, NULL, NULL);
        printf("    Layer %d mlp     count=4096     size=8KB    ret=%d\n", layer, ret);

        test_passed += 2;
        usleep(1000);  /* 1ms per layer (inference is fast) */
    }

    printf("\n  " ANSI_GREEN "✓ Inference simulation complete (16 AllReduce calls)"
           ANSI_RESET "\n");
}

/* ===== Main ===== */

static int load_nccl(const char* path) {
    nccl_handle = dlopen(path, RTLD_NOW);
    if (!nccl_handle) {
        fprintf(stderr, ANSI_RED "ERROR: Failed to load %s: %s\n" ANSI_RESET,
                path, dlerror());
        fprintf(stderr, "Build fake_nccl first: gcc -shared -fPIC -o libfake_nccl.so fake_nccl.c\n");
        return -1;
    }

    #define LOAD_SYM(name) do { \
        p_##name = (fn_##name)dlsym(nccl_handle, #name); \
        if (!p_##name) { \
            fprintf(stderr, ANSI_RED "WARNING: " #name " not found\n" ANSI_RESET); \
        } else { \
            printf("  ✓ " #name "\n"); \
        } \
    } while(0)

    printf(ANSI_BOLD "Loading NCCL symbols...\n" ANSI_RESET);
    LOAD_SYM(ncclGetVersion);
    LOAD_SYM(ncclGetUniqueId);
    LOAD_SYM(ncclCommInitRank);
    LOAD_SYM(ncclCommDestroy);
    LOAD_SYM(ncclAllReduce);
    LOAD_SYM(ncclBroadcast);
    LOAD_SYM(ncclAllGather);
    LOAD_SYM(ncclReduceScatter);
    LOAD_SYM(ncclSend);
    LOAD_SYM(ncclRecv);
    LOAD_SYM(ncclGroupStart);
    LOAD_SYM(ncclGroupEnd);
    printf("\n");

    /* Initialize fake comm for success-path tests */
    if (p_ncclGetUniqueId && p_ncclCommInitRank) {
        char uniqueId[128] = {0};
        p_ncclGetUniqueId(uniqueId);
        int ret = p_ncclCommInitRank(&fake_comm, 8, uniqueId, 0);
        if (ret == 0 && fake_comm) {
            printf(ANSI_GREEN "  ✓ Fake comm initialized (nranks=8, rank=0)\n" ANSI_RESET);
        } else {
            printf(ANSI_YELLOW "  ⚠ Comm init failed (ret=%d), using NULL comm\n" ANSI_RESET, ret);
        }
    }
    printf("\n");

    return 0;
}

int main(int argc, char** argv) {
    const char* nccl_path = "./libfake_nccl.so";  /* default */
    if (argc > 1) {
        nccl_path = argv[1];
    }

    printf(ANSI_BOLD ANSI_CYAN
           "\n"
           "╔══════════════════════════════════════════════════════════╗\n"
           "║       HoneyBeePF NCCL Uprobe Test Suite v1.0           ║\n"
           "║                                                        ║\n"
           "║  GPU not required - tests uprobe/uretprobe triggers    ║\n"
           "║  Run HoneyBeePF in another terminal to see events      ║\n"
           "╚══════════════════════════════════════════════════════════╝\n"
           ANSI_RESET "\n");

    printf("NCCL library: %s\n", nccl_path);
    printf("  (override with: ./test_nccl_uprobe /path/to/libnccl.so)\n\n");

    if (load_nccl(nccl_path) != 0) return 1;

    printf(ANSI_BOLD "Starting tests...\n" ANSI_RESET);
    printf("PID: %d  (use this to filter HoneyBeePF output)\n", getpid());

    struct timespec total_start, total_end;
    clock_gettime(CLOCK_MONOTONIC, &total_start);

    /* Run all tests */
    if (p_ncclGetVersion && p_ncclCommInitRank)
        test_basic_connectivity();

    if (p_ncclAllReduce)
        test_allreduce_datatypes();

    if (p_ncclAllReduce)
        test_allreduce_ops();

    if (p_ncclAllReduce && p_ncclBroadcast && p_ncclAllGather &&
        p_ncclReduceScatter && p_ncclSend && p_ncclRecv)
        test_all_collectives();

    if (p_ncclGroupStart && p_ncclGroupEnd && p_ncclSend && p_ncclRecv)
        test_group_operations();

    if (p_ncclAllReduce && p_ncclBroadcast && p_ncclGroupStart && p_ncclGroupEnd)
        test_simulate_llama_training();

    if (p_ncclAllReduce)
        test_burst_pattern();

    if (p_ncclAllReduce)
        test_multithreaded();

    if (p_ncclAllReduce)
        test_inference_pattern();

    clock_gettime(CLOCK_MONOTONIC, &total_end);
    double total_ms = (total_end.tv_sec - total_start.tv_sec) * 1000.0 +
                      (total_end.tv_nsec - total_start.tv_nsec) / 1000000.0;

    /* Summary */
    printf(ANSI_BOLD ANSI_CYAN
           "\n╔══════════════════════════════════════════════════════════╗\n"
           "║                    TEST SUMMARY                        ║\n"
           "╠══════════════════════════════════════════════════════════╣\n"
           ANSI_RESET);
    printf("║  Total NCCL calls made:  " ANSI_BOLD "%-30d" ANSI_RESET " ║\n", test_passed);
    printf("║  Total time:             " ANSI_BOLD "%-26.2f ms" ANSI_RESET " ║\n", total_ms);
    printf(ANSI_CYAN
           "╠══════════════════════════════════════════════════════════╣\n"
           ANSI_RESET);
    printf("║                                                        ║\n");
    printf("║  " ANSI_YELLOW "Check HoneyBeePF output for:" ANSI_RESET "                       ║\n");
    printf("║    1. All %d events captured (no drops)              ║\n", test_passed);
    printf("║    2. Correct op_type (AllReduce/Broadcast/...)        ║\n");
    printf("║    3. Correct count and datatype_size values           ║\n");
    printf("║    4. duration_ns > 0 for each event                   ║\n");
    printf("║    5. cgroup_id matches this process                   ║\n");
    printf("║    6. comm field shows 'test_nccl_upr' (truncated)     ║\n");
    printf("║                                                        ║\n");
    printf(ANSI_CYAN
           "╚══════════════════════════════════════════════════════════╝\n"
           ANSI_RESET "\n");

    /* Cleanup */
    if (fake_comm && p_ncclCommDestroy) {
        p_ncclCommDestroy(fake_comm);
    }
    dlclose(nccl_handle);
    return 0;
}