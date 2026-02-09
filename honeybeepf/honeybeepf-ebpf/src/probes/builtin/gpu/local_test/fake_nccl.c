/*
 * Fake NCCL Library for HoneyBeePF Uprobe Testing
 * =================================================
*/

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum {
    ncclSuccess            = 0,
    ncclUnhandledCudaError = 1,
    ncclInvalidArgument    = 2,
    ncclSystemError        = 3,
    ncclInternalError      = 4,
    ncclInvalidUsage       = 5,
    ncclRemoteError        = 6,
} ncclResult_t;

typedef enum {
    ncclInt8     = 0,
    ncclUint32   = 1,
    ncclInt32    = 2,
    ncclUint64   = 3,
    ncclInt64    = 4,
    ncclFloat16  = 5,
    ncclFloat32  = 6,
    ncclFloat64  = 7,
    ncclBfloat16 = 8,
} ncclDataType_t;

typedef enum {
    ncclSum  = 0,
    ncclProd = 1,
    ncclMax  = 2,
    ncclMin  = 3,
    ncclAvg  = 4,
} ncclRedOp_t;

typedef struct ncclComm* ncclComm_t;

#define NCCL_UNIQUE_ID_BYTES 128
typedef struct {
    char internal[NCCL_UNIQUE_ID_BYTES];
} ncclUniqueId;

/* Fake comm structure */
struct ncclComm {
    int rank;
    int nranks;
    int magic;  /* 0xDEAD for valid */
};

#define COMM_MAGIC 0xDEAD

/* ===== Helper: count 비례 fake latency ===== */
static void simulate_latency(size_t count) {
    int delay_us = 50;              /* base 50μs */
    if (count > 1024)      delay_us += 100;
    if (count > 1048576)   delay_us += 500;    /* 1M+ */
    if (count > 16777216)  delay_us += 2000;   /* 16M+ */
    usleep(delay_us);
}

static int is_valid_comm(ncclComm_t comm) {
    return comm && comm->magic == COMM_MAGIC;
}

/* ===== Version & Init ===== */

ncclResult_t ncclGetVersion(int* version) {
    if (!version) return ncclInvalidArgument;
    *version = 22105;  /* 2.21.5 */
    return ncclSuccess;
}

ncclResult_t ncclGetUniqueId(ncclUniqueId* uniqueId) {
    if (!uniqueId) return ncclInvalidArgument;
    memset(uniqueId->internal, 0, NCCL_UNIQUE_ID_BYTES);
    memcpy(uniqueId->internal, "FAKE_NCCL_HONEYBEEPF", 20);
    return ncclSuccess;
}

ncclResult_t ncclCommInitRank(ncclComm_t* comm, int nranks, ncclUniqueId commId, int rank) {
    (void)commId;
    if (!comm) return ncclInvalidArgument;
    if (rank < 0 || rank >= nranks) return ncclInvalidArgument;

    struct ncclComm* c = calloc(1, sizeof(struct ncclComm));
    if (!c) return ncclSystemError;

    c->rank = rank;
    c->nranks = nranks;
    c->magic = COMM_MAGIC;
    *comm = c;

    usleep(1000);  /* 1ms init delay */
    return ncclSuccess;
}

ncclResult_t ncclCommDestroy(ncclComm_t comm) {
    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    comm->magic = 0;
    free(comm);
    return ncclSuccess;
}

ncclResult_t ncclCommCount(const ncclComm_t comm, int* count) {
    if (!is_valid_comm(comm) || !count) return ncclInvalidArgument;
    *count = comm->nranks;
    return ncclSuccess;
}

ncclResult_t ncclCommUserRank(const ncclComm_t comm, int* rank) {
    if (!is_valid_comm(comm) || !rank) return ncclInvalidArgument;
    *rank = comm->rank;
    return ncclSuccess;
}

/* ===== Collective Operations ===== */

ncclResult_t ncclAllReduce(const void* sendbuff, void* recvbuff,
                           size_t count, ncclDataType_t datatype,
                           ncclRedOp_t op, ncclComm_t comm,
                           void* stream) {
    (void)sendbuff; (void)recvbuff; (void)datatype;
    (void)op; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

ncclResult_t ncclBroadcast(const void* sendbuff, void* recvbuff,
                           size_t count, ncclDataType_t datatype,
                           int root, ncclComm_t comm, void* stream) {
    (void)sendbuff; (void)recvbuff; (void)datatype;
    (void)root; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

ncclResult_t ncclAllGather(const void* sendbuff, void* recvbuff,
                           size_t count, ncclDataType_t datatype,
                           ncclComm_t comm, void* stream) {
    (void)sendbuff; (void)recvbuff; (void)datatype; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

ncclResult_t ncclReduceScatter(const void* sendbuff, void* recvbuff,
                               size_t count, ncclDataType_t datatype,
                               ncclRedOp_t op, ncclComm_t comm,
                               void* stream) {
    (void)sendbuff; (void)recvbuff; (void)datatype;
    (void)op; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

ncclResult_t ncclReduce(const void* sendbuff, void* recvbuff,
                        size_t count, ncclDataType_t datatype,
                        ncclRedOp_t op, int root,
                        ncclComm_t comm, void* stream) {
    (void)sendbuff; (void)recvbuff; (void)datatype;
    (void)op; (void)root; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

ncclResult_t ncclAllToAll(const void* sendbuff, void* recvbuff,
                          size_t count, ncclDataType_t datatype,
                          ncclComm_t comm, void* stream) {
    (void)sendbuff; (void)recvbuff; (void)datatype; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

/* ===== P2P Operations ===== */

ncclResult_t ncclSend(const void* sendbuff, size_t count,
                      ncclDataType_t datatype, int peer,
                      ncclComm_t comm, void* stream) {
    (void)sendbuff; (void)datatype; (void)peer; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

ncclResult_t ncclRecv(void* recvbuff, size_t count,
                      ncclDataType_t datatype, int peer,
                      ncclComm_t comm, void* stream) {
    (void)recvbuff; (void)datatype; (void)peer; (void)stream;

    simulate_latency(count);

    if (!is_valid_comm(comm)) return ncclInvalidArgument;
    return ncclSuccess;
}

/* ===== Group Operations ===== */

ncclResult_t ncclGroupStart(void) {
    return ncclSuccess;
}

ncclResult_t ncclGroupEnd(void) {
    usleep(100);  /* small delay to simulate group flush */
    return ncclSuccess;
}