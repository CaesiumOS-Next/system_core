/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * REE-side GP TEE Client API over Trusty libtrusty/TIPC.
 *
 * Each TEEC_Session is a TIPC channel (fd) to port "gpta.<uuid>". Operations
 * marshal the 4 TEEC params into <gptee_ipc.h> and exchange one request/one
 * response per call, mirroring the TA-side runtime in gptee_entry.c. VALUE_*,
 * temporary memrefs, and registered/whole/partial shared memory are supported.
 * Cancellation is not supported.
 *
 * PUBLIC, USER, and GROUP identities are accepted only when the Trusty kernel
 * driver authenticates the login descriptor. Application-based login methods
 * remain unsupported until Android defines a reviewed package identity policy.
 *
 * Build context: this compiles in the Android/Linux tree and links libtrusty
 * (system/core/trusty/libtrusty). It is NOT part of the Trusty TEE image.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/dma-heap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <trusty/ipc.h>  /* struct trusty_shm, TRUSTY_SHARE */
#include <trusty/tipc.h> /* tipc_connect(), tipc_send() */

#include <gptee_ipc.h>
#include <tee_client_api.h>

#define DEFAULT_TIPC_DEV "/dev/trusty-ipc-dev0"

/*
 * Memrefs at or below this size travel inline in the request (one IPC message,
 * capped at 4 KB). Larger memrefs are transferred zero-copy-ish through a
 * dmabuf shared with Trusty (allocated here, copied in/out around the call).
 * Kept small enough that up to 4 inline memrefs plus the header fit in 4 KB.
 */
#define GPTEE_INLINE_MAX 512
#define DMA_HEAP_DEV "/dev/dma_heap/system"
/*
 * Query the actual system page size rather than hardcoding 4096.
 * ARM64 can use 16K or 64K pages; a hardcoded round-up wastes memory or,
 * on smaller-than-assumed pages, produces unaligned allocations.
 */
static size_t page_size(void) {
    static size_t ps;
    if (!ps) {
        long v = sysconf(_SC_PAGESIZE);
        ps = (v > 0 && (size_t)(v & (v - 1)) == 0) ? (size_t)v : 4096;
    }
    return ps;
}
static inline size_t PAGE_ROUNDUP(size_t x) {
    size_t ps = page_size();

    if (x > SIZE_MAX - (ps - 1)) return 0;
    return (x + ps - 1) & ~(ps - 1);
}

static void uuid_to_port(const TEEC_UUID* u, char out[GPTEE_PORT_NAME_MAX]) {
    gptee_uuid_to_port(u, out);
}

static uint32_t param_type(uint32_t param_types, uint32_t i) {
    return (param_types >> (i * 4)) & 0xF;
}

static bool size_to_u32(size_t size, uint32_t* out) {
    if (size > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)size;
    return true;
}

static bool teec_param_type_valid(uint32_t t) {
    return t == TEEC_NONE || t == TEEC_VALUE_INPUT || t == TEEC_VALUE_OUTPUT ||
           t == TEEC_VALUE_INOUT || t == TEEC_MEMREF_TEMP_INPUT || t == TEEC_MEMREF_TEMP_OUTPUT ||
           t == TEEC_MEMREF_TEMP_INOUT || t == TEEC_MEMREF_WHOLE ||
           t == TEEC_MEMREF_PARTIAL_INPUT || t == TEEC_MEMREF_PARTIAL_OUTPUT ||
           t == TEEC_MEMREF_PARTIAL_INOUT;
}

static bool mem_flags_valid(uint32_t flags) {
    return (flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)) == 0;
}

static bool has_required_parent_flags(uint32_t parent_flags, uint32_t t) {
    switch (t) {
        case TEEC_MEMREF_PARTIAL_INPUT:
            return (parent_flags & TEEC_MEM_INPUT) != 0;
        case TEEC_MEMREF_PARTIAL_OUTPUT:
            return (parent_flags & TEEC_MEM_OUTPUT) != 0;
        case TEEC_MEMREF_PARTIAL_INOUT:
            return (parent_flags & (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)) ==
                   (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT);
        default:
            return true;
    }
}

static TEEC_Result validate_operation(const TEEC_Operation* op) {
    uint32_t i;

    if (!op) {
        return TEEC_SUCCESS;
    }
    for (i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
        uint32_t t = param_type(op->paramTypes, i);

        if (!teec_param_type_valid(t)) {
            return TEEC_ERROR_BAD_PARAMETERS;
        }
        switch (t) {
            case TEEC_MEMREF_TEMP_INPUT:
            case TEEC_MEMREF_TEMP_OUTPUT:
            case TEEC_MEMREF_TEMP_INOUT:
                if (op->params[i].tmpref.size && !op->params[i].tmpref.buffer) {
                    return TEEC_ERROR_BAD_PARAMETERS;
                }
                if (op->params[i].tmpref.size > UINT32_MAX) {
                    return TEEC_ERROR_BAD_PARAMETERS;
                }
                break;
            case TEEC_MEMREF_WHOLE: {
                const TEEC_SharedMemory* p = op->params[i].memref.parent;

                if (!p || !mem_flags_valid(p->flags) ||
                    !(p->flags & (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT))) {
                    return TEEC_ERROR_BAD_PARAMETERS;
                }
                if (p->size && !p->buffer) {
                    return TEEC_ERROR_BAD_PARAMETERS;
                }
                if (p->size > UINT32_MAX) {
                    return TEEC_ERROR_BAD_PARAMETERS;
                }
                break;
            }
            case TEEC_MEMREF_PARTIAL_INPUT:
            case TEEC_MEMREF_PARTIAL_OUTPUT:
            case TEEC_MEMREF_PARTIAL_INOUT: {
                const TEEC_SharedMemory* p = op->params[i].memref.parent;
                size_t off = op->params[i].memref.offset;
                size_t size = op->params[i].memref.size;

                if (!p || !mem_flags_valid(p->flags) || !has_required_parent_flags(p->flags, t)) {
                    return TEEC_ERROR_BAD_PARAMETERS;
                }
                if (p->size && !p->buffer) return TEEC_ERROR_BAD_PARAMETERS;
                if (off > p->size || size > p->size - off) return TEEC_ERROR_BAD_PARAMETERS;
                if (size > UINT32_MAX) return TEEC_ERROR_BAD_PARAMETERS;
                break;
            }
            default:
                break;
        }
    }
    return TEEC_SUCCESS;
}

/*
 * Resolve a memref parameter (tmpref or registered whole/partial) to its
 * buffer, size and direction, and the GP wire param-type to send. Returns 0 if
 * the slot is not a memref.
 */
static int memref_resolve(const TEEC_Operation* op, int i, uint8_t** buf, size_t* size, int* is_in,
                          int* is_out, uint32_t* gp_attr) {
    uint32_t t = param_type(op->paramTypes, i);

    switch (t) {
        case TEEC_MEMREF_TEMP_INPUT:
        case TEEC_MEMREF_TEMP_OUTPUT:
        case TEEC_MEMREF_TEMP_INOUT:
            *buf = op->params[i].tmpref.buffer;
            *size = op->params[i].tmpref.size;
            *is_in = (t != TEEC_MEMREF_TEMP_OUTPUT);
            *is_out = (t != TEEC_MEMREF_TEMP_INPUT);
            break;
        case TEEC_MEMREF_WHOLE:
        case TEEC_MEMREF_PARTIAL_INPUT:
        case TEEC_MEMREF_PARTIAL_OUTPUT:
        case TEEC_MEMREF_PARTIAL_INOUT: {
            TEEC_SharedMemory* p = op->params[i].memref.parent;

            if (!p) return 0;
            if (t == TEEC_MEMREF_WHOLE) {
                *buf = p->buffer;
                *size = p->size;
                *is_in = (p->flags & TEEC_MEM_INPUT) != 0;
                *is_out = (p->flags & TEEC_MEM_OUTPUT) != 0;
            } else {
                /*
                 * partial memref — the offset and size are caller-
                 * controlled. Prove they stay within the parent buffer before
                 * doing pointer arithmetic. Use the subtraction form to avoid
                 * unsigned wraparound: a huge offset (e.g. near-SIZE_MAX)
                 * would wrap the addition but is caught by the first check;
                 * offset+size <= p->size is checked via the second.
                 */
                size_t off = op->params[i].memref.offset;
                size_t sz = op->params[i].memref.size;
                if (off > p->size || sz > p->size - off) return 0;
                *buf = (uint8_t*)p->buffer + off;
                *size = sz;
                *is_in = (t != TEEC_MEMREF_PARTIAL_OUTPUT);
                *is_out = (t != TEEC_MEMREF_PARTIAL_INPUT);
            }
            break;
        }
        default:
            return 0;
    }

    if (*is_in && *is_out)
        *gp_attr = TEEC_MEMREF_TEMP_INOUT; /* == GP MEMREF_INOUT */
    else if (*is_out)
        *gp_attr = TEEC_MEMREF_TEMP_OUTPUT;
    else
        *gp_attr = TEEC_MEMREF_TEMP_INPUT;
    return 1;
}

/* Allocate a dmabuf and mmap it. Returns fd (>=0); sets the map and length. */
static int dmabuf_alloc(size_t size, void** map, size_t* map_len) {
    struct dma_heap_allocation_data data = {0};
    int heap = open(DMA_HEAP_DEV, O_RDONLY | O_CLOEXEC);
    int fd;
    void* m;

    if (heap < 0) return -1;
    data.len = PAGE_ROUNDUP(size ? size : 1);
    if (!data.len) {
        close(heap);
        return -1;
    }
    data.fd_flags = O_RDWR | O_CLOEXEC;
    if (ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &data) < 0) {
        close(heap);
        return -1;
    }
    close(heap);
    fd = (int)data.fd;
    m = mmap(NULL, data.len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        close(fd);
        return -1;
    }
    *map = m;
    *map_len = data.len;
    return fd;
}

/* Per-memref dmabuf bookkeeping for the duration of one transaction. */
struct shmslot {
    int param;
    int fd;
    void* map;
    size_t map_len;
    uint8_t* user_buf;
    size_t size;
    int is_out;
    int is_preallocated_dma;
};

/* Send one request and read one response on @fd. */
static TEEC_Result transact(int fd, uint32_t opclass, uint32_t cmd_id, uint32_t login_method,
                            const void* connection_data, TEEC_Operation* op, uint32_t* ret_origin,
                            uint32_t* out_session) {
    /*
     * unions ensure correct alignment for wire header structs,
     * avoiding the UB of casting a uint8_t[] to a struct pointer.
     */
    union {
        struct gptee_msg_hdr hdr;
        uint8_t raw[sizeof(struct gptee_msg_hdr) + 4 * GPTEE_INLINE_MAX];
    } req_buf;
    union {
        struct gptee_resp_hdr hdr;
        uint8_t raw[sizeof(struct gptee_resp_hdr) + 4 * GPTEE_INLINE_MAX];
    } resp_buf;
    struct gptee_msg_hdr* hdr = &req_buf.hdr;
    struct gptee_resp_hdr* resp = &resp_buf.hdr;
    struct shmslot slots[TEEC_CONFIG_PAYLOAD_REF_COUNT];
    struct trusty_shm shms[TEEC_CONFIG_PAYLOAD_REF_COUNT];
    uint32_t pt = op ? op->paramTypes : 0;
    size_t off = 0;
    size_t recv_data = 0;
    int nshm = 0;
    int response_ok = 0;
    int i;
    struct iovec iov;
    TEEC_Result res = TEEC_ERROR_COMMUNICATION;
    ssize_t rc;

    memset(req_buf.raw, 0, sizeof(req_buf.hdr));
    memset(resp_buf.raw, 0, sizeof(resp_buf.hdr));
    hdr->op = opclass;
    hdr->cmd_id = cmd_id;
    hdr->param_types = pt;
    hdr->protocol = GPTEE_PROTOCOL_ID;
    if (opclass == GPTEE_OP_OPEN_SESSION) {
        hdr->session = login_method;
        if (login_method == TEEC_LOGIN_GROUP) {
            /*
             * The requested gid is only input to the kernel policy check.
             * The Trusty IPC driver verifies group membership and overwrites
             * this entire field with the credential-derived client UUID.
             */
            memcpy(&hdr->client_uuid, connection_data, sizeof(uint32_t));
        }
    }

    res = validate_operation(op);
    if (res != TEEC_SUCCESS) {
        if (ret_origin) *ret_origin = TEEC_ORIGIN_API;
        goto cleanup;
    }

    /* ---- marshal request ---- */
    for (i = 0; op && i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
        uint32_t t = param_type(pt, i);
        uint8_t* buf = NULL;
        size_t size = 0;
        int is_in = 0, is_out = 0;
        uint32_t gp_attr = t;
        uint32_t wire_size;

        if (t == TEEC_VALUE_INPUT || t == TEEC_VALUE_INOUT) {
            hdr->params[i].attr = t;
            hdr->params[i].u.value.a = op->params[i].value.a;
            hdr->params[i].u.value.b = op->params[i].value.b;
            continue;
        }
        if (t == TEEC_VALUE_OUTPUT) {
            hdr->params[i].attr = t;
            continue;
        }
        if (!memref_resolve(op, i, &buf, &size, &is_in, &is_out, &gp_attr)) {
            hdr->params[i].attr = t; /* NONE */
            continue;
        }

        /* Reflect the resolved GP memref type into the wire param_types. */
        hdr->param_types = (hdr->param_types & ~(0xFu << (i * 4))) | (gp_attr << (i * 4));
        hdr->params[i].attr = gp_attr;
        if (!size_to_u32(size, &wire_size)) {
            res = TEEC_ERROR_BAD_PARAMETERS;
            if (ret_origin) *ret_origin = TEEC_ORIGIN_API;
            goto cleanup;
        }
        hdr->params[i].u.memref.size = wire_size;

        if (size <= GPTEE_INLINE_MAX) {
            /* Inline: input bytes follow the header. */
            if (is_in && size) {
                memcpy(req_buf.raw + sizeof(req_buf.hdr) + off, buf, size);
                off += size;
            }
        } else {
            TEEC_SharedMemory* p = NULL;
            if (t == TEEC_MEMREF_WHOLE || t == TEEC_MEMREF_PARTIAL_INPUT ||
                t == TEEC_MEMREF_PARTIAL_OUTPUT || t == TEEC_MEMREF_PARTIAL_INOUT) {
                p = op->params[i].memref.parent;
            }

            if (p && p->allocated == 2 &&
                (t == TEEC_MEMREF_WHOLE ||
                 (op->params[i].memref.offset == 0 && op->params[i].memref.size == p->size))) {
                /* Preallocated DMA buffer used as a WHOLE memory reference! Zero copy! */
                int dfd = p->id;
                hdr->params[i].u.memref.flags = GPTEE_MEMREF_HANDLE;
                slots[nshm].param = i;
                slots[nshm].fd = dfd;
                slots[nshm].map = NULL;
                slots[nshm].map_len = 0;
                slots[nshm].user_buf = buf;
                slots[nshm].size = size;
                slots[nshm].is_out = is_out;
                slots[nshm].is_preallocated_dma = 1;
                shms[nshm].fd = dfd;
                shms[nshm].transfer = TRUSTY_SHARE;
                nshm++;
            } else {
                /* Shared dmabuf: copy input in, attach handle. */
                void* map = NULL;
                size_t map_len = 0;
                int dfd = dmabuf_alloc(size, &map, &map_len);

                if (dfd < 0) {
                    res = TEEC_ERROR_OUT_OF_MEMORY;
                    if (ret_origin) *ret_origin = TEEC_ORIGIN_API;
                    goto cleanup;
                }
                if (is_in && size) memcpy(map, buf, size);
                hdr->params[i].u.memref.flags = GPTEE_MEMREF_HANDLE;
                slots[nshm].param = i;
                slots[nshm].fd = dfd;
                slots[nshm].map = map;
                slots[nshm].map_len = map_len;
                slots[nshm].user_buf = buf;
                slots[nshm].size = size;
                slots[nshm].is_out = is_out;
                slots[nshm].is_preallocated_dma = 0;
                shms[nshm].fd = dfd;
                shms[nshm].transfer = TRUSTY_SHARE;
                nshm++;
            }
        }
    }
    if (!size_to_u32(off, &hdr->data_len)) {
        res = TEEC_ERROR_BAD_PARAMETERS;
        if (ret_origin) *ret_origin = TEEC_ORIGIN_API;
        goto cleanup;
    }

    /* ---- send (with handles) + receive ---- */
    iov.iov_base = req_buf.raw;
    iov.iov_len = sizeof(req_buf.hdr) + off;
    rc = tipc_send(fd, &iov, 1, nshm ? shms : NULL, nshm);
    if (rc < 0 || (size_t)rc != iov.iov_len) {
        if (opclass == GPTEE_OP_OPEN_SESSION && rc < 0) {
            if (errno == EACCES || errno == EPERM) {
                res = TEEC_ERROR_ACCESS_DENIED;
                if (ret_origin) *ret_origin = TEEC_ORIGIN_API;
                goto cleanup;
            }
            if (errno == EOPNOTSUPP) {
                res = TEEC_ERROR_NOT_SUPPORTED;
                if (ret_origin) *ret_origin = TEEC_ORIGIN_API;
                goto cleanup;
            }
        }
        if (ret_origin) *ret_origin = TEEC_ORIGIN_COMMS;
        goto cleanup;
    }

    rc = read(fd, resp_buf.raw, sizeof(resp_buf.raw));
    if (rc < 0 || (size_t)rc < sizeof(struct gptee_resp_hdr)) {
        if (ret_origin) *ret_origin = TEEC_ORIGIN_TEE;
        res = TEEC_ERROR_TARGET_DEAD;
        goto cleanup;
    }

    /*
     * bound the response decode by the bytes actually received
     * (rc - header), not the peer-declared resp->data_len. A TA that
     * over-declares data_len must not make the client copy bytes beyond the
     * received message (the uninitialised resp_buf.raw tail) into the user buffer.
     */
    recv_data = (size_t)rc - sizeof(struct gptee_resp_hdr);
    if (resp->protocol != GPTEE_PROTOCOL_ID || resp->data_len != recv_data) {
        if (ret_origin) *ret_origin = TEEC_ORIGIN_COMMS;
        goto cleanup;
    }
    if (op && resp->return_origin == TEEC_ORIGIN_TRUSTED_APP) {
        off = 0;
        for (i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
            uint32_t t = param_type(pt, i);
            uint8_t* buf = NULL;
            size_t size = 0;
            int is_in = 0, is_out = 0;
            uint32_t gp_attr = t;

            if (t == TEEC_VALUE_OUTPUT || t == TEEC_VALUE_INOUT) {
                if (resp->params[i].attr != t) {
                    if (ret_origin) *ret_origin = TEEC_ORIGIN_COMMS;
                    res = TEEC_ERROR_COMMUNICATION;
                    goto cleanup;
                }
                continue;
            }
            if (!memref_resolve(op, i, &buf, &size, &is_in, &is_out, &gp_attr)) continue;
            if (resp->params[i].attr != gp_attr) {
                if (ret_origin) *ret_origin = TEEC_ORIGIN_COMMS;
                res = TEEC_ERROR_COMMUNICATION;
                goto cleanup;
            }
            if (!is_out) continue;
            if (size <= GPTEE_INLINE_MAX) {
                uint32_t written = resp->params[i].u.memref.size;
                size_t copy =
                        (resp->result == TEEC_SUCCESS) ? (written < size ? written : size) : 0;

                if (off > resp->data_len || copy > resp->data_len - off) {
                    if (ret_origin) *ret_origin = TEEC_ORIGIN_COMMS;
                    res = TEEC_ERROR_COMMUNICATION;
                    goto cleanup;
                }
                off += copy;
            }
        }
        if (off != resp->data_len) {
            if (ret_origin) *ret_origin = TEEC_ORIGIN_COMMS;
            res = TEEC_ERROR_COMMUNICATION;
            goto cleanup;
        }
    }
    response_ok = 1;

    /* ---- apply response ---- */
    off = 0;
    for (i = 0;
         op && resp->return_origin == TEEC_ORIGIN_TRUSTED_APP && i < TEEC_CONFIG_PAYLOAD_REF_COUNT;
         i++) {
        uint32_t t = param_type(pt, i);
        uint8_t* buf = NULL;
        size_t size = 0;
        int is_in = 0, is_out = 0;
        uint32_t gp_attr = t;

        if (t == TEEC_VALUE_OUTPUT || t == TEEC_VALUE_INOUT) {
            op->params[i].value.a = resp->params[i].u.value.a;
            op->params[i].value.b = resp->params[i].u.value.b;
            continue;
        }
        if (!memref_resolve(op, i, &buf, &size, &is_in, &is_out, &gp_attr)) continue;
        if (!is_out) continue;

        {
            uint32_t written = resp->params[i].u.memref.size;

            /* Inline outputs come back in the response data region. */
            if (size <= GPTEE_INLINE_MAX) {
                size_t copy =
                        (resp->result == TEEC_SUCCESS) ? (written < size ? written : size) : 0;

                /* bound by the received span, not resp->data_len. */
                if (copy) {
                    memcpy(buf, resp_buf.raw + sizeof(resp_buf.hdr) + off, copy);
                }
                off += copy;
            }
            /* (Handle outputs were written straight into the dmabuf; copied
             * back to the user buffer during cleanup below.) */
            /* Report the size the TA produced. */
            if (param_type(pt, i) == TEEC_MEMREF_TEMP_OUTPUT ||
                param_type(pt, i) == TEEC_MEMREF_TEMP_INOUT)
                op->params[i].tmpref.size = written;
            else
                op->params[i].memref.size = written;
        }
    }

    if (out_session) *out_session = resp->session;
    if (ret_origin) *ret_origin = resp->return_origin;
    res = resp->result;

cleanup:
    /*
     * validate each shared-memory slot against the response before
     * copying output bytes back into the user buffer. The param index is
     * already bounds-checked (i < TEEC_CONFIG_PAYLOAD_REF_COUNT) at
     * registration time; here we additionally verify the response slot
     * carries a memref that permits output.
     */
    for (i = 0; i < nshm; i++) {
        if (slots[i].is_preallocated_dma) continue;
        uint32_t slot_param = slots[i].param;
        uint32_t resp_attr = resp->params[slot_param].attr;
        int resp_is_out =
                (resp_attr == TEEC_MEMREF_TEMP_OUTPUT || resp_attr == TEEC_MEMREF_TEMP_INOUT);
        if (response_ok && resp->return_origin == TEEC_ORIGIN_TRUSTED_APP &&
            resp->result == TEEC_SUCCESS && slots[i].is_out && resp_is_out) {
            uint32_t written = resp->params[slot_param].u.memref.size;
            size_t copy = written < slots[i].size ? written : slots[i].size;

            if (copy) memcpy(slots[i].user_buf, slots[i].map, copy);
        }
        munmap(slots[i].map, slots[i].map_len);
        close(slots[i].fd);
    }
    return res;
}

TEEC_Result TEEC_InitializeContext(const char* name, TEEC_Context* context) {
    const char* device;

    if (!context) return TEEC_ERROR_BAD_PARAMETERS;
    context->dev = NULL;
    if (name && strcmp(name, DEFAULT_TIPC_DEV) != 0 && strcmp(name, "trusty") != 0)
        return TEEC_ERROR_ITEM_NOT_FOUND;

    device = (!name || strcmp(name, "trusty") == 0) ? DEFAULT_TIPC_DEV : name;
    context->dev = strdup(device);
    if (!context->dev) return TEEC_ERROR_OUT_OF_MEMORY;
    return TEEC_SUCCESS;
}

void TEEC_FinalizeContext(TEEC_Context* context) {
    if (context) free(context->dev);
    if (context) context->dev = NULL;
}

TEEC_Result TEEC_OpenSession(TEEC_Context* context, TEEC_Session* session,
                             const TEEC_UUID* destination, uint32_t connectionMethod,
                             const void* connectionData, TEEC_Operation* operation,
                             uint32_t* returnOrigin) {
    char port[GPTEE_PORT_NAME_MAX];
    TEEC_Result res;
    int fd;

    if (!context || !context->dev || !session || !destination) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    /*
     * output handle is initialized to inert state before any
     * fallible operation. On error the caller finds a safe, recognisable
     * sentinel (ctx=NULL, fd=-1), not uninitialised memory.
     */
    session->ctx = NULL;
    session->fd = -1;
    session->lock_initialized = 0;

    if (connectionMethod != TEEC_LOGIN_PUBLIC && connectionMethod != TEEC_LOGIN_USER &&
        connectionMethod != TEEC_LOGIN_GROUP) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_NOT_SUPPORTED;
    }
    if ((connectionMethod == TEEC_LOGIN_GROUP && !connectionData) ||
        (connectionMethod != TEEC_LOGIN_GROUP && connectionData)) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    uuid_to_port(destination, port);
    int retries = 20;
    do {
        fd = tipc_connect(context->dev, port);
        if (fd >= 0) {
            break;
        }
        usleep(10000);
    } while (--retries > 0);

    if (fd < 0) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_COMMS;
        return TEEC_ERROR_COMMUNICATION;
    }

    session->ctx = context;
    session->fd = fd;
    if (pthread_mutex_init(&session->lock, NULL) != 0) {
        close(fd);
        session->ctx = NULL;
        session->fd = -1;
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_OUT_OF_MEMORY;
    }
    session->lock_initialized = 1;

    res = transact(fd, GPTEE_OP_OPEN_SESSION, 0, connectionMethod, connectionData, operation,
                   returnOrigin, NULL);
    if (res != TEEC_SUCCESS) {
        close(fd);
        session->ctx = NULL;
        session->fd = -1;
        pthread_mutex_destroy(&session->lock);
        session->lock_initialized = 0;
    }
    return res;
}

void TEEC_CloseSession(TEEC_Session* session) {
    if (!session || session->fd < 0 || !session->lock_initialized) return;
    if (pthread_mutex_lock(&session->lock) != 0) return;
    transact(session->fd, GPTEE_OP_CLOSE_SESSION, 0, TEEC_LOGIN_PUBLIC, NULL, NULL, NULL, NULL);
    close(session->fd);
    session->fd = -1;
    session->ctx = NULL;
    pthread_mutex_unlock(&session->lock);
    pthread_mutex_destroy(&session->lock);
    session->lock_initialized = 0;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session* session, uint32_t commandID, TEEC_Operation* operation,
                               uint32_t* returnOrigin) {
    TEEC_Result result;

    if (!session || session->fd < 0 || !session->lock_initialized) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_PARAMETERS;
    }
    if (pthread_mutex_lock(&session->lock) != 0) {
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_GENERIC;
    }
    if (session->fd < 0) {
        pthread_mutex_unlock(&session->lock);
        if (returnOrigin) *returnOrigin = TEEC_ORIGIN_API;
        return TEEC_ERROR_BAD_STATE;
    }
    if (operation) {
        operation->started = 1;
        operation->session = session;
    }
    result = transact(session->fd, GPTEE_OP_INVOKE_COMMAND, commandID, TEEC_LOGIN_PUBLIC, NULL,
                      operation, returnOrigin, NULL);
    if (operation) {
        operation->started = 0;
        operation->session = NULL;
    }
    pthread_mutex_unlock(&session->lock);
    return result;
}

/*
 * Registered buffers stay caller-owned. Allocated buffers use dma-heap so
 * large memrefs can be passed to Trusty as TIPC handles without another
 * temporary dma-buf allocation.
 */
TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context* context, TEEC_SharedMemory* sharedMem) {
    if (!context || !context->dev || !sharedMem || !mem_flags_valid(sharedMem->flags) ||
        !(sharedMem->flags & (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)) ||
        (sharedMem->size && !sharedMem->buffer))
        return TEEC_ERROR_BAD_PARAMETERS;
    /* lifecycle fields set to canonical sentinel values at entry. */
    sharedMem->id = 0;
    sharedMem->allocated = 0;
    return TEEC_SUCCESS;
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context* context, TEEC_SharedMemory* sharedMem) {
    if (!context || !context->dev || !sharedMem || !mem_flags_valid(sharedMem->flags) ||
        !(sharedMem->flags & (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
        return TEEC_ERROR_BAD_PARAMETERS;

    /* lifecycle fields initialized before allocation attempt. */
    sharedMem->buffer = NULL;
    sharedMem->id = 0;
    sharedMem->allocated = 0;

    void* map = NULL;
    size_t map_len = 0;
    int dfd = dmabuf_alloc(sharedMem->size, &map, &map_len);
    if (dfd < 0) {
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    sharedMem->buffer = map;
    sharedMem->id = dfd;
    sharedMem->allocated = 2; /* 2: preallocated DMA buffer */
    return TEEC_SUCCESS;
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory* sharedMem) {
    if (sharedMem && sharedMem->allocated) {
        if (sharedMem->allocated == 2) {
            size_t map_len = PAGE_ROUNDUP(sharedMem->size ? sharedMem->size : 1);
            munmap(sharedMem->buffer, map_len);
            close(sharedMem->id);
        } else {
            free(sharedMem->buffer);
        }
        sharedMem->buffer = NULL;
        sharedMem->id = 0;
        sharedMem->allocated = 0;
        /* set size to 0 on release. */
        sharedMem->size = 0;
    }
}

void TEEC_RequestCancellation(TEEC_Operation* operation) {
    /* TODO(P4): cancellation support. */
    (void)operation;
}
