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
 * GlobalPlatform TEE Client API (REE side) for Trusty.
 *
 * Public surface matches the GP TEE Client API specification so that existing
 * client source (incl. OP-TEE's) compiles unchanged. The struct internals are
 * implementation-defined (the spec permits this) and here carry the Trusty
 * transport state: a libtrusty device name and a per-session TIPC fd. The wire
 * format is <gptee_ipc.h>; sessions are reached at port "gpta.<uuid>".
 */

#ifndef TEE_CLIENT_API_H
#define TEE_CLIENT_API_H

#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t TEEC_Result;

/* Return codes (GP TEE Client API). */
#define TEEC_SUCCESS 0x00000000
#define TEEC_ERROR_GENERIC 0xFFFF0000
#define TEEC_ERROR_ACCESS_DENIED 0xFFFF0001
#define TEEC_ERROR_CANCEL 0xFFFF0002
#define TEEC_ERROR_ACCESS_CONFLICT 0xFFFF0003
#define TEEC_ERROR_EXCESS_DATA 0xFFFF0004
#define TEEC_ERROR_BAD_FORMAT 0xFFFF0005
#define TEEC_ERROR_BAD_PARAMETERS 0xFFFF0006
#define TEEC_ERROR_BAD_STATE 0xFFFF0007
#define TEEC_ERROR_ITEM_NOT_FOUND 0xFFFF0008
#define TEEC_ERROR_NOT_IMPLEMENTED 0xFFFF0009
#define TEEC_ERROR_NOT_SUPPORTED 0xFFFF000A
#define TEEC_ERROR_NO_DATA 0xFFFF000B
#define TEEC_ERROR_OUT_OF_MEMORY 0xFFFF000C
#define TEEC_ERROR_BUSY 0xFFFF000D
#define TEEC_ERROR_COMMUNICATION 0xFFFF000E
#define TEEC_ERROR_SECURITY 0xFFFF000F
#define TEEC_ERROR_SHORT_BUFFER 0xFFFF0010
#define TEEC_ERROR_EXTERNAL_CANCEL 0xFFFF0011
#define TEEC_ERROR_TARGET_DEAD 0xFFFF3024
#define TEEC_ERROR_STORAGE_NOT_AVAILABLE 0xF0100003
#define TEEC_ERROR_STORAGE_NO_SPACE 0xFFFF3041

/* Return-code origins. */
#define TEEC_ORIGIN_API 0x00000001
#define TEEC_ORIGIN_COMMS 0x00000002
#define TEEC_ORIGIN_TEE 0x00000003
#define TEEC_ORIGIN_TRUSTED_APP 0x00000004

/* Parameter types (numerically identical to GP TEE_PARAM_TYPE_* by design). */
#define TEEC_NONE 0x00000000
#define TEEC_VALUE_INPUT 0x00000001
#define TEEC_VALUE_OUTPUT 0x00000002
#define TEEC_VALUE_INOUT 0x00000003
#define TEEC_MEMREF_TEMP_INPUT 0x00000005
#define TEEC_MEMREF_TEMP_OUTPUT 0x00000006
#define TEEC_MEMREF_TEMP_INOUT 0x00000007
#define TEEC_MEMREF_WHOLE 0x0000000C
#define TEEC_MEMREF_PARTIAL_INPUT 0x0000000D
#define TEEC_MEMREF_PARTIAL_OUTPUT 0x0000000E
#define TEEC_MEMREF_PARTIAL_INOUT 0x0000000F

/* Shared memory control flags. */
#define TEEC_MEM_INPUT 0x00000001
#define TEEC_MEM_OUTPUT 0x00000002

/* Login methods. */
#define TEEC_LOGIN_PUBLIC 0x00000000
#define TEEC_LOGIN_USER 0x00000001
#define TEEC_LOGIN_GROUP 0x00000002
#define TEEC_LOGIN_APPLICATION 0x00000004
#define TEEC_LOGIN_USER_APPLICATION 0x00000005
#define TEEC_LOGIN_GROUP_APPLICATION 0x00000006

#define TEEC_PARAM_TYPES(p0, p1, p2, p3) ((p0) | ((p1) << 4) | ((p2) << 8) | ((p3) << 12))
#define TEEC_PARAM_TYPE_GET(p, i) (((p) >> ((i) * 4)) & 0xF)

#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4
#define TEEC_CONFIG_SHAREDMEM_MAX_SIZE ULONG_MAX

typedef struct {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
} TEEC_UUID;

typedef struct {
    /*
     * libtrusty device node, e.g. "/dev/trusty-ipc-dev0".
     * Owned by the context (strdup'd in InitializeContext, freed in
     * FinalizeContext). Callers must not free or modify it.
     */
    char* dev;
} TEEC_Context;

typedef struct {
    TEEC_Context* ctx;
    int fd;               /* TIPC channel fd for this session */
    pthread_mutex_t lock; /* GP 3.3.2: Per-session mutex for thread safety */
    uint8_t lock_initialized;
} TEEC_Session;

typedef struct {
    void* buffer;
    size_t size;
    uint32_t flags;
    /* implementation-defined below */
    int id;
    uint8_t allocated;
} TEEC_SharedMemory;

typedef struct {
    void* buffer;
    size_t size;
} TEEC_TempMemoryReference;

typedef struct {
    TEEC_SharedMemory* parent;
    size_t size;
    size_t offset;
} TEEC_RegisteredMemoryReference;

typedef struct {
    uint32_t a;
    uint32_t b;
} TEEC_Value;

typedef union {
    TEEC_TempMemoryReference tmpref;
    TEEC_RegisteredMemoryReference memref;
    TEEC_Value value;
} TEEC_Parameter;

typedef struct {
    uint32_t started;
    uint32_t paramTypes;
    TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
    /* implementation-defined session backref */
    TEEC_Session* session;
} TEEC_Operation;

TEEC_Result TEEC_InitializeContext(const char* name, TEEC_Context* context);

void TEEC_FinalizeContext(TEEC_Context* context);

TEEC_Result TEEC_OpenSession(TEEC_Context* context, TEEC_Session* session,
                             const TEEC_UUID* destination, uint32_t connectionMethod,
                             const void* connectionData, TEEC_Operation* operation,
                             uint32_t* returnOrigin);

void TEEC_CloseSession(TEEC_Session* session);

TEEC_Result TEEC_InvokeCommand(TEEC_Session* session, uint32_t commandID, TEEC_Operation* operation,
                               uint32_t* returnOrigin);

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context* context, TEEC_SharedMemory* sharedMem);

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context* context, TEEC_SharedMemory* sharedMem);

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory* sharedMem);

void TEEC_RequestCancellation(TEEC_Operation* operation);

#ifdef __cplusplus
}
#endif

#endif /* TEE_CLIENT_API_H */
