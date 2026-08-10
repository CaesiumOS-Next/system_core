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
 * REE-side negative tests for gptee libteec. These cases must fail in the
 * Client API layer with TEEC_ORIGIN_API instead of crashing or reaching a TA.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

static const TEEC_UUID kSampleUUID = {
        0x8aaaf200, 0x2450, 0x11e4, {0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};

#define TA_CMD_INC 0

static int failures;

static void expect_result(const char* name, TEEC_Result got, TEEC_Result want, uint32_t origin,
                          uint32_t want_origin) {
    if (got == want && origin == want_origin) {
        printf("[ OK ] %s -> 0x%08x origin %u\n", name, got, origin);
        return;
    }
    printf("[FAIL] %s -> 0x%08x origin %u, want 0x%08x origin %u\n", name, got, origin, want,
           want_origin);
    failures++;
}

static void test_context_and_session_api(TEEC_Context* ctx) {
    TEEC_Session sess;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, NULL);
    expect_result("InitializeContext NULL context", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    origin = 0;
    res = TEEC_OpenSession(NULL, &sess, &kSampleUUID, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    expect_result("OpenSession NULL context", res, TEEC_ERROR_BAD_PARAMETERS, origin,
                  TEEC_ORIGIN_API);

    origin = 0;
    res = TEEC_OpenSession(ctx, NULL, &kSampleUUID, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    expect_result("OpenSession NULL session", res, TEEC_ERROR_BAD_PARAMETERS, origin,
                  TEEC_ORIGIN_API);

    origin = 0;
    res = TEEC_OpenSession(ctx, &sess, NULL, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    expect_result("OpenSession NULL destination", res, TEEC_ERROR_BAD_PARAMETERS, origin,
                  TEEC_ORIGIN_API);

    memset(&sess, 0xa5, sizeof(sess));
    origin = 0;
    res = TEEC_OpenSession(ctx, &sess, &kSampleUUID, TEEC_LOGIN_APPLICATION, NULL, NULL, &origin);
    expect_result("OpenSession unsupported APPLICATION login", res, TEEC_ERROR_NOT_SUPPORTED,
                  origin, TEEC_ORIGIN_API);
    if (sess.ctx != NULL || sess.fd != -1) {
        printf("[FAIL] unsupported login left session active ctx=%p fd=%d\n", (void*)sess.ctx,
               sess.fd);
        failures++;
    }

    origin = 0;
    res = TEEC_OpenSession(ctx, &sess, &kSampleUUID, TEEC_LOGIN_GROUP, NULL, NULL, &origin);
    expect_result("OpenSession GROUP without connection data", res, TEEC_ERROR_BAD_PARAMETERS,
                  origin, TEEC_ORIGIN_API);

    origin = 0;
    res = TEEC_OpenSession(ctx, &sess, &kSampleUUID, TEEC_LOGIN_PUBLIC, &origin, NULL, &origin);
    expect_result("OpenSession PUBLIC with connection data", res, TEEC_ERROR_BAD_PARAMETERS, origin,
                  TEEC_ORIGIN_API);

    origin = 0;
    res = TEEC_InvokeCommand(NULL, TA_CMD_INC, NULL, &origin);
    expect_result("InvokeCommand NULL session", res, TEEC_ERROR_BAD_PARAMETERS, origin,
                  TEEC_ORIGIN_API);

    memset(&sess, 0, sizeof(sess));
    sess.fd = -1;
    origin = 0;
    res = TEEC_InvokeCommand(&sess, TA_CMD_INC, NULL, &origin);
    expect_result("InvokeCommand closed session", res, TEEC_ERROR_BAD_PARAMETERS, origin,
                  TEEC_ORIGIN_API);
}

static void test_shared_memory_api(TEEC_Context* ctx) {
    TEEC_SharedMemory shm;
    uint8_t backing[8];
    TEEC_Result res;

    res = TEEC_RegisterSharedMemory(ctx, NULL);
    expect_result("RegisterSharedMemory NULL", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    memset(&shm, 0, sizeof(shm));
    shm.buffer = backing;
    shm.size = sizeof(backing);
    shm.flags = TEEC_MEM_INPUT;
    res = TEEC_RegisterSharedMemory(NULL, &shm);
    expect_result("RegisterSharedMemory NULL context", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    shm.flags = 0;
    res = TEEC_RegisterSharedMemory(ctx, &shm);
    expect_result("RegisterSharedMemory zero flags", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    shm.flags = TEEC_MEM_INPUT | 0x80000000u;
    res = TEEC_RegisterSharedMemory(ctx, &shm);
    expect_result("RegisterSharedMemory reserved flags", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    memset(&shm, 0, sizeof(shm));
    shm.flags = TEEC_MEM_INPUT;
    res = TEEC_RegisterSharedMemory(ctx, &shm);
    expect_result("RegisterSharedMemory empty buffer", res, TEEC_SUCCESS, 0, 0);

    memset(&shm, 0, sizeof(shm));
    shm.size = sizeof(backing);
    shm.flags = TEEC_MEM_INPUT;
    res = TEEC_RegisterSharedMemory(ctx, &shm);
    expect_result("RegisterSharedMemory NULL buffer", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    res = TEEC_AllocateSharedMemory(ctx, NULL);
    expect_result("AllocateSharedMemory NULL", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    memset(&shm, 0, sizeof(shm));
    shm.flags = TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(NULL, &shm);
    expect_result("AllocateSharedMemory NULL context", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);

    memset(&shm, 0, sizeof(shm));
    res = TEEC_AllocateSharedMemory(ctx, &shm);
    expect_result("AllocateSharedMemory zero flags", res, TEEC_ERROR_BAD_PARAMETERS, 0, 0);
}

static void expect_invoke_api_error(TEEC_Session* sess, const char* name, TEEC_Operation* op) {
    uint32_t origin = 0;
    TEEC_Result res = TEEC_InvokeCommand(sess, TA_CMD_INC, op, &origin);

    expect_result(name, res, TEEC_ERROR_BAD_PARAMETERS, origin, TEEC_ORIGIN_API);
}

static void test_operation_validation(TEEC_Context* ctx) {
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_SharedMemory parent;
    uint8_t backing[16];
    uint32_t origin = 0;
    TEEC_Result res;

    res = TEEC_OpenSession(ctx, &sess, &kSampleUUID, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        printf("[FAIL] OpenSession for operation validation: 0x%08x origin %u\n", res, origin);
        failures++;
        return;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(4, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    expect_invoke_api_error(&sess, "Invoke RFU param type", &op);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = NULL;
    op.params[0].tmpref.size = 1;
    expect_invoke_api_error(&sess, "Invoke temp input NULL/nonzero", &op);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = NULL;
    op.params[0].tmpref.size = 1;
    expect_invoke_api_error(&sess, "Invoke temp output NULL/nonzero", &op);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = NULL;
    op.params[0].memref.size = 1;
    expect_invoke_api_error(&sess, "Invoke partial NULL parent", &op);

    memset(&parent, 0, sizeof(parent));
    parent.buffer = backing;
    parent.size = sizeof(backing);
    parent.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &parent;
    op.params[0].memref.offset = sizeof(backing) - 1;
    op.params[0].memref.size = 2;
    expect_invoke_api_error(&sess, "Invoke partial out of bounds", &op);

    parent.flags = TEEC_MEM_OUTPUT;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &parent;
    op.params[0].memref.size = 1;
    expect_invoke_api_error(&sess, "Invoke partial direction mismatch", &op);

    parent.flags = 0;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &parent;
    expect_invoke_api_error(&sess, "Invoke whole zero flags", &op);

    TEEC_CloseSession(&sess);
}

int main(void) {
    TEEC_Context ctx;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("[FAIL] TEEC_InitializeContext: 0x%08x\n", res);
        return 1;
    }

    test_context_and_session_api(&ctx);
    test_shared_memory_api(&ctx);
    test_operation_validation(&ctx);

    TEEC_FinalizeContext(&ctx);
    printf(failures ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", failures);
    return failures ? 1 : 0;
}
