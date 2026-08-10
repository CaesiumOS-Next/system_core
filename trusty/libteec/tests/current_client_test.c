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

/* REE end-to-end tests for kernel-authenticated GP current-client identity. */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <gptee_ipc.h>
#include <tee_client_api.h>
#include <trusty/tipc.h>

#define DEFAULT_TIPC_DEV "/dev/trusty-ipc-dev0"
#define SAMPLE_TA_PORT \
    GPTEE_PORT_PREFIX  \
    "8aaaf200-2450-11e4-abe2-0002a5d5c51b"
#define TA_CMD_GET_CURRENT_CLIENT 42

struct test_identity {
    uint32_t login;
    TEEC_UUID uuid;
};

static const TEEC_UUID kSampleUuid = {
        0x8aaaf200, 0x2450, 0x11e4, {0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};

static int failures;

static uint32_t find_nonmember_group(void) {
    gid_t groups[128];
    int count = getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups);
    uint32_t candidate;

    if (count < 0) count = 0;
    for (candidate = 60000; candidate < 65000; candidate++) {
        int i;
        int member = candidate == (uint32_t)getegid();

        for (i = 0; !member && i < count; i++) member = candidate == (uint32_t)groups[i];
        if (!member) return candidate;
    }
    return 65000;
}

static int uuid_is_nil(const TEEC_UUID* uuid) {
    const uint8_t* bytes = (const uint8_t*)uuid;
    size_t i;

    for (i = 0; i < sizeof(*uuid); i++) {
        if (bytes[i] != 0) return 0;
    }
    return 1;
}

static void fail_result(const char* name, TEEC_Result result, uint32_t origin) {
    printf("[FAIL] %s: result=0x%08x origin=%u\n", name, result, origin);
    failures++;
}

static int get_identity(TEEC_Context* context, uint32_t login, const void* connection_data,
                        struct test_identity* identity) {
    TEEC_Operation operation;
    TEEC_Session session;
    uint32_t origin = 0;
    TEEC_Result result;

    result = TEEC_OpenSession(context, &session, &kSampleUuid, login, connection_data, NULL,
                              &origin);
    if (result != TEEC_SUCCESS) {
        fail_result("OpenSession for identity", result, origin);
        return -1;
    }

    memset(identity, 0, sizeof(*identity));
    memset(&operation, 0, sizeof(operation));
    operation.paramTypes =
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = identity;
    operation.params[0].tmpref.size = sizeof(*identity);
    result = TEEC_InvokeCommand(&session, TA_CMD_GET_CURRENT_CLIENT, &operation, &origin);
    TEEC_CloseSession(&session);
    if (result != TEEC_SUCCESS || operation.params[0].tmpref.size != sizeof(*identity)) {
        fail_result("Invoke current-client query", result, origin);
        return -1;
    }
    return 0;
}

static void test_standard_logins(TEEC_Context* context, struct test_identity* user_identity) {
    struct test_identity public_identity;
    struct test_identity repeated_user;
    struct test_identity group_identity;
    uint32_t group = (uint32_t)getegid();
    uint32_t invalid_group = find_nonmember_group();
    TEEC_Session session;
    uint32_t origin = 0;
    TEEC_Result result;

    if (!get_identity(context, TEEC_LOGIN_PUBLIC, NULL, &public_identity)) {
        if (public_identity.login != TEEC_LOGIN_PUBLIC || !uuid_is_nil(&public_identity.uuid)) {
            printf("[FAIL] PUBLIC identity is not public/nil\n");
            failures++;
        } else {
            printf("[ OK ] PUBLIC identity is public with nil UUID\n");
        }
    }

    if (!get_identity(context, TEEC_LOGIN_USER, NULL, user_identity) &&
        !get_identity(context, TEEC_LOGIN_USER, NULL, &repeated_user)) {
        if (user_identity->login != TEEC_LOGIN_USER || uuid_is_nil(&user_identity->uuid) ||
            memcmp(user_identity, &repeated_user, sizeof(*user_identity))) {
            printf("[FAIL] USER identity is missing or unstable\n");
            failures++;
        } else {
            printf("[ OK ] USER identity is credential-derived and stable\n");
        }
    }

    if (!get_identity(context, TEEC_LOGIN_GROUP, &group, &group_identity)) {
        if (group_identity.login != TEEC_LOGIN_GROUP || uuid_is_nil(&group_identity.uuid) ||
            !memcmp(&group_identity.uuid, &user_identity->uuid, sizeof(group_identity.uuid))) {
            printf("[FAIL] GROUP identity is missing or aliases USER\n");
            failures++;
        } else {
            printf("[ OK ] GROUP identity uses the requested member GID\n");
        }
    }

    result = TEEC_OpenSession(context, &session, &kSampleUuid, TEEC_LOGIN_GROUP, &invalid_group,
                              NULL, &origin);
    if (result != TEEC_ERROR_ACCESS_DENIED || origin != TEEC_ORIGIN_API) {
        fail_result("non-member GROUP rejection", result, origin);
        if (result == TEEC_SUCCESS) TEEC_CloseSession(&session);
    } else {
        printf("[ OK ] non-member GROUP rejected by kernel credentials\n");
    }

    origin = 0;
    result = TEEC_OpenSession(context, &session, &kSampleUuid, TEEC_LOGIN_APPLICATION, NULL, NULL,
                              &origin);
    if (result != TEEC_ERROR_NOT_SUPPORTED || origin != TEEC_ORIGIN_API) {
        fail_result("APPLICATION login rejection", result, origin);
        if (result == TEEC_SUCCESS) TEEC_CloseSession(&session);
    } else {
        printf("[ OK ] APPLICATION login explicitly unsupported\n");
    }
}

static ssize_t read_retry(int fd, void* buffer, size_t size) {
    ssize_t rc;

    do {
        rc = read(fd, buffer, size);
    } while (rc < 0 && errno == EINTR);
    return rc;
}

static int raw_round_trip(int fd, const struct gptee_msg_hdr* request, void* response,
                          size_t response_size) {
    ssize_t rc;

    do {
        rc = write(fd, request, sizeof(*request));
    } while (rc < 0 && errno == EINTR);
    if (rc != (ssize_t)sizeof(*request)) return -1;

    rc = read_retry(fd, response, response_size);
    if (rc < (ssize_t)sizeof(struct gptee_resp_hdr)) return -1;
    return (int)rc;
}

static void test_raw_spoofing(const struct test_identity* expected_user) {
    union {
        struct gptee_resp_hdr header;
        uint8_t bytes[sizeof(struct gptee_resp_hdr) + sizeof(struct test_identity)];
    } response;
    struct gptee_msg_hdr request;
    struct test_identity identity;
    int fd;
    int rc;

    fd = tipc_connect(DEFAULT_TIPC_DEV, SAMPLE_TA_PORT);
    if (fd < 0) {
        printf("[FAIL] raw TIPC connect: %d\n", fd);
        failures++;
        return;
    }

    memset(&request, 0, sizeof(request));
    request.op = GPTEE_OP_OPEN_SESSION;
    request.session = TEEC_LOGIN_USER;
    request.protocol = GPTEE_PROTOCOL_ID;
    memset(&request.client_uuid, 0xa5, sizeof(request.client_uuid));
    rc = raw_round_trip(fd, &request, &response, sizeof(response));
    if (rc != (int)sizeof(struct gptee_resp_hdr) || response.header.protocol != GPTEE_PROTOCOL_ID ||
        response.header.result != TEEC_SUCCESS) {
        printf("[FAIL] raw forged USER open was not authenticated\n");
        failures++;
        close(fd);
        return;
    }

    memset(&request, 0, sizeof(request));
    request.op = GPTEE_OP_INVOKE_COMMAND;
    request.cmd_id = TA_CMD_GET_CURRENT_CLIENT;
    request.protocol = GPTEE_PROTOCOL_ID;
    request.param_types =
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    request.params[0].attr = TEEC_MEMREF_TEMP_OUTPUT;
    request.params[0].u.memref.size = sizeof(identity);
    rc = raw_round_trip(fd, &request, &response, sizeof(response));
    if (rc != (int)sizeof(response) || response.header.result != TEEC_SUCCESS ||
        response.header.data_len != sizeof(identity)) {
        printf("[FAIL] raw current-client response malformed\n");
        failures++;
    } else {
        memcpy(&identity, response.bytes + sizeof(response.header), sizeof(identity));
        if (memcmp(&identity, expected_user, sizeof(identity))) {
            printf("[FAIL] forged client UUID was not replaced\n");
            failures++;
        } else {
            printf("[ OK ] forged USER UUID replaced by kernel identity\n");
        }
    }

    memset(&request, 0, sizeof(request));
    request.op = GPTEE_OP_CLOSE_SESSION;
    request.protocol = GPTEE_PROTOCOL_ID;
    (void)raw_round_trip(fd, &request, &response, sizeof(response));
    close(fd);

    fd = tipc_connect(DEFAULT_TIPC_DEV, SAMPLE_TA_PORT);
    if (fd < 0) {
        printf("[FAIL] raw TIPC reconnect: %d\n", fd);
        failures++;
        return;
    }
    memset(&request, 0, sizeof(request));
    request.op = GPTEE_OP_OPEN_SESSION;
    request.session = TEEC_LOGIN_USER | GPTEE_LOGIN_KERNEL_AUTHENTICATED;
    request.protocol = GPTEE_PROTOCOL_ID;
    errno = 0;
    rc = (int)write(fd, &request, sizeof(request));
    if (rc != -1 || errno != EINVAL) {
        printf("[FAIL] forged authenticated bit: rc=%d errno=%d\n", rc, errno);
        failures++;
    } else {
        printf("[ OK ] forged kernel-authenticated bit rejected\n");
    }
    close(fd);
}

int main(void) {
    TEEC_Context context;
    struct test_identity user_identity;
    TEEC_Result result;

    memset(&user_identity, 0, sizeof(user_identity));
    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        printf("[FAIL] TEEC_InitializeContext: 0x%08x\n", result);
        return 1;
    }

    test_standard_logins(&context, &user_identity);
    if (user_identity.login == TEEC_LOGIN_USER) test_raw_spoofing(&user_identity);

    TEEC_FinalizeContext(&context);
    printf(failures ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", failures);
    return failures ? 1 : 0;
}
