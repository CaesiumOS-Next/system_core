# libteec — GP TEE Client API (REE side) for Trusty

This is the **normal-world** half of the gptee module: an implementation of the
GlobalPlatform TEE Client API (`TEEC_*`) that talks to GP TAs running on Trusty.

Unlike the rest of `lib/gptee/` (which builds into the Trusty TEE image), this
library is built in the **Linux/Android** tree and links **libtrusty**
(`system/core/trusty/libtrusty`). It is intentionally not wired into the Trusty
`rules.mk` build.

## How it works

- `TEEC_Context` owns a copy of the libtrusty device node name (default
  `/dev/trusty-ipc-dev0`).
- `TEEC_OpenSession` connects to the TA's TIPC port `gpta.<uuid>` via
  `tipc_connect()` and performs the `OPEN_SESSION` exchange.
- `TEEC_InvokeCommand` / `TEEC_CloseSession` exchange one request / one response
  per call using the shared wire format in `../include/gptee_ipc.h`.
- Parameter marshalling matches the TA-side runtime and the shared
  `gptee_ipc.h` wire interface.

The `TEEC_*` numeric param-type codes are identical to the GP
`TEE_PARAM_TYPE_*` codes used on the wire, so no translation table is needed.

## Supported scope

- Supported: `VALUE_*`, `MEMREF_TEMP_*`, and registered shared memory
  (`TEEC_RegisterSharedMemory` / `TEEC_AllocateSharedMemory`, `MEMREF_WHOLE`,
  `MEMREF_PARTIAL_*`).
- Memrefs up to 512 bytes travel inline; larger ones are transferred through a
  dmabuf (`/dev/dma_heap/system`) shared with Trusty via `tipc_send`, so there
  is no 4 KB limit. The dmabuf is copied in/out around the call.
- PUBLIC, USER, and GROUP login methods are supported when the Trusty kernel
  authenticates and seals the current-client descriptor. GROUP additionally
  requires membership in the requested group.
- APPLICATION, USER_APPLICATION, and GROUP_APPLICATION are intentionally not
  supported until Android supplies a reviewed package/signing identity policy.
- Cancellation is not supported. Dmabuf-backed shared memory is currently
  copied into and out of the shared allocation rather than exposed as a
  caller-owned zero-copy buffer.

## Building

The AOSP module is defined by the adjacent `Android.bp`, exports the GP Client
API header, consumes `gptee_ipc_headers`, and links `libtrusty`. The kernel-side
authenticated identity hook must land before normal-world non-public sessions
are enabled in a product.
