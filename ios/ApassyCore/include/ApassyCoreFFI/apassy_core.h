// The vault core of the Apassy iPhone app (contract docs/contracts/ios-core-v1.md).
//
// Every call takes and answers JSON (UTF-8, NUL-terminated). An answer is never NULL;
// free it with apassy_core_free_string, which erases it first.

#ifndef APASSY_CORE_H
#define APASSY_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ApassyCore ApassyCore;

/// Start a core. `config` is JSON (contract section 3). NULL on a bad config.
ApassyCore *_Nullable apassy_core_new(const char *_Nonnull config);

/// 0: copied 32 key bytes; 1: missing; all other values: unavailable.
/// Never replace an existing key. Only create if may_create is true.
/// Provider and context remain valid until core_free returns; calls must be thread-safe.
typedef int32_t (*apassy_history_key_provider)(void *_Nullable context,
    const char *_Nonnull vault_id, bool may_create, uint8_t *_Nonnull out_key_32);
ApassyCore *_Nullable apassy_core_new_with_history_key_provider(
    const char *_Nonnull config, apassy_history_key_provider _Nonnull provider,
    void *_Nullable context);

/// The Keychain store of the Apassy Connect account device key (contract section 5.14):
/// one P-256 key of this iPhone, outside every vault, this device only, not synchronizable.
/// `read` copies the stored PKCS#8 document into `out` (at most `capacity` bytes), sets
/// `out_length`, and answers 0; 1: no key; any other value: unavailable. `write` stores a
/// new document (replacing an earlier one) and answers 0, else unavailable. `delete`
/// answers 0 (deleted), 1 (no key), or unavailable. Set it once per core, after
/// apassy_core_new; false for a second call. The callbacks and the context stay valid
/// until apassy_core_free returns and are thread-safe. Keep no copy of the bytes.
typedef int32_t (*apassy_account_key_read)(void *_Nullable context, uint8_t *_Nonnull out,
    size_t capacity, size_t *_Nonnull out_length);
typedef int32_t (*apassy_account_key_write)(void *_Nullable context,
    const uint8_t *_Nonnull key, size_t length);
typedef int32_t (*apassy_account_key_delete)(void *_Nullable context);
bool apassy_core_set_account_key_store(ApassyCore *_Nonnull core,
    apassy_account_key_read _Nonnull read, apassy_account_key_write _Nonnull write,
    apassy_account_key_delete _Nonnull delete_key, void *_Nullable context);

/// One call (contract section 4). Safe from several threads at once.
char *_Nonnull apassy_core_call(ApassyCore *_Nonnull core, const char *_Nonnull request);

/// Erase an answer and free it.
void apassy_core_free_string(char *_Nullable answer);

/// The external HTTP transport (contract section 2.1, ADR 0039 section 5): the Apple
/// Watch performs each relay request with URLSession.
///
/// `send` gets the request as JSON: {"id": u64, "method": "GET", "url": "https://...",
/// "headers": [["name", "value"], ...], "body_b64u": "..." (absent without a body),
/// "timeout_ms": u64}. It runs on the core's calling thread, may block until the answer,
/// and returns {"status": u16, "headers": [["name", "value"], ...], "body_b64u": "..."}
/// or {"error": "connect" | "broken" | "protocol"}, allocated with malloc or strdup.
/// The core erases and frees it with free. NULL means "broken". The request holds the
/// bearer: keep no copy of it after `send` returns.
///
/// `cancel` ends the request `request_id` at once: its `send` then answers
/// {"error": "broken"}. It can come from another thread while that `send` runs, and also
/// just before that `send` starts: then that `send` fails at once. It must not call the
/// core.
///
/// Both callbacks can run on several threads at once.
typedef char *_Nullable (*apassy_http_send)(void *_Nullable context,
    const char *_Nonnull request_json);
typedef void (*apassy_http_cancel)(void *_Nullable context, uint64_t request_id);

/// Install the transport once per process, before apassy_core_new. A second call is
/// ignored. The callbacks and the context stay valid for the life of the process.
void apassy_core_set_http_transport(apassy_http_send _Nonnull send,
    apassy_http_cancel _Nonnull cancel, void *_Nullable context);

/// Lock the vault, drop the relay session, and free the core.
void apassy_core_free(ApassyCore *_Nullable core);

#ifdef __cplusplus
}
#endif

#endif
