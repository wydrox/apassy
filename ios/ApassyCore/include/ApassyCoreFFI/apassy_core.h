// The vault core of the Apassy iPhone app (contract docs/contracts/ios-core-v1.md).
//
// Every call takes and answers JSON (UTF-8, NUL-terminated). An answer is never NULL;
// free it with apassy_core_free_string, which erases it first.

#ifndef APASSY_CORE_H
#define APASSY_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ApassyCore ApassyCore;

/// Start a core. `config` is JSON (contract section 3). NULL on a bad config.
ApassyCore *_Nullable apassy_core_new(const char *_Nonnull config);

/// One call (contract section 4). Safe from several threads at once.
char *_Nonnull apassy_core_call(ApassyCore *_Nonnull core, const char *_Nonnull request);

/// Erase an answer and free it.
void apassy_core_free_string(char *_Nullable answer);

/// Lock the vault, drop the relay session, and free the core.
void apassy_core_free(ApassyCore *_Nullable core);

#ifdef __cplusplus
}
#endif

#endif
