#ifndef FASTBED_CANCEL_H
#define FASTBED_CANCEL_H

#include "fastbed/common.h"

#include <stdatomic.h>

/*
 * A request-owned, one-way cooperative cancellation token.  The pointed-to
 * flag must outlive every operation using the token.  Fastbed's server keeps
 * that flag in the ref-counted connection request, so request workers may
 * safely poll it without taking the server mutex.
 */
typedef struct {
    const atomic_bool *requested;
} fb_cancel_token;

static inline fb_cancel_token
fb_cancel_token_from_flag(const atomic_bool *requested)
{
    return (fb_cancel_token){.requested = requested};
}

static inline bool
fb_cancel_requested(const fb_cancel_token *token)
{
    return FB_UNLIKELY(
        token != NULL && token->requested != NULL &&
        atomic_load_explicit(token->requested, memory_order_relaxed));
}

#endif
