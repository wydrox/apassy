// The body length limits of the edge Worker. They live outside index.ts because
// workerd accepts only handlers as exports of the Worker's main module.

/** Added to each relay limit below, so the relay stays the judge near it. */
const LENGTH_MARGIN = 64 * 1024;
/** The largest snapshot (SPEC 24.1), plus the margin. Only for `PUT /v1/sync/snapshot`. */
export const MAX_SNAPSHOT_LENGTH = 64 * 1024 * 1024 + LENGTH_MARGIN;
/** The largest proxied request body (`MAX_REQUEST_BODY`, 8 MiB), plus the margin. */
export const MAX_PROXY_LENGTH = 8 * 1024 * 1024 + LENGTH_MARGIN;
/** The largest JSON body (`MAX_JSON_BODY`, 64 KiB), plus the margin. Every other request. */
export const MAX_JSON_LENGTH = 64 * 1024 + LENGTH_MARGIN;
/** The largest body of `PUT /v1/feed` (relay-feed-v1 section 10.1: the b64u of a 256 KiB sealed feed in its JSON), the same as the relay's limit. Only for `PUT /v1/feed`. */
export const MAX_FEED_LENGTH = 352 * 1024;
