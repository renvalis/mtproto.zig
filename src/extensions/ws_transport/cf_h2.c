/* Bounded memory-only nghttp2 adapter. Socket/TLS ownership stays in Zig. */
#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CF_PACKET (4u * 1024u * 1024u)
#define CF_BUDGET (8u * 1024u * 1024u)
#define CF_INFLIGHT 8u

struct cf_request {
  struct cf_request *next;
  uint8_t *body, *reply;
  size_t size, offset, reply_size, reply_cap, header_bytes;
  int32_t id;
  int status, head, done;
};
struct cf_h2 {
  nghttp2_session *session;
  struct cf_request *requests;
  size_t bytes, pending;
  int error, ready;
};

static struct cf_request *request_for(struct cf_h2 *ctx, int32_t id) {
  for (struct cf_request *r = ctx->requests; r; r = r->next)
    if (r->id == id) return r;
  return NULL;
}
static nghttp2_ssize read_body(nghttp2_session *s, int32_t id, uint8_t *buf,
                               size_t length, uint32_t *flags,
                               nghttp2_data_source *source, void *user) {
  (void)s; (void)id; (void)user;
  struct cf_request *r = source->ptr;
  size_t n = r->size - r->offset;
  if (n > length) n = length;
  memcpy(buf, r->body + r->offset, n);
  r->offset += n;
  if (r->offset == r->size) *flags |= NGHTTP2_DATA_FLAG_EOF;
  return (nghttp2_ssize)n;
}
static int header(nghttp2_session *s, const nghttp2_frame *frame,
                  const uint8_t *name, size_t namelen, const uint8_t *value,
                  size_t valuelen, uint8_t flags, void *user) {
  (void)s; (void)flags;
  struct cf_h2 *ctx = user;
  struct cf_request *r = request_for(ctx, frame->hd.stream_id);
  if (!r) return 0;
  r->header_bytes += namelen + valuelen;
  if (r->header_bytes > 16384) { ctx->error = 1; return NGHTTP2_ERR_CALLBACK_FAILURE; }
  if (namelen == 7 && !memcmp(name, ":status", 7)) {
    if (valuelen != 3 || value[0] < '1' || value[0] > '5' ||
        value[1] < '0' || value[1] > '9' || value[2] < '0' || value[2] > '9') {
      ctx->error = 1; return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    r->status = (value[0]-'0')*100 + (value[1]-'0')*10 + value[2]-'0';
  }
  if (!r->head && namelen == 12 && !memcmp(name, "content-type", 12) &&
      valuelen >= 9 && !memcmp(value, "text/html", 9)) {
    ctx->error = 1; return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (!r->head && namelen == 16 && !memcmp(name, "content-encoding", 16) &&
      !(valuelen == 8 && !memcmp(value, "identity", 8))) {
    ctx->error = 1; return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
static int data(nghttp2_session *s, uint8_t flags, int32_t id,
                const uint8_t *bytes, size_t length, void *user) {
  (void)s; (void)flags;
  struct cf_h2 *ctx = user;
  struct cf_request *r = request_for(ctx, id);
  if (!r || r->head || r->status != 200 || length > CF_PACKET-r->reply_size)
    goto fail;
  size_t needed = r->reply_size + length;
  if (needed > r->reply_cap) {
    size_t cap = needed > 4096 ? needed : 4096;
    size_t extra = cap-r->reply_cap;
    if (extra > CF_BUDGET-ctx->bytes) goto fail;
    void *p = realloc(r->reply, cap);
    if (!p) goto fail;
    r->reply = p; ctx->bytes += extra; r->reply_cap = cap;
  }
  memcpy(r->reply+r->reply_size, bytes, length); r->reply_size += length;
  return 0;
fail:
  ctx->error = 1; return NGHTTP2_ERR_CALLBACK_FAILURE;
}
static int closed(nghttp2_session *s, int32_t id, uint32_t error, void *user) {
  (void)s;
  struct cf_h2 *ctx = user;
  struct cf_request *r = request_for(ctx, id);
  if (!r) return 0;
  ctx->pending--;
  free(r->body); r->body = NULL; ctx->bytes -= r->size; r->size = 0;
  if (error) ctx->error = 1;
  if (r->head) {
    if ((r->status >= 200 && r->status < 300) || r->status == 405 || r->status == 501)
      ctx->ready = 1;
    else ctx->error = 1;
  } else if (r->status != 200 || r->reply_size % 4) ctx->error = 1;
  r->done = 1;
  return 0;
}
static nghttp2_nv nv(const char *name, const char *value) {
  nghttp2_nv out = {(uint8_t *)name, (uint8_t *)value, strlen(name), strlen(value), 0};
  return out;
}
static int submit(struct cf_h2 *ctx, const char *host, const uint8_t *body,
                  size_t length, int head) {
  if (ctx->error) return -1;
  if (ctx->pending >= CF_INFLIGHT || length > CF_BUDGET-ctx->bytes) return 1;
  if (length > CF_PACKET) return -1;
  struct cf_request *r = calloc(1, sizeof(*r));
  if (!r) return -1;
  r->head = head; r->size = length;
  if (length) {
    r->body = malloc(length);
    if (!r->body) { free(r); return -1; }
    memcpy(r->body, body, length);
  }
  nghttp2_nv headers[] = {nv(":method", head ? "HEAD" : "POST"),
    nv(":scheme", "https"), nv(":authority", host), nv(":path", "/api"),
    nv("content-type", "application/octet-stream"), nv("accept-encoding", "identity")};
  nghttp2_data_provider2 provider = {{.ptr=r}, read_body};
  int32_t id = nghttp2_submit_request2(ctx->session, NULL, headers, 6,
                                      head ? NULL : &provider, r);
  if (id < 0) { free(r->body); free(r); return -1; }
  r->id = id; r->next = ctx->requests; ctx->requests = r;
  ctx->pending++; ctx->bytes += length;
  return 0;
}
void cf_h2_free(struct cf_h2 *ctx) {
  if (!ctx) return;
  if (ctx->session) nghttp2_session_del(ctx->session);
  struct cf_request *r = ctx->requests;
  while (r) { struct cf_request *next = r->next; free(r->body); free(r->reply); free(r); r = next; }
  free(ctx);
}
struct cf_h2 *cf_h2_new(const char *host) {
  struct cf_h2 *ctx = calloc(1, sizeof(*ctx));
  nghttp2_session_callbacks *callbacks = NULL;
  if (!ctx || nghttp2_session_callbacks_new(&callbacks)) { free(ctx); return NULL; }
  nghttp2_session_callbacks_set_on_header_callback(callbacks, header);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, data);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, closed);
  int error = nghttp2_session_client_new(&ctx->session, callbacks, ctx);
  nghttp2_session_callbacks_del(callbacks);
  if (error) { cf_h2_free(ctx); return NULL; }
  nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
    {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 256*1024},
    {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 16384}};
  if (nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, settings, 3) ||
      nghttp2_submit_window_update(ctx->session, NGHTTP2_FLAG_NONE, 0, 4*1024*1024-65535) ||
      submit(ctx, host, NULL, 0, 1)) { cf_h2_free(ctx); return NULL; }
  return ctx;
}
int cf_h2_ready(struct cf_h2 *ctx) { return !ctx->error && ctx->ready; }
int cf_h2_post(struct cf_h2 *ctx, const char *host, const uint8_t *body, size_t length) {
  return submit(ctx, host, body, length, 0);
}
nghttp2_ssize cf_h2_feed(struct cf_h2 *ctx, const uint8_t *bytes, size_t length) {
  if (ctx->error) return -1;
  nghttp2_ssize n = nghttp2_session_mem_recv2(ctx->session, bytes, length);
  return ctx->error ? -1 : n;
}
nghttp2_ssize cf_h2_drain(struct cf_h2 *ctx, const uint8_t **bytes) {
  if (ctx->error) return -1;
  nghttp2_ssize n = nghttp2_session_mem_send2(ctx->session, bytes);
  return ctx->error ? -1 : n;
}
/* Returned body remains valid until cf_h2_pop(). Completed requests can finish
 * out of order: MTProto message IDs, rather than HTTP stream IDs, match replies. */
int cf_h2_reply(struct cf_h2 *ctx, const uint8_t **bytes, size_t *length) {
  if (ctx->error) return -1;
  for (struct cf_request *r = ctx->requests; r; r = r->next) {
    if (r->done) { *bytes = r->reply; *length = r->reply_size; return 1; }
  }
  return 0;
}
void cf_h2_pop(struct cf_h2 *ctx) {
  struct cf_request **prev = &ctx->requests;
  while (*prev) {
    struct cf_request *r = *prev;
    if (r->done) {
      *prev = r->next; ctx->bytes -= r->reply_cap; free(r->reply); free(r); return;
    }
    prev = &r->next;
  }
}
