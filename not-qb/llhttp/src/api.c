#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "llhttp.h"

#define CALLBACK_MAYBE(PARSER, NAME)                                          \
  do {                                                                        \
    const http_settings_t* settings;                                        \
    settings = (const http_settings_t*) (PARSER)->settings;                 \
    if (settings == NULL || settings->NAME == NULL) {                         \
      err = 0;                                                                \
      break;                                                                  \
    }                                                                         \
    err = settings->NAME((PARSER));                                           \
  } while (0)

#define SPAN_CALLBACK_MAYBE(PARSER, NAME, START, LEN)                         \
  do {                                                                        \
    const http_settings_t* settings;                                        \
    settings = (const http_settings_t*) (PARSER)->settings;                 \
    if (settings == NULL || settings->NAME == NULL) {                         \
      err = 0;                                                                \
      break;                                                                  \
    }                                                                         \
    err = settings->NAME((PARSER), (START), (LEN));                           \
    if (err == -1) {                                                          \
      err = HPE_USER;                                                         \
      http_set_error_reason((PARSER), "Span callback error in " #NAME);     \
    }                                                                         \
  } while (0)

void http_init(http_t* parser, http_type_t type,
                 const http_settings_t* settings) {
  http__internal_init(parser);

  parser->type = type;
  parser->settings = (void*) settings;
}


#if defined(__wasm__)

extern int wasm_on_message_begin(http_t * p);
extern int wasm_on_url(http_t* p, const char* at, size_t length);
extern int wasm_on_status(http_t* p, const char* at, size_t length);
extern int wasm_on_header_field(http_t* p, const char* at, size_t length);
extern int wasm_on_header_value(http_t* p, const char* at, size_t length);
extern int wasm_on_headers_complete(http_t * p, int status_code,
                                    uint8_t upgrade, int should_keep_alive);
extern int wasm_on_body(http_t* p, const char* at, size_t length);
extern int wasm_on_message_complete(http_t * p);

static int wasm_on_headers_complete_wrap(http_t* p) {
  return wasm_on_headers_complete(p, p->status_code, p->upgrade,
                                  http_should_keep_alive(p));
}

const http_settings_t wasm_settings = {
  .on_message_begin = wasm_on_message_begin,
  .on_url = wasm_on_url,
  .on_status = wasm_on_status,
  .on_header_field = wasm_on_header_field,
  .on_header_value = wasm_on_header_value,
  .on_headers_complete = wasm_on_headers_complete_wrap,
  .on_body = wasm_on_body,
  .on_message_complete = wasm_on_message_complete,
};


http_t* http_alloc(http_type_t type) {
  http_t* parser = malloc(sizeof(http_t));
  http_init(parser, type, &wasm_settings);
  return parser;
}

void http_free(http_t* parser) {
  free(parser);
}

#endif  // defined(__wasm__)

/* Some getters required to get stuff from the parser */

uint8_t http_get_type(http_t* parser) {
  return parser->type;
}

uint8_t http_get_http_major(http_t* parser) {
  return parser->http_major;
}

uint8_t http_get_http_minor(http_t* parser) {
  return parser->http_minor;
}

uint8_t http_get_method(http_t* parser) {
  return parser->method;
}

int http_get_status_code(http_t* parser) {
  return parser->status_code;
}

uint8_t http_get_upgrade(http_t* parser) {
  return parser->upgrade;
}


void http_reset(http_t* parser) {
  http_type_t type = parser->type;
  const http_settings_t* settings = parser->settings;
  void* data = parser->data;
  uint16_t lenient_flags = parser->lenient_flags;

  http__internal_init(parser);

  parser->type = type;
  parser->settings = (void*) settings;
  parser->data = data;
  parser->lenient_flags = lenient_flags;
}


http_errno_t http_execute(http_t* parser, const char* data, size_t len) {
  return http__internal_execute(parser, data, data + len);
}


void http_settings_init(http_settings_t* settings) {
  memset(settings, 0, sizeof(*settings));
}


http_errno_t http_finish(http_t* parser) {
  int err;

  /* We're in an error state. Don't bother doing anything. */
  if (parser->error != 0) {
    return 0;
  }

  switch (parser->finish) {
    case HTTP_FINISH_SAFE_WITH_CB:
      CALLBACK_MAYBE(parser, on_message_complete);
      if (err != HPE_OK) return err;

    /* FALLTHROUGH */
    case HTTP_FINISH_SAFE:
      return HPE_OK;
    case HTTP_FINISH_UNSAFE:
      parser->reason = "Invalid EOF state";
      return HPE_INVALID_EOF_STATE;
    default:
      abort();
  }
}


void http_pause(http_t* parser) {
  if (parser->error != HPE_OK) {
    return;
  }

  parser->error = HPE_PAUSED;
  parser->reason = "Paused";
}


void http_resume(http_t* parser) {
  if (parser->error != HPE_PAUSED) {
    return;
  }

  parser->error = 0;
}


void http_resume_after_upgrade(http_t* parser) {
  if (parser->error != HPE_PAUSED_UPGRADE) {
    return;
  }

  parser->error = 0;
}


http_errno_t http_get_errno(const http_t* parser) {
  return parser->error;
}


const char* http_get_error_reason(const http_t* parser) {
  return parser->reason;
}


void http_set_error_reason(http_t* parser, const char* reason) {
  parser->reason = reason;
}


const char* http_get_error_pos(const http_t* parser) {
  return parser->error_pos;
}


const char* http_errno_name(http_errno_t err) {
#define HTTP_ERRNO_GEN(CODE, NAME, _) case HPE_##NAME: return "HPE_" #NAME;
  switch (err) {
    HTTP_ERRNO_MAP(HTTP_ERRNO_GEN)
    default: abort();
  }
#undef HTTP_ERRNO_GEN
}


const char* http_method_name(http_method_t method) {
#define HTTP_METHOD_GEN(NUM, NAME, STRING) case HTTP_##NAME: return #STRING;
  switch (method) {
    HTTP_ALL_METHOD_MAP(HTTP_METHOD_GEN)
    default: abort();
  }
#undef HTTP_METHOD_GEN
}

const char* http_status_name(http_status_t status) {
#define HTTP_STATUS_GEN(NUM, NAME, STRING) case HTTP_STATUS_##NAME: return #STRING;
  switch (status) {
    HTTP_STATUS_MAP(HTTP_STATUS_GEN)
    default: abort();
  }
#undef HTTP_STATUS_GEN
}


void http_set_lenient_headers(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_HEADERS;
  } else {
    parser->lenient_flags &= ~LENIENT_HEADERS;
  }
}


void http_set_lenient_chunked_length(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_CHUNKED_LENGTH;
  } else {
    parser->lenient_flags &= ~LENIENT_CHUNKED_LENGTH;
  }
}


void http_set_lenient_keep_alive(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_KEEP_ALIVE;
  } else {
    parser->lenient_flags &= ~LENIENT_KEEP_ALIVE;
  }
}

void http_set_lenient_transfer_encoding(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_TRANSFER_ENCODING;
  } else {
    parser->lenient_flags &= ~LENIENT_TRANSFER_ENCODING;
  }
}

void http_set_lenient_version(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_VERSION;
  } else {
    parser->lenient_flags &= ~LENIENT_VERSION;
  }
}

void http_set_lenient_data_after_close(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_DATA_AFTER_CLOSE;
  } else {
    parser->lenient_flags &= ~LENIENT_DATA_AFTER_CLOSE;
  }
}

void http_set_lenient_optional_lf_after_cr(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_OPTIONAL_LF_AFTER_CR;
  } else {
    parser->lenient_flags &= ~LENIENT_OPTIONAL_LF_AFTER_CR;
  }
}

void http_set_lenient_optional_crlf_after_chunk(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_OPTIONAL_CRLF_AFTER_CHUNK;
  } else {
    parser->lenient_flags &= ~LENIENT_OPTIONAL_CRLF_AFTER_CHUNK;
  }
}

void http_set_lenient_optional_cr_before_lf(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_OPTIONAL_CR_BEFORE_LF;
  } else {
    parser->lenient_flags &= ~LENIENT_OPTIONAL_CR_BEFORE_LF;
  }
}

void http_set_lenient_spaces_after_chunk_size(http_t* parser, int enabled) {
  if (enabled) {
    parser->lenient_flags |= LENIENT_SPACES_AFTER_CHUNK_SIZE;
  } else {
    parser->lenient_flags &= ~LENIENT_SPACES_AFTER_CHUNK_SIZE;
  }
}

/* Callbacks */


int http__on_message_begin(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_message_begin);
  return err;
}


int http__on_protocol(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_protocol, p, endp - p);
  return err;
}


int http__on_protocol_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_protocol_complete);
  return err;
}


int http__on_url(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_url, p, endp - p);
  return err;
}


int http__on_url_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_url_complete);
  return err;
}


int http__on_status(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_status, p, endp - p);
  return err;
}


int http__on_status_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_status_complete);
  return err;
}


int http__on_method(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_method, p, endp - p);
  return err;
}


int http__on_method_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_method_complete);
  return err;
}


int http__on_version(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_version, p, endp - p);
  return err;
}


int http__on_version_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_version_complete);
  return err;
}


int http__on_header_field(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_header_field, p, endp - p);
  return err;
}


int http__on_header_field_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_header_field_complete);
  return err;
}


int http__on_header_value(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_header_value, p, endp - p);
  return err;
}


int http__on_header_value_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_header_value_complete);
  return err;
}


int http__on_headers_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_headers_complete);
  return err;
}


int http__on_message_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_message_complete);
  return err;
}


int http__on_body(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_body, p, endp - p);
  return err;
}


int http__on_chunk_header(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_chunk_header);
  return err;
}


int http__on_chunk_extension_name(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_chunk_extension_name, p, endp - p);
  return err;
}


int http__on_chunk_extension_name_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_chunk_extension_name_complete);
  return err;
}


int http__on_chunk_extension_value(http_t* s, const char* p, const char* endp) {
  int err;
  SPAN_CALLBACK_MAYBE(s, on_chunk_extension_value, p, endp - p);
  return err;
}


int http__on_chunk_extension_value_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_chunk_extension_value_complete);
  return err;
}


int http__on_chunk_complete(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_chunk_complete);
  return err;
}


int http__on_reset(http_t* s, const char* p, const char* endp) {
  int err;
  CALLBACK_MAYBE(s, on_reset);
  return err;
}


/* Private */


void http__debug(http_t* s, const char* p, const char* endp,
                   const char* msg) {
  if (p == endp) {
    fprintf(stderr, "p=%p type=%d flags=%02x next=null debug=%s\n", s, s->type,
            s->flags, msg);
  } else {
    fprintf(stderr, "p=%p type=%d flags=%02x next=%02x   debug=%s\n", s,
            s->type, s->flags, *p, msg);
  }
}
