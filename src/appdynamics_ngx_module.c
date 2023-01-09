#include "./appdynamics_ngx_module.h"

/***** CONFIGURATION *****/
static void *
appd_ngx_create_main_config(ngx_conf_t *cf) {
  appd_ngx_main_conf_t *amcf;

  amcf = ngx_pcalloc(cf->pool, sizeof(appd_ngx_main_conf_t));
  if (amcf == NULL) {
    return NULL;
  }
  if (ngx_array_init(&amcf->backend_names, cf->pool, 4, sizeof(ngx_str_t)) != NGX_OK) {
    return NULL;
  }

  amcf->enabled = NGX_CONF_UNSET;
  amcf->controller_use_ssl = NGX_CONF_UNSET;
  amcf->controller_port = NGX_CONF_UNSET;

  return amcf;
}
static char *
appd_ngx_init_main_config(ngx_conf_t *cf, void *conf) {
  appd_ngx_main_conf_t *amcf = conf;
  if (amcf->enabled) {
    // TODO validate configuration
  }

  return NGX_CONF_OK;
}
static void * 
appd_ngx_create_loc_conf(ngx_conf_t *cf) {
  appd_ngx_loc_conf_t *alcf;
  alcf = ngx_pcalloc(cf->pool, sizeof(appd_ngx_loc_conf_t));
  if (alcf == NULL) {
    return NULL;
  }
  if (ngx_array_init(&alcf->collectors, cf->pool, 4, sizeof(appd_ngx_collector_t)) != NGX_OK) {
    return NULL;
  }

  alcf->bt_name_max_segments = NGX_CONF_UNSET;
  alcf->error_on_4xx = NGX_CONF_UNSET;

  return alcf;
}
static char * 
appd_ngx_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  appd_ngx_loc_conf_t *prev = parent;
  appd_ngx_loc_conf_t *conf = child;
  appd_ngx_main_conf_t *amcf;
  ngx_str_t *s;
  ngx_uint_t i;
  appd_ngx_collector_t *pcc, *c;

  ngx_conf_merge_str_value(conf->backend_name, prev->backend_name, "");
  if (conf->backend_name.len > 0) {
    amcf = ngx_http_conf_get_module_main_conf(cf, appdynamics_ngx_module);
    if (!appd_ngx_is_backend_registered(amcf, (char *)conf->backend_name.data)) {
      s = ngx_array_push(&amcf->backend_names);
      if (s == NULL) {
        return NGX_CONF_ERROR;
      }
      *s = conf->backend_name;
    }
  }

  ngx_conf_merge_str_value(conf->bt_name, prev->bt_name, "");
  ngx_conf_merge_uint_value(conf->bt_name_max_segments, prev->bt_name_max_segments, 3);
  ngx_conf_merge_value(conf->error_on_4xx, prev->error_on_4xx, 1);

  pcc = prev->collectors.elts; 
  for (i = 0; i < prev->collectors.nelts; i++) {
    c = ngx_array_push(&conf->collectors);
    if (c == NULL) {
      return NGX_CONF_ERROR;
    }
    c = &pcc[i];
  }

  return NGX_CONF_OK;
}

static char *
appd_ngx_collectors_add(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  appd_ngx_loc_conf_t  *alcf = conf;
  appd_ngx_collector_t *c;
  ngx_str_t            *value;
  ngx_http_compile_complex_value_t ccv;

  value = cf->args->elts;

  c = ngx_array_push(&alcf->collectors);
  if (c == NULL) {
    return NGX_CONF_ERROR;
  }

  c->name = value[1];
  if (value[2].len == 0) {
    ngx_memzero(&c->value, sizeof(ngx_http_complex_value_t));
  } else {
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &c->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
      return NGX_CONF_ERROR;
    }
  }

  return NGX_CONF_OK;
}


static ngx_int_t 
appd_ngx_postconfiguration(ngx_conf_t *cf) {
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  appd_ngx_main_conf_t       *amcf;

  amcf = ngx_http_conf_get_module_main_conf(cf, appdynamics_ngx_module);

  if (amcf->enabled) {
    cf->log->action = "registering appd phase handlers";
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appd_ngx_rewrite_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appd_ngx_preaccess_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appd_ngx_precontent_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appd_ngx_log_handler;
  }
  
  return NGX_OK;
}


/***** INITIALIZATION *****/
static ngx_int_t 
appd_ngx_init_worker(ngx_cycle_t *cycle) {
  appd_ngx_main_conf_t *amcf;
  amcf = ngx_http_cycle_get_module_main_conf(cycle, appdynamics_ngx_module);
  if (amcf->enabled) {
    if (appd_ngx_sdk_init(cycle, amcf) != NGX_OK) {
      return NGX_ERROR;
    }

    if (appd_ngx_backends_init(cycle, amcf) != NGX_OK) {
      return NGX_ERROR;
    }

    // seed the random number generator used by appd_ngx_get_state_key
    srand((int)ngx_time());
  }
  return NGX_OK;
}

static ngx_int_t
appd_ngx_sdk_init(ngx_cycle_t *cycle, appd_ngx_main_conf_t *amcf) {
  cycle->log->action = "initializing AppDynamics SDK";
  ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "MOD_APPD - controller_host      : %V:%d", &amcf->controller_hostname, amcf->controller_port);
  ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "MOD_APPD - controller_account   : %V", &amcf->controller_account);
  ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "MOD_APPD - controller_accesskey : %V", &amcf->controller_access_key);
  ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "MOD_APPD - agent_name           : %V->%V", &amcf->agent_app_name, &amcf->agent_tier_name);

  struct appd_config* cfg = appd_config_init();
  appd_config_set_controller_host(cfg, (const char*)amcf->controller_hostname.data);
  appd_config_set_controller_port(cfg, amcf->controller_port);
  appd_config_set_controller_account(cfg, (const char*)amcf->controller_account.data);
  appd_config_set_controller_access_key(cfg, (const char*)amcf->controller_access_key.data);
  appd_config_set_controller_use_ssl(cfg, amcf->controller_use_ssl);
  if (amcf->controller_certificate_file.len > 0) {
    appd_config_set_controller_certificate_file(cfg, (const char*)amcf->controller_certificate_file.data);
  }
  appd_config_set_app_name(cfg, (const char*)amcf->agent_app_name.data);
  appd_config_set_tier_name(cfg, (const char*)amcf->agent_tier_name.data);
  appd_config_set_node_name(cfg, (const char*)amcf->agent_node_name.data);

  if (appd_sdk_init(cfg) != APPD_NGX_OK) {
    return NGX_ERROR;
  }
  return NGX_OK;
}

static ngx_int_t 
appd_ngx_backends_init(ngx_cycle_t *cycle, appd_ngx_main_conf_t *amcf) {
  ngx_uint_t i;
  ngx_str_t  *backends;
  char       *backend;

  backends = amcf->backend_names.elts;
  for (i = 0; i < amcf->backend_names.nelts; i++) {
    backend = (char *)backends[i].data;
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "MOD_APPD - registering backend %s", backend);
    if (appd_ngx_register_backend(amcf, backend) != NGX_OK) {
      ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "MOD_APPD - failed to register backend %s", backend);
      return NGX_ERROR;
    }
  }
  return NGX_OK;
}
static ngx_int_t 
appd_ngx_register_backend(appd_ngx_main_conf_t *amcf, char *backend) {
  appd_backend_declare(APPD_BACKEND_HTTP, backend);
  if (appd_backend_set_identifying_property(backend, "HOST", backend) != APPD_NGX_OK) {
    return NGX_ERROR;
  }
  if (appd_backend_add(backend) != APPD_NGX_OK) {
    return NGX_ERROR;
  }
  return NGX_OK;
}

static appd_ngx_bool_t 
appd_ngx_is_backend_registered(appd_ngx_main_conf_t *amcf, char *backend) {
  ngx_uint_t i;
  ngx_str_t  *backends;

  backends = amcf->backend_names.elts;
  for (i = 0; i < amcf->backend_names.nelts; i++) {
    // TODO are backend names case sensitive?
    if (ngx_strcmp(backend, backends[i].data) == 0) {
      return APPD_NGX_TRUE;
    }
  }
  return APPD_NGX_FALSE;
};


static void 
appd_ngx_exit_worker(ngx_cycle_t *cycle) {
  appd_sdk_term();
}


/***** REQUEST INSTRUMENTATION *****/

static ngx_int_t 
appd_ngx_rewrite_handler(ngx_http_request_t *r) {
  appd_ngx_tracing_ctx *tc;

  if (r->parent != NULL) {
    // subrequest - ignore
    return NGX_DECLINED;
  }

  if (appd_ngx_get_module_ctx(r) != NULL) {
    // unknown reason why request would already have a context associated with it
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "MOD_APPD - unexpectedly found an existing module context bound to request in REWRITE phase");
    return NGX_DECLINED;
  }

  tc = ngx_pcalloc(r->pool, sizeof(appd_ngx_tracing_ctx));
  if (tc == NULL) {
    return NGX_ERROR;
  }
  if (appd_ngx_set_module_ctx(r, tc) != NGX_OK) {
    return NGX_ERROR;
  }

  appd_ngx_transaction_begin(r, tc);

  return NGX_DECLINED;
}
static ngx_int_t 
appd_ngx_preaccess_handler(ngx_http_request_t *r) {
  appd_ngx_tracing_ctx *tc;

  tc = appd_ngx_get_module_ctx(r);
  if (tc != NULL && tc->bt != NULL) {
    tc->frame = appd_frame_begin(tc->bt, APPD_FRAME_TYPE_CPP, "NGINX", "NGX_HTTP_ACCESS_PHASE", "NGINX_ACCESS", __LINE__);
  }
  return NGX_DECLINED;
}

static ngx_int_t 
appd_ngx_precontent_handler(ngx_http_request_t *r) {
  appd_ngx_tracing_ctx *tc;
  appd_ngx_loc_conf_t *alcf;

  if (r->parent != NULL) {
    // subrequest
    return NGX_DECLINED;
  }

  tc = appd_ngx_get_module_ctx(r);
  if (tc == NULL) {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "MOD_APPD - module context unexpectedly not found in PRECONTENT phase");
    return NGX_DECLINED;
  }

  if (tc-> bt != NULL) {
    if(tc->frame != NULL) {
      appd_frame_end(tc->bt, tc->frame);
      tc->frame = NULL;
    }
    tc->frame = appd_frame_begin(tc->bt, APPD_FRAME_TYPE_CPP, "NGINX", "NGX_HTTP_CONTENT_PHASE", "NGINX_CONTENT", __LINE__);
  }

  alcf = ngx_http_get_module_loc_conf(r, appdynamics_ngx_module);
  if (alcf->backend_name.len > 0) {
    appd_ngx_backend_begin(r, alcf, tc);
  }

  return NGX_DECLINED;
}
static ngx_int_t 
appd_ngx_log_handler(ngx_http_request_t *r) {
  appd_ngx_tracing_ctx *tc;

  tc = appd_ngx_get_module_ctx(r);
  if (tc == NULL) {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "MOD_APPD - module context unexpectedly not found in LOG phase");
    return NGX_DECLINED;
  }

  tc->closed = 1;
  if (tc->bt != NULL) {
    if (tc->frame != NULL) {
      appd_frame_end(tc->bt, tc->frame);
    }
    if (tc->exit != NULL) {
      appd_ngx_backend_end(r, tc);
    }
    appd_ngx_collect_transaction_data(r, tc);
    appd_ngx_transaction_end(r, tc);
  }

  return NGX_DECLINED;
}



static void
appd_ngx_transaction_begin(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc) {
  ngx_table_elt_t *correlation_header_e;
  char *correlation_header = NULL;
  char *bt_name;
  char *url;

  bt_name = appd_ngx_generate_transaction_name(r);
  correlation_header_e = appd_ngx_find_header(r, &APPD_NGX_SINGULARITY_HEADER);
  if (correlation_header_e != NULL) {
    correlation_header = appd_ngx_to_cstr(correlation_header_e->value, r->pool);
  }
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - beginning BT for URL %s", bt_name);

  tc->bt = appd_bt_begin(bt_name, correlation_header);

  url = appd_ngx_to_cstr(r->uri, r->pool);
  appd_bt_set_url(tc->bt, url);
}
static void 
appd_ngx_transaction_end(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc) {
  appd_ngx_loc_conf_t *alcf;
  alcf = ngx_http_get_module_loc_conf(r, appdynamics_ngx_module);
  if (appd_ngx_is_http_error(alcf, r->err_status)) {
    appd_bt_add_error(tc->bt, APPD_LEVEL_ERROR, appd_ngx_default_error_message(r->err_status), APPD_NGX_TRUE);
  }

  appd_bt_end(tc->bt);
}

static void
appd_ngx_backend_begin(ngx_http_request_t *r, appd_ngx_loc_conf_t *alcf, appd_ngx_tracing_ctx *tc) {
  char       *backend;
  const char *th;
  
  backend = (char *)alcf->backend_name.data;
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - beginning exitcall for backend %s", backend);
  tc->exit = appd_exitcall_begin(tc->bt, backend);

  // this is a bit of a hack - opentelemetry handles correlation header injection by phonying a
  // set_proxy_header in the location config and uses a variable.  For now, we'll just append it
  // (or update the existing) to the inbound request headers and assume proxy_pass_request_headers 
  // is 'on'
  th = appd_exitcall_get_correlation_header(tc->exit);
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - correlating exitcall with header %s", th);
  appd_ngx_upsert_header(r, &APPD_NGX_SINGULARITY_HEADER, appd_ngx_cstr_to_ngx((char *)th, r->pool));
}

static char * 
appd_ngx_generate_transaction_name(ngx_http_request_t *r) {
  appd_ngx_loc_conf_t *alcf;
  ngx_str_t u;
  ngx_str_t bt_name;
  ngx_uint_t e, s, i;


  alcf = ngx_http_get_module_loc_conf(r, appdynamics_ngx_module);
  if (alcf->bt_name.len > 0) {
    // transaction has an explicitly configured name from location
    return (char *)alcf->bt_name.data;
  }

  // otherwise derive the name from URL
  u = r->uri;
  for (i = 0, s = 0, e = 1; i < u.len; i++, e++) {
    if (i > 0 && u.data[i] == '/') {
      if (++s == alcf->bt_name_max_segments) {
        goto done;
      }
    }
  }

  // we don't want to create BTs for individual files
  // here, a "file" is a URL where the last segment doesn't end w/ a forward-slash
  // and appears to have a file extension
  if (i == u.len && u.data[i-1] != '/') {
    for (; i > 0 && i > (u.len - 5); i--) {
      if (u.data[i-1] == '.') {
        for (; i > 0; i--) {
          if (i == 1) {  // u.data[0] *should* always be /
            return "/";
          } 
          else if (u.data[i-1] == '/') { 
            e = i;
            goto done;
          }
        }
      }
    }
  } 
  done:

  bt_name.len = e;
  bt_name.data = u.data;
  return appd_ngx_to_cstr(bt_name, r->pool);
}
static void 
appd_ngx_backend_end(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc) {
  ngx_uint_t exit_status;
  appd_ngx_loc_conf_t *alcf;

  if (tc->exit == NULL) {
    return;
  }
  if (r->upstream == NULL) {
    appd_exitcall_add_error(tc->exit, APPD_LEVEL_WARNING, "An Nginx configured appdynamics_backend location did not attempt to call an upstream - this may be a configuration issue.", APPD_NGX_FALSE);
  }

  alcf = ngx_http_get_module_loc_conf(r, appdynamics_ngx_module);
  exit_status = r->upstream->state->status;
  if (appd_ngx_is_http_error(alcf, exit_status)) {
    appd_exitcall_add_error(tc->exit, APPD_LEVEL_ERROR, appd_ngx_default_error_message(exit_status), APPD_NGX_FALSE);
  } else if (exit_status >= 400) {
    appd_exitcall_add_error(tc->exit, APPD_LEVEL_WARNING, appd_ngx_default_error_message(exit_status), APPD_NGX_FALSE);
  }
  // FIXME use r->upstream->state for upstream timings
  appd_exitcall_end(tc->exit);
}

static void appd_ngx_collect_transaction_data(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc) {
  appd_ngx_loc_conf_t  *alcf;
  ngx_uint_t            i;
  appd_ngx_collector_t *cc,*c;
  ngx_str_t             cv;

  alcf = ngx_http_get_module_loc_conf(r, appdynamics_ngx_module);
  cc = alcf->collectors.elts;
  for (i = 0; i < alcf->collectors.nelts; i++) {
    c = &cc[i];
    ngx_http_complex_value(r, &c->value, &cv); // intentionally ignore errors
    if (cv.len > 0) {
      appd_bt_add_user_data(tc->bt, (const char *)c->name.data, appd_ngx_to_cstr(cv, r->pool));
    }
  }
}


// NOTE these are really only intended for working on the SINGULARITY header
// and aren't suited for general purpose header manipulation
static ngx_table_elt_t * 
appd_ngx_find_header(ngx_http_request_t *r, ngx_str_t *name) {
  ngx_uint_t i;
  ngx_list_part_t *part;
  ngx_table_elt_t *header;

  part = &r->headers_in.headers.part;
  header = part->elts;

  for (i = 0; /* void */; i++) {
    if (i >= part->nelts) {
        if (part->next == NULL) {
            break;
        }
        part = part->next;
        header = part->elts;
        i = 0;
    }
    if (ngx_strcasecmp(header[i].key.data, name->data) == 0) {
      return &header[i];
    }
  }
  return NULL;
}
static void 
appd_ngx_insert_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
  ngx_table_elt_t *header;

  if (name == NULL || value == NULL) {
    return;
  }

  header = ngx_list_push(&r->headers_in.headers);
  if (header != NULL) {
    header->key = *name;
    header->value = *value;
    header->hash = ngx_hash_key(header->key.data, header->key.len);

    header->lowcase_key = ngx_palloc(r->pool, header->key.len);
    if (header->lowcase_key != NULL) {
      ngx_strlow(header->lowcase_key, header->key.data, header->key.len);
    }
  }
}
static void 
appd_ngx_upsert_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
  ngx_table_elt_t *header;

  if (name == NULL || value == NULL) {
    return;
  }

  header = appd_ngx_find_header(r, name);
  if (header == NULL) {
    appd_ngx_insert_header(r, name, value);
  } else {
    header->value = *value;
  }
}


/**** MODULE CONTEXT *****
 * We can't use Nginx module context mechanics because Nginx will ZERO
 * out module context on internal redirects with no opportunity to cleanup
 * the context (BT/Exit handles) before that happens.  Instead, we rely on
 * a somewhat filthy hack that allows arbitrary data to be stored against
 * the request in a memory pool cleanup handler (this is what Nginx realip
 * module does for similar reasons).
 */
static ngx_int_t
appd_ngx_set_module_ctx(ngx_http_request_t *r, appd_ngx_tracing_ctx *ctx) {
  ngx_pool_cleanup_t  *cln;
  cln = ngx_pool_cleanup_add(r->pool, 0);
  if (cln == NULL) { 
    return NGX_ERROR;
  }
  cln->handler = appd_ngx_cleanup_module_ctx;
  cln->data = ctx;

  return NGX_OK;
}


static appd_ngx_tracing_ctx * 
appd_ngx_get_module_ctx(ngx_http_request_t *r) {
  ngx_pool_cleanup_t    *cln;
  appd_ngx_tracing_ctx  *ctx = NULL;

  for (cln = r->pool->cleanup; cln; cln = cln->next) {
    if (cln->handler == appd_ngx_cleanup_module_ctx) {
      ctx = cln->data;
      break;
    }
  }
  return ctx;
}

static void
appd_ngx_cleanup_module_ctx(void *data) {
  appd_ngx_tracing_ctx *tc = data;

  if (!tc->closed) {
    // we SHOULD already be closed from the LOG phase handler, but
    // in case we're here and still open, clean up
    if (tc->bt != NULL) {
      if (tc->exit != NULL) {
        appd_exitcall_end(tc->exit);
      }
      appd_bt_add_error(tc->bt, APPD_LEVEL_NOTICE, "transaction closed with unknown status", 0);
      appd_bt_end(tc->bt);
    }
  }
}

/***** HELPERS *****/
static char *
appd_ngx_to_cstr(ngx_str_t source, ngx_pool_t *pool) {
  char* c = ngx_pcalloc(pool, source.len + 1);
  ngx_memcpy(c, (char *) source.data, source.len);
  return c;
}

static ngx_str_t * 
appd_ngx_cstr_to_ngx(char * source, ngx_pool_t *pool) {
  ngx_str_t *dest;

  dest = ngx_palloc(pool, sizeof(ngx_str_t));
  if (dest == NULL) {
    return NULL;
  }
  dest->len = ngx_strlen(source);
  dest->data = (u_char *)source;
  return dest;
}

static appd_ngx_bool_t 
appd_ngx_is_http_error(appd_ngx_loc_conf_t *alcf, ngx_uint_t http_code) {
  if ((alcf->error_on_4xx && http_code >= 400) || http_code >= 500) {
    return APPD_NGX_TRUE;
  }
  return APPD_NGX_FALSE;
}

static const char *
appd_ngx_default_error_message(ngx_uint_t code) {
  // ngx_http unfortunately doesn't expose the routine similar to this (status_line)
  switch (code) {
    case NGX_HTTP_BAD_REQUEST               : return "HTTP 400 : Bad Request";
    case NGX_HTTP_UNAUTHORIZED              : return "HTTP 401 : Unauthorized";
    case NGX_HTTP_FORBIDDEN                 : return "HTTP 403 : Forbidden";
    case NGX_HTTP_NOT_FOUND                 : return "HTTP 404 : Not Found";
    case NGX_HTTP_NOT_ALLOWED               : return "HTTP 405 : Not Allowed";
    case NGX_HTTP_REQUEST_TIME_OUT          : return "HTTP 408 : Request Time Out";
    case NGX_HTTP_CONFLICT                  : return "HTTP 409 : Conflict";
    case NGX_HTTP_LENGTH_REQUIRED           : return "HTTP 411 : Length Required";
    case NGX_HTTP_PRECONDITION_FAILED       : return "HTTP 412 : Precondition Failed";
    case NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  : return "HTTP 413 : Request Entity Too Large";
    case NGX_HTTP_REQUEST_URI_TOO_LARGE     : return "HTTP 414 : Request URI Too Large";
    case NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    : return "HTTP 415 : Unsupported Media Type";
    case NGX_HTTP_RANGE_NOT_SATISFIABLE     : return "HTTP 416 : Range Not Satisfiable";
    case NGX_HTTP_MISDIRECTED_REQUEST       : return "HTTP 421 : Misdirected Request";
    case NGX_HTTP_TOO_MANY_REQUESTS         : return "HTTP 429 : Too Many Requests";
    case NGX_HTTP_INTERNAL_SERVER_ERROR     : return "HTTP 500 : Internal Server Error";
    case NGX_HTTP_NOT_IMPLEMENTED           : return "HTTP 501 : Not Implemented";
    case NGX_HTTP_BAD_GATEWAY               : return "HTTP 502 : Bad Gateway";
    case NGX_HTTP_SERVICE_UNAVAILABLE       : return "HTTP 503 : Service Unavailable";
    case NGX_HTTP_GATEWAY_TIME_OUT          : return "HTTP 504 : Gateway Time Out";
    case NGX_HTTP_VERSION_NOT_SUPPORTED     : return "HTTP 505 : Version Not Supported";
    case NGX_HTTP_INSUFFICIENT_STORAGE      : return "HTTP 507 : Insufficient Storage";
  }

  return "Unknown Error";
}