#include "./appdynamics_ngx_module.h"


/* ------------ initialization stuff -------------*/


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

  return alcf;
}
static char * 
appd_ngx_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  appd_ngx_loc_conf_t *prev = parent;
  appd_ngx_loc_conf_t *conf = child;
  appd_ngx_main_conf_t *amcf;
  ngx_str_t *s;

  ngx_conf_merge_str_value(conf->backend_name, prev->backend_name, "");
  if (conf->backend_name.len > 0) {
    amcf = ngx_http_conf_get_module_main_conf(cf, appdynamics_ngx_module);
    // TODO only add backend if it's not already there
    s = ngx_array_push(&amcf->backend_names);
    if (s == NULL) {
      return NGX_CONF_ERROR;
    }
    *s = conf->backend_name;
  }

  return NGX_CONF_OK;
}


static ngx_int_t 
appd_ngx_init_worker(ngx_cycle_t *cycle) {
  appd_ngx_main_conf_t *amcf;
  amcf = ngx_http_cycle_get_module_main_conf(cycle, appdynamics_ngx_module);
  if (amcf && amcf->enabled) {
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
  appd_config_set_app_name(cfg, (const char*)amcf->agent_app_name.data);
  appd_config_set_tier_name(cfg, (const char*)amcf->agent_tier_name.data);
  appd_config_set_node_name(cfg, (const char*)amcf->agent_node_name.data);
  appd_config_set_controller_certificate_dir(cfg, "/etc/ssl/certs");

  if (appd_sdk_init(cfg) != APPD_OK) {
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
    appd_backend_declare(APPD_BACKEND_HTTP, backend);
    if (appd_backend_set_identifying_property(backend, "HOST", backend) != APPD_OK) {
      return NGX_ERROR;
    }
    if (appd_backend_add(backend) != APPD_OK) {
      ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "MOD_APPD - failed to register backend %s - assuming this is because the backend was already registered", backend);
    }
  }
  return NGX_OK;
}

static ngx_int_t 
appd_ngx_register_handlers(ngx_conf_t *cf) {
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  appd_ngx_main_conf_t       *amcf;

  amcf = ngx_http_conf_get_module_main_conf(cf, appdynamics_ngx_module);

  if (amcf->enabled) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "MOD_APPD - appdynamics is enabled - configuring phase handlers");
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appd_ngx_rewrite_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appd_ngx_precontent_handler;
  }
  
  return NGX_OK;
}


/* --------------- functional stuff ------------------ */

static ngx_int_t 
appd_ngx_rewrite_handler(ngx_http_request_t *r) {
  appd_ngx_tracing_ctx *tc;
  appd_ngx_loc_conf_t *alcf;

  if (appd_ngx_get_module_ctx(r) != NULL) {
    // if the request already has a context associated with it
    // we're already instrumenting it
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
appd_ngx_precontent_handler(ngx_http_request_t *r) {
  appd_ngx_tracing_ctx *tc;
  appd_ngx_loc_conf_t *alcf;
  // TODO we're waiting until precontent to start any associated exit
  // to try to make sure any subrequest isn't included in the exit measurement.
  // This approach might be flawed, however, if precontent gets called for the
  // subrequest (don't fully understand subrequest lifecycle)

  alcf = ngx_http_get_module_loc_conf(r, appdynamics_ngx_module);
  if (alcf->backend_name.len > 0) {
    tc = appd_ngx_get_module_ctx(r);
    if (tc == NULL) {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "MOD_APPD - module context unexpectedly not found");
      return NGX_DECLINED;
    }
    appd_ngx_backend_begin(r, alcf, tc);
  }

  return NGX_DECLINED;
}


static ngx_int_t
appd_ngx_set_module_ctx(ngx_http_request_t *r, appd_ngx_tracing_ctx *ctx) {
  ngx_pool_cleanup_t  *cln;
  // we can't actually store appd context in the module context since the
  // module context is ZEROd out on internal redirect.  The only (current)
  // reliable way to end/cleanup the AppD BT is with a pool cleanup handler.
  // To a degree, this is a filthy hack since it really only relies on the fact
  // that pool cleanup handlers a) don't get modified by internal request processing
  // and b) they contain a "data" pointer (i.e. it's just a place to stash an
  // arbitrary pointer bound to the request lifecycle).
  // NOTE that unlike the normal set_ctx macro that can't fail, this "replacement"
  // op can fail
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

  // since context is stored in a cleanup handler, we gotta work a
  // bit to find it...
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
  // TODO i think we actually still want to call **_end() in the
  // LOG phase handler and just leave this empty
  appd_ngx_tracing_ctx *tc = data;
  if (tc->bt != NULL) {
    if (tc->exit != NULL) {
      appd_exitcall_end(tc->exit);
    }
    appd_bt_end(tc->bt);
  }
}


static void
appd_ngx_transaction_begin(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc) {
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - beginning appdynamics transaction");

  tc->bt = appd_bt_begin("request", NULL);
  appd_bt_set_url(tc->bt, appd_ngx_to_cstr(r->uri, r->pool));
}

static void
appd_ngx_backend_begin(ngx_http_request_t *r, appd_ngx_loc_conf_t *alcf, appd_ngx_tracing_ctx *tc) {
  const char *backend;
  const char *th;
  
  backend = (char *)alcf->backend_name.data;
  tc->exit = appd_exitcall_begin(tc->bt, backend);

  // this is a bit of a hack - opentelemetry handles correlation header injection by phonying a
  // set_proxy_header in the location config and uses a variable.  For now, we'll just append it
  // to the inbound request headers and assume proxy_pass_request_headers is on
  th = appd_exitcall_get_correlation_header(tc->exit);
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - correlating with header %s", th);
 // TODO add header to upstream request...somehow....
}



static char *
appd_ngx_to_cstr(ngx_str_t source, ngx_pool_t *pool) {
  char* c = ngx_pcalloc(pool, source.len + 1);
  ngx_memcpy(c, (char *) source.data, source.len);
  return c;
}
