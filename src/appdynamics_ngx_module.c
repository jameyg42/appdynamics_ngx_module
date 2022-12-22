#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#include <appdynamics.h>

extern ngx_module_t appdynamics_ngx_module;

static void * appdynamics_create_main_config(ngx_conf_t *cf);
static char * appdynamics_init_main_config(ngx_conf_t *cf, void *conf);
static void * appdynamics_create_server_config(ngx_conf_t *cf);
static void * appdynamics_create_loc_conf(ngx_conf_t *cf);
static char * appdynamics_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t appdynamics_wrap_location_handler(ngx_http_request_t *r);

static ngx_int_t appdynamics_register_handlers(ngx_conf_t *cf);
static ngx_int_t appdynamics_init_worker(ngx_cycle_t *cycle);

static char * to_cstr(ngx_str_t source, ngx_pool_t *pool);


static char * appdynamics_set_upstream_handling(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t appdynamics_init_upstream_handling(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t appdynamics_init_upstream_handling_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);


typedef struct  {
  ngx_flag_t enabled;
  ngx_str_t controller_hostname;
  ngx_int_t controller_port;
  ngx_flag_t controller_use_ssl;
  ngx_str_t controller_account;
  ngx_str_t controller_access_key;
  
  ngx_str_t agent_app_name;
  ngx_str_t agent_tier_name;
  ngx_str_t agent_node_name;
} appdynamics_main_conf_t;
typedef struct {
  ngx_http_upstream_init_pt       original_init_upstream;
  ngx_http_upstream_init_peer_pt  original_init_peer;
} appdynamics_server_conf_t;
typedef struct {
  ngx_int_t proxy_host_index;
  ngx_http_handler_pt  original_handler;
} appdynamics_loc_conf_t;
typedef struct {
  appd_bt_handle bt;
  appd_exitcall_handle exit;
} appdynamics_tracing_ctx;

static ngx_command_t appdynamics_ngx_commands[] = {
  {
    ngx_string("appdynamics"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, enabled),
    NULL
  },
  {
    ngx_string("appdynamics_controller_hostname"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, controller_hostname),
    NULL
  },
  {
    ngx_string("appdynamics_controller_port"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, controller_port),
    NULL
  },
  {
    ngx_string("appdynamics_controller_use_ssl"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, controller_use_ssl),
    NULL
  },
  {
    ngx_string("appdynamics_controller_account"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, controller_account),
    NULL
  },
  {
    ngx_string("appdynamics_controller_accesskey"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, controller_access_key),
    NULL
  },


  {
    ngx_string("appdynamics_agent_app_name"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, agent_app_name),
    NULL
  },
  {
    ngx_string("appdynamics_agent_tier_name"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, agent_tier_name),
    NULL
  },
  {
    ngx_string("appdynamics_agent_node_name"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appdynamics_main_conf_t, agent_node_name),
    NULL
  },

  { 
    ngx_string("appdynamics_upstream_handling"),
    NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
    appdynamics_set_upstream_handling,
    NGX_HTTP_SRV_CONF_OFFSET,
    0,
    NULL 
  },

  ngx_null_command
};


static ngx_http_module_t appdynamics_ngx_module_ctx = {
  NULL,   /* preconfiguration */
  appdynamics_register_handlers,   /* postconfiguration */
  appdynamics_create_main_config,  /* create main configuration */
  appdynamics_init_main_config,    /* init main configuration */
  appdynamics_create_server_config,/* create server configuration */
  NULL,   /* merge server configuration */
  appdynamics_create_loc_conf,   /* create location configuration */
  appdynamics_merge_loc_conf    /* merge location configuration */
};

ngx_module_t appdynamics_ngx_module = {
  NGX_MODULE_V1,
  &appdynamics_ngx_module_ctx, /* module context */
  appdynamics_ngx_commands,    /* module directives */
  NGX_HTTP_MODULE,             /* module type */
  NULL,      /* init master */
  NULL,      /* init module - prior to forking from master process */
  appdynamics_init_worker,      /* init process - worker process fork */
  NULL,      /* init thread */
  NULL,      /* exit thread */
  NULL,      /* exit process - worker process exit */
  NULL,      /* exit master */
  NGX_MODULE_V1_PADDING,
};

static void *
appdynamics_create_main_config(ngx_conf_t *cf) {
  appdynamics_main_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(appdynamics_main_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->enabled = NGX_CONF_UNSET;
  conf->controller_use_ssl = NGX_CONF_UNSET;
  conf->controller_port = NGX_CONF_UNSET;

  return conf;
}
static char *
appdynamics_init_main_config(ngx_conf_t *cf, void *conf) {
  // appdynamics_main_conf_t *main = conf;
  // TODO validate configuration

  return NGX_CONF_OK;
}
static void *
appdynamics_create_server_config(ngx_conf_t *cf) {
  appdynamics_server_conf_t *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(appdynamics_server_conf_t));
  return conf;
}

static void * 
appdynamics_create_loc_conf(ngx_conf_t *cf) {
  appdynamics_loc_conf_t *conf;
  conf = ngx_pcalloc(cf->pool, sizeof(appdynamics_loc_conf_t));

  return conf;
}
static char * 
appdynamics_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  // all the "proxy" types end up setting clcf->handler which replaces calling registered
  // phase handlers.  In order to capture exit calls, we need to "wrap" that handler
  ngx_http_core_loc_conf_t *clcf;
  appdynamics_loc_conf_t   *conf = child;


  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  if (clcf->handler != NULL && conf->original_handler == NULL) {
ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "appdynamics_wrap_location_handler : overriding original content handler for LOC");
    conf->original_handler = clcf->handler;
    clcf->handler = appdynamics_wrap_location_handler;
  }

  ngx_str_t proxy_host = ngx_string("proxy_host");
  conf->proxy_host_index = ngx_http_get_variable_index(cf, &proxy_host);

  return NGX_CONF_OK;
}

static ngx_int_t 
appdynamics_wrap_location_handler(ngx_http_request_t *r) {
  appdynamics_loc_conf_t *alcf;
  appdynamics_tracing_ctx *actx;

  alcf = ngx_http_get_module_loc_conf(r, appdynamics_ngx_module);
  actx = ngx_http_get_module_ctx(r, appdynamics_ngx_module);

  ngx_int_t orig = alcf->original_handler(r);

  // at this time, mod_proxy (and similar) have created the upstream request and have connected to the upstream,
  // but have NOT sent the request (including headers) to the upstream.
  ngx_http_upstream_t *u;
  u = r->upstream;
  
  u_char *exit_name;
  exit_name = ngx_pcalloc(r->pool, u->schema.len + u->upstream->host.len + 1);
  if (exit_name != NULL) {
    // don't error the request if we can't alloc for the exit
    (void) ngx_sprintf(exit_name, "%V%V", &u->schema, &u->upstream->host);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MOD_APPD - created exit for %s", exit_name);

    // FIXME need to ACTUALLY figure out how to track backends that are already registered
    actx->exit = appd_exitcall_begin(actx->bt, (const char*)exit_name);
    if (actx->exit == NULL) {
      ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - registering new backend for  %s", exit_name);
      appd_backend_declare(APPD_BACKEND_HTTP, (const char*)exit_name);
      appd_backend_set_identifying_property((const char*)exit_name, "HOST", (const char*)exit_name);
      appd_backend_add((const char*)exit_name);
      actx->exit = appd_exitcall_begin(actx->bt, (const char*)exit_name);
    }

    
  }

  return orig;
}


static ngx_int_t 
appdynamics_init_worker(ngx_cycle_t *cycle) {
  appdynamics_main_conf_t *main;
  main = ngx_http_cycle_get_module_main_conf(cycle, appdynamics_ngx_module);

  if (main->enabled) {
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "controller_host      : %s:%d", main->controller_hostname.data, main->controller_port);
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "controller_account   : %V", &main->controller_account);
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "controller_accesskey : %V", &main->controller_access_key);
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "agent_name           : %V->%V", &main->agent_app_name, &main->agent_tier_name);

    struct appd_config* cfg = appd_config_init();
    appd_config_set_controller_host(cfg, (const char*)main->controller_hostname.data);
    appd_config_set_controller_port(cfg, main->controller_port);
    appd_config_set_controller_account(cfg, (const char*)main->controller_account.data);
    appd_config_set_controller_access_key(cfg, (const char*)main->controller_access_key.data);
    appd_config_set_controller_use_ssl(cfg, main->controller_use_ssl);
    appd_config_set_app_name(cfg, (const char*)main->agent_app_name.data);
    appd_config_set_tier_name(cfg, (const char*)main->agent_tier_name.data);
    appd_config_set_node_name(cfg, (const char*)main->agent_node_name.data);
    appd_config_set_controller_certificate_dir(cfg, "/etc/ssl/certs");
    int rc = appd_sdk_init(cfg);
    if (rc) {
      return NGX_ERROR;
    }
  }
  return NGX_OK;
}

// handler registration
static ngx_int_t appdynamics_rewrite_handler(ngx_http_request_t *req);
static ngx_int_t appdynamics_log_handler(ngx_http_request_t *req);
void appdynamics_begin_transaction(ngx_http_request_t *r);
void appdynamics_end_transaction(ngx_http_request_t *r);

static ngx_int_t 
appdynamics_register_handlers(ngx_conf_t *cf) {
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  appdynamics_main_conf_t    *amcf;

  amcf = ngx_http_conf_get_module_main_conf(cf, appdynamics_ngx_module);

  if (amcf->enabled) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "appdynamics is enabled - configuring phase handlers");
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appdynamics_rewrite_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
      return NGX_ERROR;
    }
    *h = appdynamics_log_handler;
  }
  
  return NGX_OK;
}


// handlers
static ngx_int_t 
appdynamics_rewrite_handler(ngx_http_request_t *r) {
  appdynamics_begin_transaction(r);
  return NGX_DECLINED;
}

static ngx_int_t 
appdynamics_log_handler(ngx_http_request_t *r) {
  appdynamics_end_transaction(r);

  return NGX_DECLINED;
}

void
appdynamics_begin_transaction(ngx_http_request_t *r) {
  appdynamics_tracing_ctx *tc;

  // TODO don't call if a subrequest/redirect
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - beginning appdynamics transaction");
  tc = ngx_palloc(r->pool, sizeof(appdynamics_tracing_ctx));
  ngx_http_set_ctx(r, tc, appdynamics_ngx_module);

  tc->exit = NULL;
  tc->bt = appd_bt_begin("request", NULL);
  appd_bt_set_url(tc->bt, to_cstr(r->uri, r->pool));
}

void 
appdynamics_end_transaction(ngx_http_request_t *r) {
  appdynamics_tracing_ctx *tc;
  tc = ngx_http_get_module_ctx(r, appdynamics_ngx_module);
  if (tc != NULL) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - ending appdynamics transaction");
    if (tc->exit != NULL) {
      appd_exitcall_end(tc->exit);
    }
    appd_bt_end(tc->bt);
  } else {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MOD_APPD - error ending appdynamics transaction - trace context not found");

  }
}

static char *
to_cstr(ngx_str_t source, ngx_pool_t *pool) {
  char* c = ngx_pcalloc(pool, source.len + 1);
  ngx_memcpy(c, (char *) source.data, source.len);
  return c;
}





static char * 
appdynamics_set_upstream_handling(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  ngx_log_error(NGX_LOG_ERR, cf->log, 0, "appdynamics_set_upstream_handling");
  ngx_http_upstream_srv_conf_t *uscf;
  appdynamics_server_conf_t  *ascf = conf;

  uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
  ascf->original_init_upstream = uscf->peer.init_upstream
                                ? uscf->peer.init_upstream
                                : ngx_http_upstream_init_round_robin;
  uscf->peer.init_upstream = appdynamics_init_upstream_handling;
  ngx_log_error(NGX_LOG_ERR, cf->log, 0, "appdynamics_set_upstream_handling - intercepted handler");
  return NGX_CONF_OK;
}
static ngx_int_t 
appdynamics_init_upstream_handling(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us) {
  ngx_log_error(NGX_LOG_ERR, cf->log, 0, "appdynamics_init_upstream_handling");
  appdynamics_server_conf_t  *ascf;
  ascf = ngx_http_conf_upstream_srv_conf(us, appdynamics_ngx_module);

  ngx_log_error(NGX_LOG_ERR, cf->log, 0, "appdynamics_init_upstream_handling - calling original handler");
  if (ascf->original_init_upstream(cf, us) != NGX_OK) {
    return NGX_ERROR;
  }
  ngx_log_error(NGX_LOG_ERR, cf->log, 0, "appdynamics_init_upstream_handling - original called successfully");

  ascf->original_init_peer = us->peer.init;
  us->peer.init = appdynamics_init_upstream_handling_peer;
  ngx_log_error(NGX_LOG_ERR, cf->log, 0, "appdynamics_init_upstream_handling - intercepted peer handler");
  return NGX_OK;
}
static ngx_int_t
appdynamics_init_upstream_handling_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - appdynamics_init_upstream_handling_peer");
  appdynamics_server_conf_t  *ascf;
  ascf = ngx_http_conf_upstream_srv_conf(us, appdynamics_ngx_module);

  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - appdynamics_init_upstream_handling_peer - calling original handler");
  if (ascf->original_init_peer(r, us) != NGX_OK) {
    return NGX_ERROR;
  }
  ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "MOD_APPD - appdynamics_init_upstream_handling_peer - original called successfully");

  return NGX_OK;

}
