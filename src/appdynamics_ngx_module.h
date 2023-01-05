#ifndef _APPD_NGX_MODULE_H_INCLUDED_
#define _APPD_NGX_MODULE_H_INCLUDED_

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#include <appdynamics.h>
#define APPD_OK  0 /* AppD API says 0 is OK, nonzero is FAIL */

extern ngx_module_t appdynamics_ngx_module;

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
  ngx_array_t backend_names; /* ngx_str_t - collect all the backend names here so they can be init'd */
} appd_ngx_main_conf_t;
typedef struct {
  ngx_str_t backend_name;
} appd_ngx_loc_conf_t;

typedef struct {
  appd_bt_handle bt;
  appd_exitcall_handle exit;
} appd_ngx_tracing_ctx;


static ngx_command_t appd_ngx_commands[] = {
  {
    ngx_string("appdynamics"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, enabled),
    NULL
  },
  {
    ngx_string("appdynamics_controller_hostname"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, controller_hostname),
    NULL
  },
  {
    ngx_string("appdynamics_controller_port"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, controller_port),
    NULL
  },
  {
    ngx_string("appdynamics_controller_use_ssl"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, controller_use_ssl),
    NULL
  },
  {
    ngx_string("appdynamics_controller_account"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, controller_account),
    NULL
  },
  {
    ngx_string("appdynamics_controller_accesskey"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, controller_access_key),
    NULL
  },

  {
    ngx_string("appdynamics_agent_app_name"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, agent_app_name),
    NULL
  },
  {
    ngx_string("appdynamics_agent_tier_name"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, agent_tier_name),
    NULL
  },
  {
    ngx_string("appdynamics_agent_node_name"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(appd_ngx_main_conf_t, agent_node_name),
    NULL
  },

  { 
    ngx_string("appdynamics_backend"),
    NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(appd_ngx_loc_conf_t, backend_name),
    NULL 
  },

  ngx_null_command
};



static ngx_int_t appd_ngx_postconfiguration(ngx_conf_t *cf);
static void * appd_ngx_create_main_config(ngx_conf_t *cf);
static char * appd_ngx_init_main_config(ngx_conf_t *cf, void *conf);
static void * appd_ngx_create_loc_conf(ngx_conf_t *cf);
static char * appd_ngx_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_http_module_t appd_ngx_module_ctx = {
  NULL,   /* preconfiguration */
  appd_ngx_postconfiguration,   /* postconfiguration */
  appd_ngx_create_main_config,  /* create main configuration */
  appd_ngx_init_main_config,    /* init main configuration */
  NULL,   /* create server configuration */
  NULL,   /* merge server configuration */
  appd_ngx_create_loc_conf,  /* create location configuration */
  appd_ngx_merge_loc_conf    /* merge location configuration */
};

static ngx_int_t appd_ngx_init_worker(ngx_cycle_t *cycle);
static void      appd_ngx_exit_worker(ngx_cycle_t *cycle);
ngx_module_t appdynamics_ngx_module = {
  NGX_MODULE_V1,
  &appd_ngx_module_ctx, /* module context */
  appd_ngx_commands,    /* module directives */
  NGX_HTTP_MODULE,      /* module type */
  NULL,      /* init master */
  NULL,      /* init module - prior to forking from master process */
  appd_ngx_init_worker, /* init process - worker process fork */
  NULL,      /* init thread */
  NULL,      /* exit thread */
  appd_ngx_exit_worker, /* exit process - worker process exit */
  NULL,      /* exit master */
  NGX_MODULE_V1_PADDING,
};


static ngx_int_t appd_ngx_rewrite_handler(ngx_http_request_t *req);
static ngx_int_t appd_ngx_precontent_handler(ngx_http_request_t *req);

static ngx_int_t appd_ngx_sdk_init(ngx_cycle_t *cycle, appd_ngx_main_conf_t *amcf);
static ngx_int_t appd_ngx_backends_init(ngx_cycle_t *cycle, appd_ngx_main_conf_t *amcf);

static void appd_ngx_transaction_begin(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc);
//static void appd_ngx_transaction_end(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc);
static void appd_ngx_backend_begin(ngx_http_request_t *r, appd_ngx_loc_conf_t *alcf, appd_ngx_tracing_ctx *tc);
//static void appd_ngx_backend_end(ngx_http_request_t *r, appd_ngx_tracing_ctx *tc);

static char * appd_ngx_generate_transaction_name(ngx_http_request_t *r);
static ngx_table_elt_t * appd_ngx_find_header(ngx_http_request_t *r, ngx_str_t *name);
static void appd_ngx_insert_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value);
static void appd_ngx_upsert_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value);

static appd_ngx_tracing_ctx * appd_ngx_get_module_ctx(ngx_http_request_t *r);
static ngx_int_t              appd_ngx_set_module_ctx(ngx_http_request_t *r, appd_ngx_tracing_ctx *ctx);
static void                   appd_ngx_cleanup_module_ctx(void *data);


static char * appd_ngx_to_cstr(ngx_str_t source, ngx_pool_t *pool);
static ngx_str_t * appd_ngx_cstr_to_ngx(char * source, ngx_pool_t *pool);

static ngx_str_t APPD_NGX_SINGULARITY_HEADER = ngx_string(APPD_CORRELATION_HEADER_NAME);

#endif

