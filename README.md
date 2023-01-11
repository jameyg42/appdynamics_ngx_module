AppDynamics Nginx Module
========
name: appdynamics_ngx_module

An Nginx module for monitoring using AppDynamics.  Currently, this
can be used to create/record BTs and Exit Calls, and collect
data into Snapshots.

## Table of Contents

- [Status](#status)
- [Installation](#installation)
- [Configuration directives](#configuration-directives)
  - [`appdynamics`](#appdynamics)
  - [`appdynamics_controller_hostname`](#appdynamics-controller-hostname)
  - [`appdynamics_controller_port`](#appdynamics-controller-port)
  - [`appdynamics_controller_use_ssl`](#appdynamics-controller-use-ssl)
  - [`appdynamics_controller_account`](#appdynamics-controller-account)
  - [`appdynamics_controller_accesskey`](#appdynamics-controller-accesskey)
  - [`appdynamics_controller_certificate_file`](#appdynamics-controller-certificate-file)
  - [`appdynamics_agent_app_name`](#appdynamics-agent-app-name)
  - [`appdynamics_agent_tier_name`](#apdynamics-agent-tier-name)
  - [`appdynamics_agent_node_name`](#appdynamics-agent-node-name)
  - [`appdynamics_bt_name`](#appdynamics-bt-name)
  - [`appdynamics_bt_name_max_segments`](#appdynamics-bt-name-max-segments)
  - [`appdynamics_backend`](#appdynamics-backend)
  - [`appdynamics_add_collector`](#appdynamics-add-collector)
  - [`appdynamics_error_on_4xx`](#appdynamics-error-on-4xx)
- [Sample configuration](#sample-configuration)
- [Transaction Naming](#transaction-naming)
- [Design Notes](#design-notes)

## Status
BETA (active development) - developed/tested against Nginx 1.23.4 and AppDynamics C++ SDK 22.7

## Installation
The `appdynamics_ngx_module` is not known to be affected by module
load order.  
### Dynamically loaded

    $ cd nginx-1.x.x
    $ ./configure --with-compat --add-dynamic-module=/path/to/module
    $ make modules

You will need to use **exactly** the same `./configure` arguments as your Nginx configuration and append `--with-compat --add-dynamic-module=/path/to/module` to the end, otherwise you will get a "module is not binary compatible" error on startup. You can run `nginx -V` to get the configuration arguments for your Nginx installation.

`make modules` will result in `appdynamics_ngx_module.so` in the `objs` directory. Copy these to `/usr/lib/nginx/modules/` then add the `load_module` directives to `nginx.conf` (above the http block):
```nginx
load_module modules/appdynamics_ngx_module.so;
```

### Statically compiled

    $ cd nginx-1.x.x
    $ ./configure --add-module=/path/to/module
    $ make && make install
  
This will compile the module directly into Nginx.

### AppDynamics library
The AppDynamics C++ Agent library is currently only distributed as a dynamic library, and needs to be "installed"
and available to the appdynamics_ngx_module's library path.  
See https://docs.appdynamics.com/appd/22.x/22.2/en/application-monitoring/install-app-server-agents/c-c++-sdk for more information.

## Configuration directives
See https://docs.appdynamics.com/appd/22.x/22.2/en/application-monitoring/install-app-server-agents/c-c++-sdk/use-the-c-c++-sdk#id-.UsetheCCPPSDKv22.1-InitializetheControllerConfiguration for additional information on meaning / defaults / etc.

### `appdynamics`

- **syntax**: `appdynamics on|off`
- **context**: `http`
- **default**: `off`

Enables or disables AppDynamics monitoring for the Nginx runtime.

### `appdynamics_controller_hostname`

- ***syntax**: `appdynamics_controller_hostname <name>`
- ***context**: `http`
- ***requred**: `yes`

### `appdynamics_controller_port`

- ***syntax**: `appdynamics_controller_port <number>`
- ***context**: `http`

### `appdynamics_controller_use_ssl`

- ***syntax**: `appdynamics_controller_use_ssl on|off`
- ***context**: `http`

### `appdynamics_controller_account`

- ***syntax**: `appdynamics_controller_account <name>`
- ***context**: `http`
- ***requred**: `yes`

### `appdynamics_controller_accesskey`

- ***syntax**: `appdynamics_controller_accesskey <key>`
- ***context**: `http`
- ***requred**: `yes`

### `appdynamics_controller_certificate_file`

- ***syntax**: `appdynamics_controller_hostname <name>`
- ***context**: `http`
- ***required**: probably...

If the Controller uses SSL, you will likely need to point the module
to a trustStore that can be used to validate the Controller's cert.
The SDK documentation does not specify what, if any, default trustStore
is used and somewhat incorrectly states that a trustStore only needs
to be configured if using a self-signed cert.  The SDK library appears
to be statically linked against OpenSSL which likely doesn't configure
any default trusts.

### `appdynamics_agent_app_name`

- ***syntax**: `appdynamics_agent_app_name <name>`
- ***context**: `http`
- ***requred**: `yes`

### `appdynamics_agent_tier_name`

- ***syntax**: `appdynamics_agent_tier_name <name>`
- ***context**: `http`
- ***requred**: `yes`

### `appdynamics_agent_node_name`

- ***syntax**: `appdynamics_agent_node_name <name>`
- ***context**: `http`
- ***requred**: `yes`

When Nginx is configured to use worker processes (`master on`), this
configuration acts as a "prefix" - the node will be named with the
hostname and worker id appended to the end of this prefix.  This is
necessary because a) AppDynamics requires each child process to be 
configured as a separate SDK instance, b) each SDK instance needs a
unique name, and c) Nginx does not support the use of `$variables` at
configuration time.  In the future, a more flexible node_name
configuration mechanism may be supported.

### `appdynamics_bt_name`

- ***syntax**: `appdynamics_bt_name <name>`
- ***context**: `location`
- ***default**: first `bt_max_segments` non-file path segments of URL

The Business Transaction name for all requests matching the `location`.
See "[Transaction Naming](#transaction-naming)" below for more information.

### `appdynamics_bt_name_max_segments`

- ***syntax**: `appdynamics_bt_max_segments <number>`
- ***context**: `location`
- ***default**: 3

When using 'automatic naming' (`bt_name` not set for the `location`), the
maximum number of path segments used to name the transaction. 
See "[Transaction Naming](#transaction-naming)" below for more information.

### `appdynamics_backend`

- ***syntax**: `appdynamics_backend <name>`
- ***context**: `location`

Treats the `location` as an Exit Call.  This is intended to be used
in conjunction with some type of upstream for the `location` (e.g. 
`proxy_pass`) and is typically the same value as `proxy_pass` (although
variables/capture-groups are NOT supported).  See "[Design](#design-notes)" below for more information.

### `appdynamics_add_collector`

- ***syntax**: `appdynamics_add_collector <key> <value>`
- ***context**: `http,server,location`

Collects the specified key+value pair as transaction/analytics
data.  Values can contain `$variables`.  Collectors are added
together across configuration blocks.

### `appdynamics_error_on_4xx`

- ***syntax**: `appdynamics_error_on_4xx on|off`
- ***context**: `http,server,location`
- ***default**: `off`

Whether to treat HTTP 4xx response codes as errors (mark the BT
and/or upstream as "errored").

## Sample configuration
```
http {
  appdynamics on;
  appdynamics_controller_hostname system.saas.appdynamics.com;
  appdynamics_controller_port 443;
  appdynamics_controller_use_ssl on;
  appdynamics_controller_account account1;
  appdynamics_controller_accesskey xxxxxyyyyzzzz;
  appdynamics_controller_certificate_file /etc/ssl/certs/ca-certificates.crt;
  appdynamics_agent_app_name "My Application";
  appdynamics_agent_tier_name nginx;
  appdynamics_agent_node_name nginx;

  server {
    listen 8888;
    appdynamics_add_collector x_forwarded_for $http_x_forwarded_for;

    location /upstream/ {
      proxy_pass http://some.server.com/;
      appdynamics_backend http://some.server.com;
    }

    location /explicity-names/ {
      appdynamics_bt_name "My Explicitly Named BT"
    }
  }
}
```

## Transaction naming
BTs are currently named either explicitly using the `appdynamics_bt_name`
configuration directive, or automatically using automatic naming.

Automatic naming works similar to AppDynamics own default Automatic
Discovery transaction naming mecanism.  It will use the first 
`appdynamics_bt_name_max_segments` (default 3) segments of the URL 
path, excluding the last path segment if it appears to be a "file" 
(e.g. image.jpg, index.html).


## Design notes

### Backend detection
Unfortunately, Nginx does not (currently) provide a way automatically
detect upstream calls before the upstream itself is called (that is, at
a point in the request processing that would allow us to start an 
AppDynamics exit call and inject the correlation headers into the upstream
call).  Nginx also does not provide a portable way to access the
`proxy_pass` (or similar upstream) from ouside the `ngx_http_proxy_module`
itself.

As a workaround, the `appdynamics_backend` configuration directive was 
introduced.  Any location that includes a `appdynamics_backend` will
create an exit call (appd_exitcall_begin) during the `NGINX_PRECONTENT`
phase, even if no upstream is actually configured for the `location` 
(it's the responsibility of nginx.conf to ensure that no "bogus" backends
are configured for the location).

### Nginx subrequests
Other than their inclusion in the BT timings, Nginx subrequests aren't 
currently handled in any meaninful way.

### Call graphs
The module creates "dummy" call graph stack frames for the `NGINX_ACCESS`
and `NGINX_CONTENT` phases.

### Internal redirects and module context
Internal redirects empty out the Nginx module context and restart the
request processing phases with no notification to modules.  Because of
this, we cannot rely on module context to store the BT/exit/etc handles
because they may be ZEROd out by an internal redirect before we get a 
chance to handle the closes in the LOG phase handler (i.e. the end
of the request).  As a workaround, we use a pool cleanup handler for the
request (ngx_http_request_t) pool to store the handles and try to
detect/ignore request phase restarts (i.e. don't create multiple BTs
after the internal redirect, but rather absorb the redirect into the
original BTs timings).

Please report any cases where this strategy does not work!

