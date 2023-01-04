http://nginx.org/en/docs/dev/development_guide.html
https://nginxguts.com/2011/01/phases.html

https://github.com/open-telemetry/opentelemetry-cpp-contrib/tree/main/instrumentation/nginx
https://github.com/opentracing-contrib/nginx-opentracing

set proxy header
https://mailman.nginx.org/pipermail/nginx-devel/2018-March/011008.html


https://docs.appdynamics.com/appd/21.x/21.4/en/application-monitoring/install-app-server-agents/c-c++-sdk/use-the-c-c++-sdk



QUESTIONS
- what's the configuration lifecycle?  only want main/server confs, but how does location config work?
- do the directive util macros need merge to be implemented?



capturing proxied requests as a custom upstream


DESIGN DECISIONS
re: the need for appdynamics_backend config parameter
none of the "upstream" modules (proxy_module, fastcgi_module...or upstream_module itself) provide extension points 
to properly intercept upstream calls (even worse, the upstreams themselves implement the request.handler
which prevents certain phase handlers from being called). This ends up making it impossible to 
a) automatically discover the upstream URL to use as the exitcall name and b) add the correlation
header to the upstream call (by the time we can hit some "extension" point that has the upstream
URL, the upstream request headers have already been buffered up - but the AppD API needs to first 
create the exitcall handle with the exitcall name BEFORE you can get the correlationId for the header).

also, none of the upstream modules publically expose their configuration objects (structs and module
name are static) so we can't simply read proxy/fastcgi/etc_module's config from the appdynamics module.

as a workaround to this, we need to use the appdynamics_backend location config to basically mirror
the proxy_pass config (allowing it to be available to the appdynamics_module).  But for the same
"ordering of operations" issue, the appdynamics_backend config cannot use any of the proxy_module's
variables (they're not set in time!)  But there's still a bit of an issue - we'll create an exitcall
EVERY time we run a request handled by a location with appdynamics_backend in it (even if there
is no proxy_pass config in the location!), and will basically assume the entire request is taken
up by upstream processing (i.e. we'll start/end the BT and exitcall at the same time) - this could
end up being very wrong if subrequests are involved (those subrequests will count as the backend
duration)....although we'll eventually look into the AppD API for overriding exitcall timings.

re: bt/exitcall handles (context) + handlers
internal redirects zero out the module's context and restart the processing phases, making
module context an inappropriate place to place handles that need to be cleaned up (appd BTs).
Instead, we'll use a pool cleanup handler as the primary context storage and "request end"
handler.  Although a bit hacky, the Nginx Development Guide itself describes pool cleanup
handlers as 'a convenient way to release resources, close file descriptors or make final 
adjustments to the shared data associated with the main object.'

internal redirects also short circuit the phase-handler lifecycle (the redirect essentially 
triggers a new phase-handler lifecycle, abandoning the current one) - another reason why we
can't rely on phase-handlers for cleanup.