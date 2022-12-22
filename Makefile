all: cycle

module:
	./compile
module-dynamic:
	./compile dynamic
nginx:
	./compile skip

run:
	LD_LIBRARY_PATH=./vendor/appdynamics-cpp-sdk/lib ./build/nginx/sbin/nginx -g "daemon off;"
start:
	LD_LIBRARY_PATH=./vendor/appdynamics-cpp-sdk/lib ./build/nginx/sbin/nginx 2>/dev/null || echo "already running"
stop:
	LD_LIBRARY_PATH=./vendor/appdynamics-cpp-sdk/lib ./build/nginx/sbin/nginx -s quit 2>/dev/null || echo "not running"
reload:
	LD_LIBRARY_PATH=./vendor/appdynamics-cpp-sdk/lib ./build/nginx/sbin/nginx -s reload 2>/dev/null || echo "not running"
restart: stop start

cycle: module run


test:
	for a in $$(seq 10); do \
		curl http://localhost:8888/; \
		curl http://localhost:8888/proxy-local/; \
		curl http://localhost:8888/proxy-remote/; \
		curl http://localhost:8888/proxy-remote-upstream/; \
		sleep 2; \
	done
