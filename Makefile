all: cycle

compile: compile-module-static
compile-module-static:
	./compile
compile-module-dynamic:
	./compile dynamic
compile-nginx:
	./compile skip

run:
	LD_LIBRARY_PATH=./vendor/appdynamics-cpp-sdk/lib ./build/nginx/sbin/nginx

cycle: compile run

test:
	for a in $$(seq 100); do \
		curl http://localhost:8888/index.html; \
		curl http://localhost:8888/; \
		curl http://localhost:8888/proxy-remote/; \
		curl http://localhost:8888/proxy-remote-upstream/; \
		sleep 2; \
	done
