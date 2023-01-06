
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
NGINX_OUT_DIR:=$(ROOT_DIR)/build/nginx
NGINX_SRC_DIR:=$(ROOT_DIR)/vendor/nginx
define nginx-configure
	cd $(NGINX_SRC_DIR) &&   \
	./auto/configure         \
     --with-cc-opt="-g -O0" \
     --with-debug           \
     --with-compat          \
     --builddir=$(NGINX_OUT_DIR) \
     --prefix=$(NGINX_OUT_DIR)   \
     --with-http_ssl_module \
     $(1);
endef

all: build

configure: configure-static
configure-static:
	$(call nginx-configure, "--add-module=$(ROOT_DIR)")
configure-dynamic:
	$(call nginx-configure, "--add-dynamic-module=$(ROOT_DIR)")

build-nginx:
	$(MAKE) -C $(NGINX_SRC_DIR) build install

	rm -f $(NGINX_SRC_DIR)/Makefile

	cd $(NGINX_OUT_DIR); \
	rm -f ./conf/nginx.conf && ln -s $(ROOT_DIR)/nginx.conf ./conf/nginx.conf

build: build-static
build-static: configure-static build-nginx
build-dynamic: configure-dynamic build-nginx

run:
	LD_LIBRARY_PATH=./vendor/appdynamics-cpp-sdk/lib ./build/nginx/sbin/nginx

cycle: compile run

test:
	for a in $$(seq 100); do \
		curl http://localhost:8888/; \
		curl http://localhost:8888/proxy-local/; \
		curl http://localhost:8888/proxy-remote/; \
		curl http://localhost:8888/index.html; \
		curl http://localhost:8888/proxy-remote/; \
		curl http://localhost:8888/proxy-remote-upstream/; \
		curl http://localhost:8888/login; \
		sleep 2; \
	done
