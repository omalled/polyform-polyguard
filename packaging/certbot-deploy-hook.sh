#!/bin/sh
set -eu

config=${POLYGUARD_NGINX_CONFIG:-/etc/nginx/nginx.conf}
binary=${POLYGUARD_BINARY:-/usr/local/bin/polyguard}

"$binary" --check-nginx "$config"
systemctl reload polyguard
