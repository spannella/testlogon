#!/bin/sh
set -eu

TOKEN_SECRET="${CACHE_TOKEN_SECRET:-local-cache-secret}"

cat > /etc/nginx/conf.d/default.conf <<CONF
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=hls_cache:20m max_size=1g inactive=20m use_temp_path=off;

log_format cachelog '\$remote_addr - \$remote_user [\$time_local] "\$request" \$status \$body_bytes_sent '
                   '"\$http_referer" "\$http_user_agent" cache=\$upstream_cache_status '
                   'upstream=\$upstream_addr';

server {
  listen 80;
  access_log /var/log/nginx/access.log cachelog;

  location /hls/ {
    secure_link \$arg_md5,\$arg_expires;
    secure_link_md5 "\$secure_link_expires\$uri ${TOKEN_SECRET}";
    if (\$secure_link = "") { return 403; }
    if (\$secure_link = "0") { return 410; }

    proxy_pass http://hls-origin/hls/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_cache hls_cache;
    proxy_cache_valid 200 302 30s;
    proxy_cache_valid 404 10s;
    proxy_ignore_headers Cache-Control Expires Set-Cookie;
    add_header X-Cache-Status \$upstream_cache_status always;
    add_header Cache-Control "public, max-age=30" always;
  }
}
CONF

nginx -g 'daemon off;'
