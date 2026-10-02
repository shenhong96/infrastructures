# Caddy 2.8.4 with the two plugins, pinned to what CT 104 has run since 2024-07 (from
# `caddy build-info`: go1.22.5, caddy-dns/cloudflare 89f16b99c18e of 2024-07-03, caddy2-filter
# 04be952a71e1 of 2023-03, which injects the theme-park CSS). An upgrade is a deliberate
# change: caddy2-filter is unmaintained and may not build against a newer Caddy.
FROM caddy:2.11.4-builder-alpine AS builder

RUN xcaddy build v2.8.4 \
    --with github.com/caddy-dns/cloudflare@89f16b99c18e \
    --with github.com/sjtug/caddy2-filter@04be952a71e1

FROM caddy:2.11.4-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
