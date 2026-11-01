#!/bin/sh
# edge-guard installer (Linux, systemd): the latest release (or VERSION=v1.2.3)
# from GitHub, a system user, /etc/edge-guard with an example config, the unit.
# It does not start the service: put the keys in /etc/edge-guard/env, edit
# /etc/edge-guard/config.yaml, then:
#   edge-guard -check -online -config /etc/edge-guard/config.yaml
#   systemctl enable --now edge-guard
set -eu
REPO=axgrid/edge-guard
VERSION=${VERSION:-latest}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$VERSION" = latest ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "downloading edge-guard-$OS-$ARCH ($VERSION)"
curl -fsSL "$BASE/edge-guard-$OS-$ARCH" -o "$TMP/edge-guard"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
(cd "$TMP" && grep " edge-guard-$OS-$ARCH\$" SHA256SUMS | sed "s/edge-guard-$OS-$ARCH/edge-guard/" | sha256sum -c -)
install -m 755 "$TMP/edge-guard" /usr/local/bin/edge-guard

id edge-guard >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin edge-guard
install -d -m 750 -g edge-guard /etc/edge-guard
if [ ! -f /etc/edge-guard/config.yaml ]; then
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/examples/config.yaml" -o /etc/edge-guard/config.yaml
  chgrp edge-guard /etc/edge-guard/config.yaml && chmod 640 /etc/edge-guard/config.yaml
fi
[ -f /etc/edge-guard/env ] || install -m 600 /dev/null /etc/edge-guard/env
if command -v systemctl >/dev/null 2>&1; then
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/deploy/edge-guard.service" -o /etc/systemd/system/edge-guard.service
  systemctl daemon-reload
fi
/usr/local/bin/edge-guard -version
echo "next: keys in /etc/edge-guard/env, apps in /etc/edge-guard/config.yaml,"
echo "      edge-guard -check -online -config /etc/edge-guard/config.yaml && systemctl enable --now edge-guard"
