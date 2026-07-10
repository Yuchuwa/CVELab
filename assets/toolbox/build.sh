#!/usr/bin/env bash
# 生成静态工具箱二进制,供每个 target 容器 bind-mount 到 /opt/toolbox:ro。
# 静态二进制(static-pie)跨 glibc/musl 通吃,解决 vulhub 弱镜像缺 nc/wget/反弹工具的问题。
# 详见 docs/PIVOT_HOST_TO_TOOLBOX_PLAN.md
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/2] busybox (Alpine busybox-static 包, static-pie, 含 nc/wget/telnet/httpd/sh)"
docker run --rm alpine:latest sh -c '
  apk add --no-cache busybox-static >/dev/null 2>&1
  cat /bin/busybox.static
' > busybox
chmod +x busybox
if ! ./busybox --help >/dev/null 2>&1; then
  rm -f busybox
  echo "FAIL: busybox 生成后在宿主机无法运行" >&2
  exit 1
fi
echo "    -> $(stat -c%s busybox) bytes, $(file -b busybox 2>/dev/null | cut -d, -f1-3)"

echo "[2/2] socat (静态编译, 端口转发/横向 pivot)"
# 优先用本地 tarball;否则尝试下载 1.7.4.4
SOCAT_TGZ=""
for f in socat-*.tar.gz; do
  if [ -f "$f" ] && gzip -t "$f" 2>/dev/null; then SOCAT_TGZ="$PWD/$f"; break; fi
done
if [ -z "$SOCAT_TGZ" ]; then
  echo "    本地无 socat tarball,尝试下载 1.7.4.4..."
  for url in \
    "https://www.dest-unreach.org/socat/download/socat-1.7.4.4.tar.gz" \
    "https://fossies.org/linux/misc/socat-1.7.4.4.tar.gz"; do
    if wget -q "$url" -O socat-1.7.4.4.tar.gz 2>/dev/null && gzip -t socat-1.7.4.4.tar.gz 2>/dev/null; then
      SOCAT_TGZ="$PWD/socat-1.7.4.4.tar.gz"; break
    fi
  done
fi

if [ -n "$SOCAT_TGZ" ]; then
  docker run --rm -v "$SOCAT_TGZ:/src/socat.tar.gz:ro" alpine:latest sh -c '
    set -e
    apk add --no-cache build-base openssl-dev openssl-libs-static >/dev/null 2>&1
    cd /tmp && gzip -dc /src/socat.tar.gz | tar x && cd socat-*
    ./configure --disable-readline >/dev/null 2>&1
    make -j"$(nproc)" LDFLAGS="-static" >/dev/null 2>&1
    cat socat
  ' > socat 2>/dev/null && chmod +x socat
  strip socat 2>/dev/null || true
  if ./socat -V >/dev/null 2>&1; then
    echo "    -> $(stat -c%s socat) bytes, $(file -b socat 2>/dev/null | cut -d, -f1-3)"
  else
    rm -f socat
    echo "    !! socat 编译失败,仅 busybox 可用(busybox 已覆盖 nc/wget/反弹)" >&2
  fi
else
  echo "    !! 无法获取 socat 源码(网络受限),仅 busybox 可用" >&2
  echo "    手动下载 socat-1.7.4.4.tar.gz 放到本目录后重跑" >&2
fi

echo "done. 产物:"
ls -la busybox socat 2>/dev/null || true
