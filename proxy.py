#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
"""
币圈新闻监控台 · 本地代理服务器
- 仅监听 127.0.0.1(只有你自己的电脑能访问)
- 职责1: 托管 index.html 页面  ->  http://127.0.0.1:8899
- 职责2: 转发新闻源 / AI 接口请求,绕开浏览器跨域限制
- 纯 Python 标准库实现,无需安装任何第三方包
"""
import http.client
import http.server
import socketserver
import urllib.parse
import ssl
import os
import re
import sys
import gzip
import io
import ipaddress
import socket

try:
    PORT = int(os.environ.get("CID_PORT", "8899"))
    if not 1024 <= PORT <= 65535:
        raise ValueError
except ValueError:
    print("[错误] CID_PORT 必须是 1024 到 65535 之间的整数。")
    sys.exit(2)
BASE = os.path.dirname(os.path.abspath(__file__))
MAX_REQUEST_BODY = 2 * 1024 * 1024
MAX_RESPONSE_BODY = 12 * 1024 * 1024
ALLOWED_APP_ORIGINS = {
    "http://127.0.0.1:%d" % PORT,
    "http://localhost:%d" % PORT,
}

# 允许从浏览器透传到目标服务器的请求头(鉴权用)
FORWARD_HEADERS = {"authorization", "x-api-key", "anthropic-version", "x-goog-api-key", "content-type"}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# 部分新闻接口要求带来源页,否则返回 403
REFERERS = {
    "api.jinse.cn": "https://www.jinse.cn/",
    "api.jinse.com": "https://www.jinse.com/",
    "api.theblockbeats.news": "https://www.theblockbeats.info/",
    "www.panewslab.com": "https://www.panewslab.com/",
    "rss.panewslab.com": "https://www.panewslab.com/",
    "www.odaily.news": "https://www.odaily.news/",
    "rss.odaily.news": "https://www.odaily.news/",
    "www.techflowpost.com": "https://www.techflowpost.com/zh-CN/newsletter",
    "www.chaincatcher.com": "https://www.chaincatcher.com/",
}

# 阿里云 WAF JS 挑战的 cookie 缓存(如深潮 TechFlow)
ACW_COOKIES = {}


def resolve_target(url):
    """一次性解析并校验目标: 仅公网 HTTPS、无凭据、全部解析结果为公网 IP。

    返回 (ip, host, port) 供固定 IP 直连使用; 校验失败返回 None。
    解析结果在本次请求内固定复用, 避免"校验后再次独立解析"的 DNS 重绑定窗口。
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        port = parsed.port or 443
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        if not addresses:
            return None
        if not all(ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            return None
        return addresses[0][4][0], parsed.hostname.strip("[]"), port
    except (OSError, ValueError):
        return None


class VerifiedHTTPSConnection(http.client.HTTPSConnection):
    """固定已校验 IP 直连,但 SNI 与证书校验保持原始域名,HTTPS 完整性不降级。"""

    def __init__(self, ip, port, host, context=None, timeout=30):
        super().__init__(host=ip, port=port, context=context, timeout=timeout)
        self._sni_host = host

    def connect(self):
        # 父类 connect() 用 self.host(即已校验 IP)作为 SNI/证书主机名,
        # 这里改为使用原始域名,保持 TLS 校验完整性
        http.client.HTTPConnection.connect(self)
        if self._tunnel_host:
            server_hostname = self._tunnel_host
        else:
            server_hostname = self._sni_host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


def open_verified_connection(target):
    """固定使用已校验的 IP 直连; SNI 与证书校验保持原始域名; 验证对端 IP 为公网。"""
    ip, host, port = target
    conn = VerifiedHTTPSConnection(ip=ip, port=port, host=host, context=make_ctx(), timeout=30)
    conn.connect()
    peer = conn.sock.getpeername()[0]
    if not ipaddress.ip_address(peer).is_global:
        conn.close()
        raise ValueError("peer address is not public")
    return conn


def acw_sc_v2(arg1):
    """阿里云 WAF acw_sc__v2 cookie 算法(移植自 RSSHub 开源实现)"""
    pwd = "3000176000856006061501533003690027800375"
    code = [15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22, 23, 25, 13,
            6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30, 7, 4, 17, 5, 3, 28, 34, 37, 12, 36]
    res = [""] * len(code)
    for i, cur in enumerate(arg1):
        for j, c in enumerate(code):
            if c == i + 1:
                res[j] = cur
    box = "".join(res)
    out = ""
    n = min(len(box), len(pwd))
    for i in range(0, n - 1, 2):
        out += format(int(box[i:i + 2], 16) ^ int(pwd[i:i + 2], 16), "02x")
    return out


def make_ctx():
    """带 ALPN 的 TLS 上下文:部分站点的 CDN 会掐断没有 ALPN 的连接"""
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


def decompress_gzip_limited(data):
    """限制 gzip 解压后的体积，避免异常上游响应占用过多内存。"""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        result = compressed.read(MAX_RESPONSE_BODY + 1)
    if len(result) > MAX_RESPONSE_BODY:
        raise ValueError("upstream response too large")
    return result


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CryptoIntelLocal/1.0"
    sys_version = ""

    # ---------- 工具 ----------
    def _is_app_request(self):
        origin = (self.headers.get("Origin") or "").rstrip("/")
        referer = self.headers.get("Referer") or ""
        host = (self.headers.get("Host") or "").lower()
        same_origin_fetch = (
            (self.headers.get("Sec-Fetch-Site") or "").lower() == "same-origin"
            and host in {"127.0.0.1:%d" % PORT, "localhost:%d" % PORT}
        )
        return same_origin_fetch or origin in ALLOWED_APP_ORIGINS or any(
            referer == allowed + "/" or referer.startswith(allowed + "/")
            for allowed in ALLOWED_APP_ORIGINS
        )

    def _cors(self):
        origin = (self.headers.get("Origin") or "").rstrip("/")
        if origin in ALLOWED_APP_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "content-type, authorization, x-api-key, anthropic-version, x-goog-api-key",
        )

    def _reply(self, code, data, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if ctype.startswith("text/html"):
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            )
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(data)
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    # ---------- 路由 ----------
    def do_OPTIONS(self):
        if not self._is_app_request():
            return self._reply(403, b'{"error":"origin not allowed"}')
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._serve_file("index.html", "text/html; charset=utf-8")
        if path == "/p":
            if not self._is_app_request():
                return self._reply(403, b'{"error":"origin not allowed"}')
            return self._forward("GET")
        if path == "/ping":
            return self._reply(200, b'{"ok":true,"app":"crypto-intelligence-desk","version":"1.0.1"}')
        self._reply(404, b'{"error":"not found"}')

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path == "/p":
            if not self._is_app_request():
                return self._reply(403, b'{"error":"origin not allowed"}')
            return self._forward("POST")
        self._reply(404, b'{"error":"not found"}')

    # ---------- 静态文件 ----------
    def _serve_file(self, name, ctype):
        try:
            with open(os.path.join(BASE, name), "rb") as f:
                self._reply(200, f.read(), ctype)
        except FileNotFoundError:
            self._reply(404, "index.html 不存在,请确认它和 proxy.py 在同一文件夹".encode("utf-8"),
                        "text/plain; charset=utf-8")

    # ---------- 请求转发 ----------
    def _forward(self, method):
        qs = urllib.parse.urlparse(self.path).query
        url = urllib.parse.parse_qs(qs).get("u", [None])[0]
        if not url or not resolve_target(url):
            return self._reply(400, b'{"error":"target must be a public https url"}')

        body = None
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > MAX_REQUEST_BODY:
                return self._reply(413, b'{"error":"request body too large"}')
            body = self.rfile.read(length) if length else None

        target = resolve_target(url)
        host = target[1]

        def build_headers():
            headers = {
                "Host": host,
                "User-Agent": UA,
                "Accept": "*/*",
                "Accept-Encoding": "gzip",
            }
            if host in REFERERS:
                headers["Referer"] = REFERERS[host]
                headers["Origin"] = "https://" + host
            if host == "api.theblockbeats.news":
                headers["language"] = "cn"  # 官方RSS文档要求的语言头
            if host == "www.techflowpost.com":
                headers["Accept-Language"] = "zh-CN"
            for k, v in self.headers.items():
                if k.lower() in FORWARD_HEADERS:
                    headers[k] = v
            return headers

        def do_request(cur_target, cookie=None):
            """固定 IP 直连并处理重定向(≤5次); 返回 (status, ctype, data)。"""
            headers = build_headers()
            if cookie:
                headers["Cookie"] = cookie
            cur_url = url
            cur_method = method
            cur_body = body
            conn = open_verified_connection(cur_target)
            try:
                for _ in range(6):
                    parsed = urllib.parse.urlsplit(cur_url)
                    path = parsed.path or "/"
                    if parsed.query:
                        path += "?" + parsed.query
                    conn.request(cur_method, path, body=cur_body, headers=headers)
                    resp = conn.getresponse()
                    data = resp.read(MAX_RESPONSE_BODY + 1)
                    if len(data) > MAX_RESPONSE_BODY:
                        raise ValueError("upstream response too large")
                    location = resp.getheader("Location")
                    if resp.status in (301, 302, 303, 307, 308) and location:
                        new_url = urllib.parse.urljoin(cur_url, location)
                        new_target = resolve_target(new_url)
                        if not new_target:
                            raise ValueError("blocked redirect target")
                        conn.close()
                        cur_url = new_url
                        cur_target = new_target
                        headers["Host"] = new_target[1]  # Host 头保持跟随域名
                        if resp.status in (301, 302, 303):
                            cur_method = "GET"
                            cur_body = None
                        conn = open_verified_connection(cur_target)
                        continue
                    if resp.getheader("Content-Encoding") == "gzip":
                        data = decompress_gzip_limited(data)
                    ctype = resp.getheader("Content-Type", "application/octet-stream")
                    if isinstance(ctype, bytes):
                        ctype = ctype.decode("latin-1", "replace")
                    return resp.status, ctype, data
                raise ValueError("too many redirects")
            finally:
                conn.close()

        try:
            status, ctype, data = do_request(target, ACW_COOKIES.get(host))
            # 命中阿里云 WAF JS 挑战:现场算出 cookie 后重试一次
            m = re.search(rb"var arg1='([0-9A-Fa-f]+)'", data[:4000])
            if m:
                ACW_COOKIES[host] = "acw_sc__v2=" + acw_sc_v2(m.group(1).decode())
                status, ctype, data = do_request(target, ACW_COOKIES[host])
            self._reply(status, data, ctype)
        except Exception:
            self._reply(502, b'{"error":"upstream request failed"}')

    # 精简日志:只打印转发目标的主机名
    def log_message(self, fmt, *args):
        try:
            msg = fmt % args
            if "/p?u=" in msg:
                host = urllib.parse.urlparse(
                    urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)["u"][0]).netloc
                msg = "-> " + host
            sys.stdout.write("[proxy] %s\n" % msg)
        except Exception:
            pass


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print("=" * 52)
    print("   币圈新闻监控台 · 本地代理已启动")
    print("   请在浏览器打开:  http://127.0.0.1:%d" % PORT)
    print("   关闭本窗口即停止服务")
    print("=" * 52)
    try:
        ThreadingServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n监控台已停止。")
    except OSError:
        print("[错误] 端口 %d 已被占用,可能监控台已在运行。" % PORT)
        sys.exit(1)
