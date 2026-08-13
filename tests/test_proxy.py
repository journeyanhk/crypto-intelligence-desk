# -*- coding: utf-8 -*-
# proxy.py 安全边界测试: 目标解析校验、固定 IP 直连、体积限制、WAF 算法、本地集成路径
# 仅使用标准库 unittest, 零第三方依赖
import gzip
import http.client
import json
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import proxy  # noqa: E402


def fake_addr(ip, port=443):
    return (2, 1, 6, "", (ip, port))


class ResolveTargetTests(unittest.TestCase):
    """任务 3.1: resolve_target 一次性解析校验逻辑(mock DNS)。"""

    def test_public_https_allowed(self):
        with mock.patch("proxy.socket.getaddrinfo", return_value=[fake_addr("93.184.216.34")]):
            target = proxy.resolve_target("https://example.com/news?a=1")
        self.assertEqual(target, ("93.184.216.34", "example.com", 443))

    def test_loopback_rejected(self):
        with mock.patch("proxy.socket.getaddrinfo", return_value=[fake_addr("127.0.0.1")]):
            self.assertIsNone(proxy.resolve_target("https://example.com/"))

    def test_private_ip_rejected(self):
        with mock.patch("proxy.socket.getaddrinfo", return_value=[fake_addr("10.0.0.8")]):
            self.assertIsNone(proxy.resolve_target("https://example.com/"))

    def test_mixed_public_private_rejected(self):
        with mock.patch(
            "proxy.socket.getaddrinfo",
            return_value=[fake_addr("93.184.216.34"), fake_addr("192.168.1.10")],
        ):
            self.assertIsNone(proxy.resolve_target("https://example.com/"))

    def test_non_https_rejected(self):
        with mock.patch("proxy.socket.getaddrinfo", return_value=[fake_addr("93.184.216.34")]):
            self.assertIsNone(proxy.resolve_target("http://example.com/"))

    def test_credentials_rejected(self):
        with mock.patch("proxy.socket.getaddrinfo", return_value=[fake_addr("93.184.216.34")]):
            self.assertIsNone(proxy.resolve_target("https://user:pass@example.com/"))

    def test_resolution_failure_rejected(self):
        with mock.patch("proxy.socket.getaddrinfo", side_effect=OSError("no such host")):
            self.assertIsNone(proxy.resolve_target("https://nonexistent.invalid/"))

    def test_global_ipv6_allowed(self):
        with mock.patch(
            "proxy.socket.getaddrinfo",
            return_value=[(10, 1, 6, "", ("2606:4700::1111", 443, 0, 0))],
        ):
            target = proxy.resolve_target("https://example.com/")
        self.assertEqual(target, ("2606:4700::1111", "example.com", 443))

    def test_ipv6_loopback_rejected(self):
        with mock.patch(
            "proxy.socket.getaddrinfo",
            return_value=[(10, 1, 6, "", ("::1", 443, 0, 0))],
        ):
            self.assertIsNone(proxy.resolve_target("https://example.com/"))

    def test_url_missing(self):
        self.assertIsNone(proxy.resolve_target("not-a-url"))

    def test_custom_port(self):
        with mock.patch("proxy.socket.getaddrinfo", return_value=[fake_addr("93.184.216.34", 8443)]):
            target = proxy.resolve_target("https://example.com:8443/")
        self.assertEqual(target[2], 8443)


class OpenVerifiedConnectionTests(unittest.TestCase):
    """任务 3.1 补充: 对端 IP 验证与 SNI 保持(通过 mock VerifiedHTTPSConnection)。"""

    def test_peer_must_be_public(self):
        with mock.patch("proxy.VerifiedHTTPSConnection") as m_conn:
            m_conn.return_value.sock.getpeername.return_value = ("10.0.0.1", 443)
            with self.assertRaises(ValueError):
                proxy.open_verified_connection(("93.184.216.34", "example.com", 443))

    def test_public_peer_accepted(self):
        with mock.patch("proxy.VerifiedHTTPSConnection") as m_conn:
            m_conn.return_value.sock.getpeername.return_value = ("93.184.216.34", 443)
            conn = proxy.open_verified_connection(("93.184.216.34", "example.com", 443))
            self.assertIsNotNone(conn)
            m_conn.assert_called_once()
            _, kwargs = m_conn.call_args
            self.assertEqual(kwargs["ip"], "93.184.216.34")
            self.assertEqual(kwargs["host"], "example.com")
            self.assertEqual(kwargs["timeout"], 30)


class DecompressTests(unittest.TestCase):
    """任务 3.2: gzip 限量解压。"""

    def test_normal_decompress(self):
        payload = gzip.compress(b"hello news " * 200)
        self.assertEqual(proxy.decompress_gzip_limited(payload), b"hello news " * 200)

    def test_too_large_rejected(self):
        payload = gzip.compress(b"x" * (proxy.MAX_RESPONSE_BODY + 4096))
        with self.assertRaises(ValueError):
            proxy.decompress_gzip_limited(payload)


class AcwScV2Tests(unittest.TestCase):
    """任务 3.3: WAF cookie 算法输出格式。"""

    def test_output_hex_and_length(self):
        # pwd 固定 40 个十六进制字符: 输入长度 >= 40 时输出恒为 40 字符
        for n in (20, 24, 40, 100, 123):
            arg = "ab" * n  # 十六进制输入
            out = proxy.acw_sc_v2(arg)
            self.assertRegex(out, r"^[0-9a-f]+$")
            if len(arg) >= 40:
                self.assertEqual(len(out), 40)
            else:
                self.assertIn(len(out), (len(arg), len(arg) - 1))


class IntegrationTests(unittest.TestCase):
    """任务 3.4: 随机端口启动真实服务,覆盖本地 HTTP 路径。"""

    @classmethod
    def setUpClass(cls):
        cls.srv = proxy.ThreadingServer(("127.0.0.1", 0), proxy.Handler)
        cls.port = cls.srv.server_address[1]
        cls.orig_origins = proxy.ALLOWED_APP_ORIGINS
        proxy.ALLOWED_APP_ORIGINS = {
            "http://127.0.0.1:%d" % cls.port,
            "http://localhost:%d" % cls.port,
        }
        proxy.Handler.log_message = lambda *args, **kwargs: None
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        proxy.ALLOWED_APP_ORIGINS = cls.orig_origins
        cls.srv.shutdown()
        cls.srv.server_close()

    def request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def origin_headers(self):
        return {"Origin": "http://127.0.0.1:%d" % self.port}

    def test_ping(self):
        status, data = self.request("GET", "/ping")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["app"], "crypto-intelligence-desk")

    def test_index(self):
        status, data = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"CRYPTO INTELLIGENCE DESK", data)
        self.assertIn(b"<html", data)

    def test_unknown_path_404(self):
        status, _ = self.request("GET", "/nope")
        self.assertEqual(status, 404)

    def test_p_without_app_origin_forbidden(self):
        status, _ = self.request("GET", "/p?u=https://example.com/")
        self.assertEqual(status, 403)

    def test_p_cross_site_origin_forbidden(self):
        status, _ = self.request("GET", "/p?u=https://example.com/", headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)

    def test_p_private_target_bad_request(self):
        status, _ = self.request("GET", "/p?u=https://127.0.0.1/", headers=self.origin_headers())
        self.assertEqual(status, 400)

    def test_p_http_target_bad_request(self):
        status, _ = self.request("GET", "/p?u=http://example.com/", headers=self.origin_headers())
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
