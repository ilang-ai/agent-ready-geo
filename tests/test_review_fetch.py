"""Review findings 1, 4, 6, 8, 21: redirects, gzip, bounds, read errors, proxies (127.0.0.1 only)."""
import gzip
import os
import time
import tracemalloc
import unittest

from fixture_site import RouteServer, send_raw
import probe_site as ps

HTML = b'<!DOCTYPE html><html><head><title>Home</title></head><body><h1>Home</h1></body></html>'
MD = b'# Home\n\nMarkdown body.\n'

def page(body=HTML, content_type='text/html; charset=utf-8', headers=None, status=200):
    return lambda h: send_raw(h, status, body, content_type, headers)

def redirect(location, status=302):
    return lambda h: send_raw(h, status, b'', 'text/plain', {'Location': location})

class RedirectTests(unittest.TestCase):
    def test_308_is_followed_on_every_python_version(self):
        with RouteServer({'/perm': redirect('/final', 308), '/final': page(b'final', 'text/plain')}) as server:
            row = ps.Probe(timeout=5).fetch('perm', server.origin + '/perm', 'text')
        self.assertEqual((row['status'], row['final_url']), (200, server.origin + '/final'))
        self.assertEqual((row['redirects'][0]['status'], row['redirects'][0]['followed']), (308, True))
        self.assertIsNone(row['error'])

    def test_every_hop_is_a_counted_request(self):
        routes = {'/hop%d' % n: redirect('/hop%d' % (n + 1) if n < 4 else '/final') for n in range(5)}
        routes['/final'] = page(b'final', 'text/plain')
        with RouteServer(routes) as server:
            probe = ps.Probe(timeout=5)
            row = probe.fetch('hops', server.origin + '/hop0', 'text')
            self.assertEqual(len(server.requests), 6)
        self.assertEqual((row['status'], len(row['redirects']), probe.requests_sent), (200, 5, 6))

    def test_redirect_limit_loop_and_budget(self):
        routes = {'/c%d' % n: redirect('/c%d' % (n + 1)) for n in range(8)}
        routes['/loop'] = redirect('/loop')
        with RouteServer(routes) as server:
            probe = ps.Probe(timeout=5)
            limited = probe.fetch('limit', server.origin + '/c0', 'text')
            self.assertEqual((limited['status'], limited['error']['kind'], probe.requests_sent), (302, 'redirect_limit_or_loop', 6))
            looped = ps.Probe(timeout=5).fetch('loop', server.origin + '/loop', 'text')
            self.assertEqual(looped['error']['kind'], 'redirect_limit_or_loop')
            budget = ps.Probe(timeout=5, request_budget=3)
            cut = budget.fetch('budget', server.origin + '/c0', 'text')
            self.assertEqual((cut['error']['kind'], budget.requests_sent), ('not_collected_request_budget', 3))
            self.assertEqual(budget.fetch('after', server.origin + '/c0', 'text')['observation'], 'not_collected')

    def test_large_redirect_body_is_never_read(self):
        size = 8 * 1024 * 1024
        def big(h):
            h.send_response(302)
            h.send_header('Location', '/final')
            h.send_header('Content-Length', str(size))
            h.end_headers()
            for _ in range(size // 65536):
                h.wfile.write(b'x' * 65536)
        with RouteServer({'/big': big, '/final': page(b'final', 'text/plain')}) as server:
            tracemalloc.start()
            try:
                row = ps.Probe(timeout=5).fetch('big', server.origin + '/big', 'text')
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        self.assertEqual(row['status'], 200)
        self.assertLess(peak, 4 * 1024 * 1024)

    def test_slow_redirect_body_does_not_delay_the_fetch(self):
        def slow(h):
            h.send_response(302)
            h.send_header('Location', '/final')
            h.send_header('Content-Length', '12')
            h.end_headers()
            for _ in range(12):
                h.wfile.write(b'x')
                h.wfile.flush()
                time.sleep(0.5)
        with RouteServer({'/slow': slow, '/final': page(b'final', 'text/plain')}) as server:
            started = time.monotonic()
            row = ps.Probe(timeout=3).fetch('slow', server.origin + '/slow', 'text')
            elapsed = time.monotonic() - started
        self.assertEqual((row['status'], row['error']), (200, None))
        self.assertLess(elapsed, 2.0)

    def test_dripped_headers_stop_at_the_deadline(self):
        head = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok'
        def drip(h):
            for index in range(len(head)):
                h.wfile.write(head[index:index + 1])
                h.wfile.flush()
                time.sleep(0.2)
            h.close_connection = True
        with RouteServer({'/drip': drip}) as server:
            started = time.monotonic()
            row = ps.Probe(timeout=1.0).fetch('drip', server.origin + '/drip', 'text')
            elapsed = time.monotonic() - started
        self.assertEqual(row['error']['kind'], 'fetch_deadline')
        self.assertLess(elapsed, 2.5)

    def test_dripped_tls_handshake_stops_at_the_deadline(self):
        import socket
        import threading
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        stop = threading.Event()
        def serve():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.sendall(b'\x16\x03\x03\x40\x00')  # a TLS record header announcing 16 KiB
                    while not stop.is_set():
                        conn.sendall(b'\x00')
                        time.sleep(0.2)
                except OSError:
                    pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            row = ps.Probe(timeout=1.0).fetch('tls', 'https://127.0.0.1:%d/' % listener.getsockname()[1], 'html')
            elapsed = time.monotonic() - started
        finally:
            stop.set()
            listener.close()
        self.assertEqual(row['error']['kind'], 'fetch_deadline')
        self.assertLess(elapsed, 2.5)

class RateLimitTests(unittest.TestCase):
    def test_two_consecutive_429_halt_the_host(self):
        with RouteServer({'/a': page(b'no', 'text/plain', status=429), '/b': page(b'no', 'text/plain', status=503), '/c': page(b'ok', 'text/plain')}) as server:
            probe = ps.Probe(timeout=5)
            probe.fetch('a', server.origin + '/a', 'text')
            self.assertNotIn('127.0.0.1', probe.halted)
            probe.fetch('b', server.origin + '/b', 'text')
            self.assertIn('127.0.0.1', probe.halted)
            self.assertEqual(probe.fetch('c', server.origin + '/c', 'text')['error']['kind'], 'not_collected_retry_after')
            self.assertEqual([e['action'] for e in probe.retry_after_events], ['recorded_without_retry_after', 'stopped_further_requests_to_host'])

    def test_success_resets_the_count_and_pauses_share_one_allowance(self):
        routes = {'/limited': page(b'no', 'text/plain', {'Retry-After': '1'}, 429), '/ok': page(b'ok', 'text/plain')}
        with RouteServer(routes) as server:
            probe = ps.Probe(timeout=5, max_retry_after=1)
            probe.fetch('one', server.origin + '/limited', 'text')
            started = time.monotonic()
            probe.fetch('two', server.origin + '/ok', 'text')
            self.assertGreaterEqual(time.monotonic() - started, 0.8)  # paused for Retry-After
            probe.fetch('three', server.origin + '/limited', 'text')
            self.assertIn('127.0.0.1', probe.halted)  # allowance of 1 s already spent
            self.assertIn('pause allowance', probe.halted['127.0.0.1'])

class BodyDecodingTests(unittest.TestCase):
    def fetch(self, route, expected='text'):
        with RouteServer({'/x': route}) as server:
            return ps.Probe(timeout=5).fetch('x', server.origin + '/x', expected), server

    def test_corrupt_gzip_is_evidence_not_a_crash(self):
        good = gzip.compress(b'User-agent: *\nAllow: /\n')
        corrupt = good[:10] + b'\xff' * 20 + good[-8:]
        row, _ = self.fetch(page(corrupt, 'text/plain', {'Content-Encoding': 'gzip'}))
        self.assertEqual(row['status'], 200)
        self.assertTrue(row['body']['content_decode_error'].startswith('Corrupt gzip data'))
        self.assertFalse(row['body']['complete'])
        self.assertEqual(row['observation'], 'incomplete_collection')
        with RouteServer({'/': page(), '/robots.txt': page(corrupt, 'text/plain', {'Content-Encoding': 'gzip'})}) as server:
            report = ps.collect(server.origin + '/', ps.Probe(timeout=5), skip_client_difference=True)
        self.assertEqual(report['summary']['robots']['state'], 'incomplete_body')

    def test_trailing_bytes_after_gzip_keep_the_body(self):
        row, _ = self.fetch(page(gzip.compress(b'User-agent: *\nAllow: /\n') + b'JUNK', 'text/plain', {'Content-Encoding': 'gzip'}))
        self.assertTrue(row['body']['complete'])
        self.assertEqual(row['body']['content_decode_note'], 'Ignored 4 bytes after the last gzip member')
        self.assertEqual(row['body']['semantic']['kind'], 'text')

    def test_multi_member_gzip(self):
        row, _ = self.fetch(page(gzip.compress(b'# One\n') + gzip.compress(b'two\n'), 'text/markdown', {'Content-Encoding': 'gzip'}))
        self.assertTrue(row['body']['complete'])
        self.assertEqual(row['body']['snippet'], '# One\ntwo\n')

    def test_unsupported_encoding(self):
        row, _ = self.fetch(page(b'\x0b\x02\x80compressed', 'text/markdown', {'Content-Encoding': 'br'}))
        self.assertIn('Unsupported Content-Encoding', row['body']['content_decode_error'])
        self.assertFalse(row['body']['complete'])

    def test_cut_chunked_body_keeps_the_prefix(self):
        def cut(h):
            h.send_response(200)
            h.send_header('Content-Type', 'text/markdown; charset=utf-8')
            h.send_header('Transfer-Encoding', 'chunked')
            h.end_headers()
            h.wfile.write(b'%x\r\n' % len(MD) + MD[:5])
            h.wfile.flush()
            h.close_connection = True
        row, _ = self.fetch(cut, 'markdown')
        self.assertEqual(row['error']['kind'], 'body_read_error')
        self.assertEqual(row['body']['wire_bytes_retained'], 5)
        self.assertFalse(row['body']['complete'])

class NegotiationEndToEndTests(unittest.TestCase):
    def run_mode(self, mode):
        state = {'md': 0}
        def home(h):
            accept = h.headers.get('Accept') or ''
            if accept == 'text/markdown':
                state['md'] += 1
                if mode == 'chunked_cut' and state['md'] == 2:
                    h.send_response(200)
                    h.send_header('Content-Type', 'text/markdown; charset=utf-8')
                    h.send_header('Vary', 'Accept')
                    h.send_header('Transfer-Encoding', 'chunked')
                    h.end_headers()
                    h.wfile.write(b'%x\r\n' % len(MD) + MD[:5])
                    h.wfile.flush()
                    h.close_connection = True
                    return
                if mode == 'br':
                    return send_raw(h, 200, b'\x0b\x02\x80compressed', 'text/markdown; charset=utf-8', {'Vary': 'Accept', 'Content-Encoding': 'br'})
                return send_raw(h, 200, MD, 'text/markdown; charset=utf-8', {'Vary': 'Accept'})
            if mode == 'q0_cut' and accept.startswith('text/html,text/markdown;q=0'):
                h.send_response(200)
                h.send_header('Content-Type', 'text/markdown; charset=utf-8')
                h.send_header('Vary', 'Accept')
                h.send_header('Transfer-Encoding', 'chunked')
                h.end_headers()
                h.wfile.write(b'%x\r\n' % 200 + b'# Home')
                h.wfile.flush()
                h.close_connection = True
                return
            if mode == 'markdown_default' and not accept:
                return send_raw(h, 200, MD, 'text/markdown; charset=utf-8', {'Vary': 'Accept'})
            return send_raw(h, 200, HTML, 'text/html; charset=utf-8', {'Vary': 'Accept'})
        with RouteServer({'/': home}) as server:
            report = ps.collect(server.origin + '/', ps.Probe(timeout=5), skip_dns=True, skip_client_difference=True)
        return report['summary']['negotiation_verdicts']

    def test_read_errors_are_unknown_not_failures(self):
        for mode in ('chunked_cut', 'br'):
            verdicts = self.run_mode(mode)
            self.assertEqual(verdicts['summary'], 'markdown_negotiation_unknown', (mode, verdicts))
            self.assertIsNone(verdicts['markdown_served_for_text_markdown'], mode)

    def test_markdown_header_on_q0_is_a_failure_even_when_cut(self):
        verdicts = self.run_mode('q0_cut')
        self.assertIs(verdicts['q0_requests_did_not_return_markdown'], False)
        self.assertEqual(verdicts['summary'], 'markdown_negotiation_problems')

    def test_homepage_without_accept_must_be_html(self):
        verdicts = self.run_mode('markdown_default')
        self.assertIs(verdicts['html_served_without_accept_header'], False)
        self.assertIn('html_served_without_accept_header', verdicts['failed_verdicts'])

class ProxyTests(unittest.TestCase):
    def test_loopback_bypasses_an_environment_proxy(self):
        saved = {key: os.environ.get(key) for key in ('HTTP_PROXY', 'http_proxy')}
        os.environ['HTTP_PROXY'] = os.environ['http_proxy'] = 'http://user:secret@127.0.0.1:9'
        try:
            with RouteServer({'/': page()}) as server:
                row = ps.Probe(timeout=5).fetch('home', server.origin + '/', 'html')
                summary = ps.proxy_summary(server.origin + '/')
        finally:
            for key, value in saved.items():
                if value is None: os.environ.pop(key, None)
                else: os.environ[key] = value
        self.assertEqual(row['status'], 200)
        self.assertEqual(summary, {'configured': True, 'applies_to_target': False, 'proxy_host': '127.0.0.1'})
        self.assertNotIn('secret', str(summary))

if __name__ == '__main__':
    unittest.main()
