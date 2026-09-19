"""Review findings 3, 5, 7, 8, 9, 10, 12-19 at unit level (no network)."""
import json
from pathlib import Path
import ssl
import tempfile
import time
import unittest
from urllib.error import URLError

import fixture_site  # noqa: F401
import probe_site as ps

SCRIPTS = Path(__file__).resolve().parent.parent / 'scripts'

def rules(body, name):
    return next(item for item in ps.analyze_robots(body)['effective_rules_by_bot'] if item['name'] == name)

class LinearTimeTests(unittest.TestCase):
    """Findings 7 and 17: hostile bodies stay fast."""
    def assertFast(self, fn, limit=0.5):
        started = time.monotonic()
        result = fn()
        self.assertLess(time.monotonic() - started, limit)
        return result

    def test_many_leading_comments(self):
        body = '<!-- a -->' * 40 + '<p>x</p>'
        self.assertTrue(self.assertFast(lambda: ps.looks_like_html(body)))
        self.assertTrue(self.assertFast(lambda: ps.looks_like_html('<!-- a -->' * 5000 + '<!DOCTYPE html><html>')))

    def test_hostile_markdown_lines(self):
        self.assertEqual(self.assertFast(lambda: ps.markdown_h1s('#' + ' ' * 80000 + 'x#')), [(1, 'x#')])
        self.assertEqual(self.assertFast(lambda: ps.MD_LINK.findall('[' * 80000)), [])
        self.assertEqual(self.assertFast(lambda: ps.check_llms_txt('# T\n' + '[a](' * 20000)['link_count']), 0)
        self.assertFalse(self.assertFast(lambda: ps.is_air_urn('urn:air:' + 'a' * 80000)))
        self.assertTrue(ps.is_air_urn('urn:air:example.com:server:lookup'))

    def test_large_html_is_parsed_only_in_its_head(self):
        body = '<!DOCTYPE html><html><head><title>T</title></head><body>' + '<p>x</p>' * 200000 + '</body></html>'
        semantic = self.assertFast(lambda: ps.semantic_body(body, 'text/html', True), 3.0)
        self.assertEqual((semantic['kind'], semantic['title']), ('html', 'T'))

class ClassificationTests(unittest.TestCase):
    def test_markdown_opening_with_html_block(self):
        text = '<p align="center"><img src="logo.png"></p>\n\n# Example auth.md\n\nDetails.\n'
        self.assertEqual(ps.semantic_body(text, 'text/markdown', True)['kind'], 'markdown')
        self.assertEqual(ps.check_auth_md(text)['findings'][0]['result'], 'ok')
        self.assertEqual(ps.semantic_body('<p>x</p><div>y</div>', 'text/markdown', True)['kind'], 'html')

    def test_json_read_as_utf8_whatever_the_charset(self):
        raw = '{"name": "中文"}'.encode('utf-8')
        text, _ = ps.decode_text(raw, 'application/json; charset=utf-16')
        self.assertEqual(ps.semantic_body(text, 'application/json; charset=utf-16', True, raw=raw)['kind'], 'json')

    def test_utf16_xml_parsed_from_its_bytes(self):
        raw = '<?xml version="1.0" encoding="UTF-16"?><urlset><url><loc>x</loc></url></urlset>'.encode('utf-16')
        text, _ = ps.decode_text(raw, 'application/xml; charset=utf-16')
        self.assertEqual(ps.semantic_body(text, 'application/xml; charset=utf-16', True, raw=raw)['kind'], 'xml')

    def test_nan_and_infinity_are_invalid_json(self):
        for text in ('{"v": NaN}', '[Infinity]', '{"v": -Infinity}', '{"v": 1e999}'):
            with self.assertRaises(ValueError, msg=text):
                ps.parse_json_text(text)
            self.assertEqual(ps.semantic_body(text, 'application/json', True)['kind'], 'invalid_json')

    def test_retry_after_superscript(self):
        self.assertIsNone(ps.parse_retry_after('²'))

    def test_non_text_charsets_are_rejected(self):
        for charset in ('utf-7', 'unicode_escape', 'raw_unicode_escape', 'idna', 'punycode', 'undefined', 'base64', 'rot13', 'no-such-codec'):
            self.assertEqual(ps.safe_charset('text/plain; charset=' + charset), ('utf-8', charset), charset)
        text, charset = ps.decode_text(b'+2D8-\\ud800', 'text/plain; charset=utf-7')
        self.assertEqual(charset, 'utf-8')
        text.encode('utf-8')  # no lone surrogate
        self.assertEqual(ps.safe_charset('text/html; charset=ISO-8859-1'), ('iso8859-1', None))
        self.assertEqual(ps.MD_LINK.findall('See [Foo](https://en.wikipedia.org/wiki/Foo_(bar)) and [x](/a "t")'), ['https://en.wikipedia.org/wiki/Foo_(bar)', '/a'])

class JsonWriteTests(unittest.TestCase):
    def test_lone_surrogate_and_nan_still_give_strict_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'out.json'
            ps.write_json_file(path, {'\ud800': 'x\udfff', 'nan': float('nan')})
            text = path.read_text(encoding='utf-8')
            doc = json.loads(text, parse_constant=ps._reject_constant)
            self.assertEqual(doc['nan'], 'nan')
            self.assertIn('\\ud800', text)
            with self.assertRaises(FileExistsError):
                ps.write_json_file(path, {})
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ['out.json'])

class MalformedUrlTests(unittest.TestCase):
    def test_bracket_placeholders_never_raise(self):
        for bad in ('https://[site_url]/page', 'https://[api-host]/v1', 'https://[/x', 'https://a:99999/'):
            self.assertFalse(ps.same_origin(bad, 'https://example.com'))
            self.assertIsNone(ps._join('https://example.com/', bad))
        catalog = ps.check_api_catalog({'linkset': [{'anchor': 'https://[api-host]/v1', 'service-doc': [{'href': '/ai/'}]}]}, 'https://example.com/.well-known/api-catalog')
        anchor = [f for f in catalog['findings'] if f['check'] == 'entry_anchor'][0]
        self.assertEqual(anchor['result'], 'problem')
        self.assertIn('not a valid URL', anchor['detail'])
        prm = ps.check_prm({'resource': 'https://[resource]/', 'authorization_servers': ['https://x']}, 'https://example.com')
        self.assertEqual([f['result'] for f in prm['findings'] if f['check'] == 'resource_identity'], ['problem'])
        card = ps.check_mcp_card({'serverInfo': {'name': 'n', 'version': '1'}, 'endpoint': 'https://[host]/mcp', 'capabilities': {'tools': {}}}, 'https://example.com/')
        self.assertEqual([f['result'] for f in card['findings'] if f['check'] == 'transport_endpoint'], ['problem'])

    def test_bracketed_hosts_behave_the_same_on_every_python(self):
        # urlsplit rejects these only from 3.11.4; the probe checks them itself.
        self.assertTrue(ps.bracket_host_ok('[::1]:8080'))
        self.assertTrue(ps.bracket_host_ok('example.com'))
        for netloc in ('[site_url]', '[api-host]:443', '[::1', '::1]', '[::1][::2]'):
            self.assertFalse(ps.bracket_host_ok(netloc), netloc)
        with self.assertRaises(ps.InputRejected):
            ps.normalise_url('https://[site_url]/page')
        self.assertFalse(ps.same_origin('https://[site_url]/', 'https://site_url'))
        self.assertEqual(ps.normalise_url('http://[::1]:8080/x')[0], 'http://[::1]:8080/x')

    def test_default_port_and_trailing_dot(self):
        self.assertEqual(ps.normalise_url('https://example.com:443/x')[0], 'https://example.com/x')
        self.assertEqual(ps.normalise_url('http://example.com:80/')[0], 'http://example.com/')
        self.assertEqual(ps.normalise_url('https://example.com:8443/')[0], 'https://example.com:8443/')
        self.assertEqual(ps.canonical_origin('https://Example.com.:443/a'), 'https://example.com')
        self.assertTrue(ps.same_origin('https://example.com./x', 'https://example.com:443'))
        self.assertEqual(ps.check_oauth_as({'issuer': 'https://example.com'}, ps.canonical_origin('https://example.com.:443'))['findings'][0]['result'], 'ok')

    def test_idna_deviation_characters_are_rejected(self):
        for host in ('faß.de', 'βόλος.gr', 'a‍b.com', 'a‌b.com'):
            with self.assertRaises(ps.InputRejected) as caught:
                ps.normalise_url('https://%s/' % host)
            self.assertIn('xn--', str(caught.exception))
        self.assertEqual(ps.normalise_url('https://xn--fa-hia.de/')[0], 'https://xn--fa-hia.de/')

class RobotsGroupingTests(unittest.TestCase):
    def test_unknown_directives_do_not_split_a_user_agent_run(self):
        facts = ps.analyze_robots('User-agent: *\nCrawl-delay: 10\nUser-agent: GPTBot\nDisallow: /\n')
        self.assertEqual(facts['group_count'], 1)
        self.assertTrue(facts['disallow_all_for_wildcard'])
        self.assertTrue(rules('User-agent: *\nCrawl-delay: 10\nUser-agent: GPTBot\nDisallow: /\n', 'GPTBot')['disallow_root'])

    def test_content_signal_between_user_agents_applies_to_both(self):
        body = 'User-agent: *\nContent-Signal: search=yes, ai-train=no\nUser-agent: GPTBot\nAllow: /\n'
        self.assertTrue(rules(body, 'GPTBot')['content_signal_applies'])
        self.assertEqual(ps.analyze_robots(body)['bots_without_applicable_content_signal'], [])

    def test_empty_allow_and_root_patterns(self):
        facts = ps.analyze_robots('User-agent: *\nDisallow: /\nAllow:\n')
        self.assertEqual((facts['allow_rules'], facts['empty_allow_rules']), (0, 1))
        self.assertTrue(facts['disallow_all_for_wildcard'])
        for pattern in ('*', '/*', '/*$'):
            self.assertTrue(ps.analyze_robots('User-agent: *\nDisallow: %s\n' % pattern)['disallow_all_for_wildcard'], pattern)
        self.assertEqual(rules('User-agent: *\nDisallow: /private/\n\nUser-agent: GPTBot\nDisallow: /*$\n', 'GPTBot')['verdict'], 'named_group_keeps_star_disallows')

    def test_only_the_leading_product_token_counts(self):
        self.assertEqual(ps.product_tokens('GPTBot, CCBot'), ['gptbot'])
        self.assertEqual(ps.product_tokens('Mozilla/5.0 (compatible; GPTBot/1.1)'), ['mozilla'])
        self.assertEqual(ps.product_tokens('GPTBot/1.1'), ['gptbot'])
        self.assertEqual(ps.product_tokens('* extra'), ['*'])
        self.assertEqual(ps.product_tokens('*foo'), [])
        self.assertNotIn('CCBot', ps.analyze_robots('User-agent: GPTBot, CCBot\nDisallow: /\n')['named_ai_crawler_names'])

    def test_only_cr_and_lf_end_a_line(self):
        facts = ps.analyze_robots('User-agent: *\n# note Disallow: /\nAllow: /\n')
        self.assertEqual((facts['disallow_rules'], facts['disallow_all_for_wildcard']), (0, False))
        self.assertEqual(ps.markdown_h1s('intro # not a heading\n'), [])

class VerdictTests(unittest.TestCase):
    def row(self, status, block=None):
        return {'status': status, 'edge_block': block, 'headers': {}}

    def test_client_difference_verdicts(self):
        ok = self.row(200)
        cases = [
            (self.row(429), 'rate_limited_or_unavailable'),
            (self.row(503), 'rate_limited_or_unavailable'),
            (self.row(403, {'error_code': '1015'}), 'rate_limited_or_unavailable'),
            (self.row(403, {'error_code': '1010'}), 'default_python_client_blocked'),
            (self.row(403, {'error_code': '1020'}), 'default_python_client_blocked'),
            (self.row(403), 'default_python_client_blocked'),
            (self.row(503, {'challenge': 'challenge'}), 'rate_limited_or_unavailable'),
            (self.row(200), 'same_status'),
            (self.row(404), 'status_differs'),
            (self.row(None), 'unknown'),
        ]
        for default, expected in cases:
            self.assertEqual(ps._difference_verdict(ok, default), expected, default)
        self.assertEqual(ps._difference_verdict(self.row(403), ok), 'probe_client_blocked')

    def test_row_facts_use_headers_and_errors(self):
        errored = {'status': 200, 'error': {'kind': 'body_read_error'}, 'headers': {'content-type': 'text/markdown'}, 'body': {'complete': False, 'semantic': {'kind': 'markdown'}}}
        facts = ps._row_facts(errored)
        self.assertIsNone(ps._served_markdown(facts))
        self.assertIs(ps._returned_markdown(facts), True)
        self.assertIs(ps._is_html(facts), False)
        clean_html = {'status': 200, 'error': None, 'headers': {'content-type': 'text/html'}, 'body': {'complete': True, 'semantic': {'kind': 'html'}}}
        self.assertIs(ps._is_html(ps._row_facts(clean_html)), True)

    def test_tls_local_trust_store(self):
        err = ssl.SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate')
        err.verify_message = 'unable to get local issuer certificate'
        self.assertEqual(ps.classify_exception(URLError(err)), ('tls_certificate_unverified', 'possibly_local'))
        self.assertEqual(ps.classify_exception(err), ('tls_certificate_unverified', 'possibly_local'))
        self.assertEqual(ps.classify_exception(ssl.SSLError(1, 'handshake failure')), ('tls_error', 'remote'))

class SourceHygieneTests(unittest.TestCase):
    def test_scripts_are_pure_ascii(self):
        for path in SCRIPTS.glob('*.py'):
            text = path.read_text(encoding='utf-8')
            bad = sorted({'U+%04X' % ord(ch) for ch in text if ord(ch) > 126})
            self.assertEqual(bad, [], path.name)

if __name__ == '__main__':
    unittest.main()
