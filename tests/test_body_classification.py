"""Body classification is judged from the body, not from the declared Content-Type."""
import unittest

import fixture_site  # noqa: F401
import probe_site as ps

def kind(text, content_type='', complete=True):
    return ps.semantic_body(text, content_type, complete)['kind']

def fake_result(expected, text, content_type, status=200):
    semantic = ps.semantic_body(text, content_type, True)
    return {'status': status, 'expected_representation': expected, 'error': None, 'body': {'complete': True, 'semantic': semantic, 'content_decode_error': None}}

class BodyKindTests(unittest.TestCase):
    def test_html_with_bom(self):
        self.assertEqual(kind('\ufeff<!DOCTYPE html><html><head><title>x</title></head></html>', 'text/html'), 'html')

    def test_html_after_comment_and_xml_prolog(self):
        self.assertEqual(kind('<!-- build 1 -->\n<html><body>x</body></html>'), 'html')
        self.assertEqual(kind('<?xml version="1.0"?>\n<!DOCTYPE html><html></html>', 'application/xhtml+xml'), 'html')

    def test_tag_led_html_served_as_json(self):
        self.assertEqual(kind('<meta charset="utf-8"><title>App</title><div id="root"></div>', 'application/json'), 'html')

    def test_html_fallback_for_json_path(self):
        result = fake_result('json', '<!DOCTYPE html><html><body>SPA shell</body></html>', 'application/json')
        self.assertEqual(ps.Probe.classify(result), 'html_response_instead_of_requested_representation')
        state, doc = ps.document_state(result, b'<!DOCTYPE html>', 'json')
        self.assertEqual((state, doc), ('html_fallback', None))

    def test_json(self):
        out = ps.semantic_body('{"linkset": []}', 'application/linkset+json', True)
        self.assertEqual(out['kind'], 'json')
        self.assertEqual(out['top_level_keys'], ['linkset'])

    def test_json_with_bom_parses_and_is_noted(self):
        out = ps.semantic_body('\ufeff{"a": 1}', 'application/json', True)
        self.assertEqual(out['kind'], 'json')
        self.assertTrue(out['bom'])

    def test_invalid_and_incomplete_json(self):
        self.assertEqual(kind('{"a": ', 'application/json', True), 'invalid_json')
        self.assertEqual(kind('{"a": ', 'application/json', False), 'json_incomplete')

    def test_xml_sitemap(self):
        out = ps.semantic_body('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://e.com/</loc></url></urlset>', 'application/xml', True)
        self.assertEqual(out['kind'], 'xml')
        self.assertTrue(out['xml_root'].endswith('urlset'))

    def test_rss_without_prolog_is_not_html(self):
        self.assertEqual(kind('<rss version="2.0"><channel><title>t</title><link>https://e.com/</link></channel></rss>', 'application/rss+xml'), 'xml')

    def test_markdown(self):
        self.assertEqual(kind('# Title\n\nText with [a link](/x).\n', 'text/markdown'), 'markdown')
        self.assertEqual(kind('Intro\n\n## Section\n', 'text/plain'), 'markdown')

    def test_ilang(self):
        self.assertEqual(kind('::ILANG::v5.0\n[TYPE:index]\n', 'text/plain'), 'ilang')

    def test_plain_text_and_empty(self):
        self.assertEqual(kind('User-agent: *\nAllow: /\n', 'text/plain'), 'text')
        self.assertEqual(kind(' \r\n', 'text/plain'), 'empty')

class EdgeBlockTests(unittest.TestCase):
    def test_cloudflare_1010(self):
        block = ps.edge_block_signature(403, {'server': 'cloudflare'}, 'error code: 1010')
        self.assertEqual(block['error_code'], '1010')
        self.assertEqual(block['vendor'], 'cloudflare')
        self.assertIn('Browser Integrity Check', block['meaning'])

    def test_no_signature_for_success_or_plain_403(self):
        self.assertIsNone(ps.edge_block_signature(200, {'server': 'cloudflare'}, 'error code: 1010'))
        self.assertIsNone(ps.edge_block_signature(403, {'server': 'nginx'}, '<h1>Forbidden</h1>'))

    def test_challenge_header(self):
        self.assertEqual(ps.edge_block_signature(403, {'cf-mitigated': 'challenge'}, '')['challenge'], 'challenge')

class ClassifyTests(unittest.TestCase):
    def test_edge_block_observation(self):
        result = fake_result('html', 'error code: 1010', 'text/plain', status=403)
        result['edge_block'] = ps.edge_block_signature(403, {'server': 'cloudflare'}, 'error code: 1010')
        self.assertEqual(ps.Probe.classify(result), 'edge_block_response')

    def test_local_error_observation(self):
        result = {'status': None, 'error': {'kind': 'input_rejected', 'side': 'local_input'}}
        self.assertEqual(ps.Probe.classify(result), 'not_requested_local_error')

    def test_retry_after_parsing(self):
        self.assertEqual(ps.parse_retry_after('120'), 120)
        self.assertIsNone(ps.parse_retry_after('soon'))
        from datetime import datetime, timezone
        now = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(ps.parse_retry_after('Sat, 19 Sep 2026 12:00:30 GMT', now), 30)

if __name__ == '__main__':
    unittest.main()
