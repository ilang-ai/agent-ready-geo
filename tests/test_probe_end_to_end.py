"""Full probe runs against a local 127.0.0.1 fixture site (no other network)."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from fixture_site import FixtureServer, build_site
import probe_site as ps
import verify_artifacts as va

class ProbeEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / 'site'
        cls.server = FixtureServer(cls.root, block_python_default=True).__enter__()
        build_site(cls.root, cls.server.origin, extra_wrong_digest_skill=True)
        cls.probe = ps.Probe(timeout=5)
        cls.report = ps.collect(cls.server.origin + '/', cls.probe)
        cls.summary = cls.report['summary']

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__(None, None, None)
        cls.tmp.cleanup()

    def test_get_only_and_user_agents(self):
        self.assertTrue(self.server.requests)
        self.assertEqual({r['method'] for r in self.server.requests}, {'GET'})
        agents = {r['user_agent'] for r in self.server.requests}
        self.assertIn(ps.DEFAULT_USER_AGENT, agents)
        self.assertEqual({a for a in agents if a != ps.DEFAULT_USER_AGENT}, {ps.PYTHON_DEFAULT_USER_AGENT})
        self.assertEqual(self.report['collection']['user_agent'], {'value': ps.DEFAULT_USER_AGENT, 'source': 'built_in_default'})
        self.assertEqual(self.report['schema_version'], '2.0')
        self.assertEqual(self.report['tool'], 'agent-ready-geo-probe')
        self.assertTrue(self.report['schema_changes'])

    def test_homepage_and_client_difference(self):
        self.assertEqual(self.summary['homepage_status_with_probe_user_agent'], 200)
        difference = self.summary['client_difference']
        self.assertEqual(difference['verdict'], 'default_python_client_blocked')
        self.assertEqual(difference['default_client_edge_error_codes'], ['1010'])
        first = difference['comparisons'][0]
        self.assertEqual(first['default_python_client']['status'], 403)
        self.assertEqual(first['default_python_client']['first_120_body_bytes'], 'error code: 1010')
        self.assertEqual([c['resource'] for c in difference['comparisons']], ['homepage', 'robots', 'llms'])

    def test_negotiation(self):
        verdicts = self.summary['negotiation_verdicts']
        self.assertEqual(verdicts['summary'], 'markdown_negotiation_observed', verdicts)
        self.assertEqual(verdicts['x_markdown_tokens_values'], ['12', '12', '12'])

    def test_soft_404_and_well_known_parse(self):
        self.assertIs(self.summary['soft_404']['unknown_paths_answer_200'], False)
        shapes = self.summary['shape_checks']
        for ident in ('api_catalog', 'skill_index', 'mcp_card', 'ard', 'oauth_authorization_metadata', 'oauth_resource_metadata', 'auth_document', 'llms', 'jwks', 'openapi'):
            self.assertEqual(shapes[ident]['state'], 'parsed', ident)
        for ident in ('api_catalog', 'ard', 'oauth_authorization_metadata', 'oauth_resource_metadata', 'auth_document', 'llms', 'openapi'):
            self.assertEqual(shapes[ident]['problem_count'], 0, (ident, shapes[ident]['findings']))
        self.assertEqual(shapes['ard_json']['state'], 'absent')
        mcp = [f for f in shapes['mcp_card']['findings'] if f['check'] == 'transport_endpoint'][0]
        self.assertEqual(mcp['result'], 'problem')
        self.assertIn('local-only host', mcp['detail'])
        self.assertEqual(shapes['llms']['link_count'], 2)

    def test_skill_digests(self):
        artifacts = self.summary['skill_artifacts']
        self.assertEqual((artifacts['matches'], artifacts['mismatches']), (1, 1))
        good = artifacts['artifacts'][0]
        self.assertEqual(good['state'], 'match')
        good_row = next(r for r in self.report['results']['http'] if r['id'] == good['result_id'])
        self.assertEqual(good_row['headers'].get('content-encoding'), 'gzip')

    def test_robots_summary(self):
        robots = self.summary['robots']
        self.assertEqual(robots['state'], 'parsed')
        self.assertTrue(robots['content_signal']['present_in_body'])
        self.assertEqual(robots['content_signal']['values_by_group'][0]['values']['ai-train'], 'no')
        self.assertEqual(robots['content_signal']['headers']['homepage_response'], 'search=yes, ai-input=yes, ai-train=no')
        self.assertEqual(robots['named_ai_crawler_names'], ['GPTBot', 'OAI-SearchBot', 'ClaudeBot'])
        self.assertIn('Claude-Web', robots['scanner_ai_rules_bots']['missing'])
        self.assertFalse(robots['disallow_all_for_wildcard'])
        effective = {item['name']: item for item in robots['effective_rules_by_bot']}
        self.assertEqual(effective['GPTBot']['verdict'], 'named_group_keeps_star_disallows')
        self.assertEqual(effective['ClaudeBot']['verdict'], 'named_group_keeps_star_disallows')
        self.assertEqual((effective['Amazonbot']['effective_group'], effective['Amazonbot']['verdict']), ('star', 'uses_star_group'))
        self.assertEqual(robots['bots_dropping_star_disallows'], [])
        self.assertEqual(robots['bots_without_applicable_content_signal'], [])

    def test_content_signal_header_retained(self):
        home = self.report['results']['http'][0]
        self.assertEqual(home['headers']['content-signal'], 'search=yes, ai-input=yes, ai-train=no')

    def test_dns_not_applicable_for_ip_literal(self):
        self.assertEqual(self.report['results']['dns'][0]['state'], 'not_applicable')

    def test_json_round_trip_keeps_single_element_lists(self):
        again = json.loads(json.dumps(self.report, ensure_ascii=False))
        self.assertEqual(again['summary']['client_difference']['default_client_edge_error_codes'], ['1010'])
        catalog = again['summary']['shape_checks']['api_catalog']['hrefs']
        self.assertIsInstance(again['summary']['skill_artifacts']['artifacts'], list)
        self.assertIsInstance(catalog, list)

    def test_chinese_redirect_and_path(self):
        probe = ps.Probe(timeout=5)
        row = probe.fetch('cn', self.server.origin + '/go-cn', 'html')
        self.assertEqual(row['status'], 200)
        self.assertTrue(row['final_url'].endswith('/%E4%B8%AD%E6%96%87/%E9%A1%B5%E9%9D%A2'), row['final_url'])
        self.assertEqual(row['redirects'][0]['location_header'], '/中文/页面')
        direct = probe.fetch('cn2', self.server.origin + '/中文/页面', 'html')
        self.assertEqual((direct['status'], direct['input_url']), (200, self.server.origin + '/中文/页面'))

    def test_redirect_outside_scope_is_recorded_not_followed(self):
        for scope in ('host', 'site'):
            probe = ps.Probe(timeout=5, redirect_scope=scope)
            row = probe.fetch('other_' + scope, self.server.origin + '/go-other-host', 'html')
            self.assertEqual(row['status'], 302)
            self.assertEqual(row['error']['kind'], 'redirect_outside_scope')
            self.assertEqual(row['observation'], 'redirect_not_followed')
            self.assertFalse(row['redirects'][0]['followed'])
        self.assertFalse(any(r['path'] == '/after-scope' for r in self.server.requests))
        self.assertEqual(ps.site_hosts('example.com', 'site'), {'example.com', 'www.example.com'})
        self.assertEqual(ps.site_hosts('www.example.com', 'host'), {'www.example.com'})
        self.assertIsNone(ps.site_hosts('example.com', 'any'))

    def test_local_rejection_sends_nothing(self):
        before = len(self.server.requests)
        row = ps.Probe(timeout=5).fetch('bad', 'http://user:pw@127.0.0.1/', 'html')
        self.assertEqual(row['observation'], 'not_requested_local_error')
        self.assertEqual(row['error']['side'], 'local_input')
        self.assertEqual(len(self.server.requests), before)

    def test_retry_after(self):
        probe = ps.Probe(timeout=5, max_retry_after=30)
        paused = probe.fetch('slow0', self.server.origin + '/slow-down-0', 'html')
        self.assertEqual(paused['retry_after_seconds'], 0)
        self.assertEqual(probe.retry_after_events[0]['action'], 'paused_before_next_request_to_host')
        halted = probe.fetch('slow', self.server.origin + '/slow-down', 'html')
        self.assertEqual(halted['status'], 429)
        after = probe.fetch('next', self.server.origin + '/', 'html')
        self.assertEqual(after['observation'], 'not_collected')
        self.assertEqual(after['error']['kind'], 'not_collected_retry_after')

class SpaFallbackTests(unittest.TestCase):
    def test_unknown_paths_answer_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with FixtureServer(root, block_python_default=False, spa_fallback=True) as server:
                build_site(root, server.origin)
                report = ps.collect(server.origin + '/', ps.Probe(timeout=5), skip_client_difference=True)
        soft = report['summary']['soft_404']
        self.assertIs(soft['unknown_paths_answer_200'], True)
        self.assertIs(soft['html_fallback_for_unknown_json'], True)
        by_id = {r['id']: r for r in report['results']['http']}
        self.assertEqual(by_id['ard_json']['observation'], 'html_response_instead_of_requested_representation')
        self.assertEqual(report['summary']['shape_checks']['ard_json']['state'], 'html_fallback')
        self.assertIn('ard_json', report['summary']['soft_404_fallback_matches'])
        self.assertEqual(report['summary']['client_difference']['verdict'], 'not_collected')

class CliTests(unittest.TestCase):
    def test_cli_save_raw_refuse_overwrite_and_verify_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            root = tmp / 'site'
            with FixtureServer(root) as server:
                build_site(root, server.origin, extra_wrong_digest_skill=True)
                out, raw = tmp / 'probe.json', tmp / 'raw'
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(ps.main([server.origin + '/', '--output', str(out), '--save-raw', str(raw)]), 0)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    ps.main([server.origin + '/', '--output', str(out)])
            report = json.loads(out.read_text(encoding='utf-8'))
            self.assertTrue(report['collection']['raw_bodies_saved'])
            manifest = json.loads((raw / '_manifest.json').read_text(encoding='utf-8'))
            self.assertIn('homepage_default', manifest['bodies'])
            self.assertTrue((raw / manifest['bodies']['skill_artifact_1']['file']).is_file())
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = va.main(['--evidence', str(out), '--raw-dir', str(raw)])
            result = json.loads(buffer.getvalue())
            errors = [f for f in result['findings'] if f['level'] == 'error']
            self.assertEqual(code, 1)
            # The stale skill digest, and the fixture card's endpoint on 127.0.0.1.
            self.assertEqual(sorted(f['check'] for f in errors), ['agent_skills.digest', 'mcp_card.transport_endpoint'], errors)
            self.assertTrue(any(f['check'] == 'agent_skills.digest' and f['message'].startswith('ok:') for f in result['findings']))

    def test_cli_input_rejection_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(ps.main(['https://user:pw@example.com/', '--output', str(Path(tmp) / 'x.json')]), 2)
        self.assertEqual(json.loads(err.getvalue())['error']['kind'], 'input_rejected')

if __name__ == '__main__':
    unittest.main()
