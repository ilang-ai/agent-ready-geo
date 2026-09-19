"""verify_artifacts.py on a good local site folder and on deliberately broken copies."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from fixture_site import build_site, write, write_json
import probe_site as ps
import verify_artifacts as va

ORIGIN = 'https://fixture.example'

def run_verify(root, origin=ORIGIN):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = va.main(['--site-root', str(root), '--origin', origin])
    return code, json.loads(buffer.getvalue())

def errors(result):
    return [f for f in result['findings'] if f['level'] == 'error']

class VerifyArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        build_site(self.root, ORIGIN)

    def tearDown(self):
        self.tmp.cleanup()

    def test_good_folder(self):
        code, result = run_verify(self.root)
        self.assertEqual(errors(result), [])
        self.assertEqual(code, 0)
        checks = {f['check'] for f in result['findings']}
        for check in ('json_parses', 'api_catalog.href_resolves', 'agent_skills.digest', 'ard.entry_url_data_exclusive', 'mcp_card.server_identity', 'oauth_as.issuer_equals_origin', 'prm.resource_identity', 'auth_md.h1_contains_auth_md', 'llms_txt.starts_with_h1', 'llms_txt.link_resolves', 'robots.groups'):
            self.assertIn(check, checks)
        digest = [f for f in result['findings'] if f['check'] == 'agent_skills.digest']
        self.assertTrue(digest[0]['message'].startswith('ok:'), digest)

    def test_digest_uses_exact_bytes(self):
        # The fixture SKILL.md has CRLF line endings; converting them must break the digest.
        path = self.root / '.well-known' / 'agent-skills' / 'site-lookup' / 'SKILL.md'
        path.write_bytes(path.read_bytes().replace(b'\r\n', b'\n'))
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        self.assertEqual([f['check'] for f in errors(result)], ['agent_skills.digest'])

    def test_url_and_data_both_present(self):
        doc = json.loads((self.root / '.well-known' / 'ai-catalog.json').read_text(encoding='utf-8'))
        doc['entries'][0]['data'] = {'inline': True}
        write_json(self.root, '.well-known/ai-catalog.json', doc)
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        self.assertEqual([f['check'] for f in errors(result)], ['ard.entry_url_data_exclusive'])

    def test_prm_resource_mismatch(self):
        doc = json.loads((self.root / '.well-known' / 'oauth-protected-resource').read_text(encoding='utf-8'))
        doc['resource'] = ORIGIN + '/agent-auth/resource'
        write_json(self.root, '.well-known/oauth-protected-resource', doc)
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        found = errors(result)
        self.assertEqual([f['check'] for f in found], ['prm.resource_identity'])
        self.assertIn('path-scoped', found[0]['message'])

    def test_catalog_entry_without_anchor(self):
        doc = json.loads((self.root / '.well-known' / 'api-catalog').read_text(encoding='utf-8'))
        del doc['linkset'][0]['anchor']
        write_json(self.root, '.well-known/api-catalog', doc)
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        self.assertEqual([f['check'] for f in errors(result)], ['api_catalog.entry_anchor'])

    def test_missing_catalog_target_and_broken_json(self):
        (self.root / 'openapi.json').unlink()
        write(self.root, '.well-known/broken.json', '{"a": ')
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        found = sorted(f['check'] for f in errors(result))
        self.assertEqual(found, ['json_parses'])
        # A catalog target may be a dynamic route: a missing file is a warning (finding 22).
        self.assertIn('api_catalog.href_resolves', [f['check'] for f in result['findings'] if f['level'] == 'warn'])

    def test_issuer_mismatch_and_prm_without_as_issuer(self):
        doc = json.loads((self.root / '.well-known' / 'oauth-authorization-server').read_text(encoding='utf-8'))
        doc['issuer'] = 'https://other.example'
        write_json(self.root, '.well-known/oauth-authorization-server', doc)
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        self.assertEqual(sorted(f['check'] for f in errors(result)), ['oauth_as.issuer_equals_origin', 'prm.authorization_servers'])

    def test_path_scoped_prm_directory(self):
        (self.root / '.well-known' / 'oauth-protected-resource').unlink()
        write_json(self.root, '.well-known/oauth-protected-resource/api', {'resource': ORIGIN + '/api', 'authorization_servers': [ORIGIN], 'bearer_methods_supported': ['header']})
        code, result = run_verify(self.root)
        self.assertEqual(errors(result), [])
        self.assertEqual(code, 0)

    def test_auth_md_without_h1_and_llms_without_h1(self):
        write(self.root, 'auth.md', 'Authentication\n\n## auth.md is not an H1 here\n')
        write(self.root, 'llms.txt', 'No heading\n- [Missing](/nope/)\n')
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        self.assertEqual(sorted(f['check'] for f in errors(result)), ['auth_md.h1_contains_auth_md', 'llms_txt.starts_with_h1'])
        # A relative llms.txt link may be a dynamic route: a missing file is a warning (finding 22).
        self.assertIn('llms_txt.link_resolves', [f['check'] for f in result['findings'] if f['level'] == 'warn'])

    def test_robots_named_group_dropping_star_disallow_is_a_warning(self):
        # Dropping a * rule for a named bot can be deliberate (finding 22): a warning, exit 0.
        write(self.root, 'robots.txt', 'User-agent: *\nContent-Signal: search=yes\nDisallow: /private/\n\nUser-agent: GPTBot\nAllow: /\n')
        code, result = run_verify(self.root)
        self.assertEqual((code, errors(result)), (0, []))
        warns = [f for f in result['findings'] if f['level'] == 'warn']
        drop = [f for f in warns if f['check'] == 'robots.named_group_drops_star_disallow']
        self.assertEqual(len(drop), 1)
        self.assertIn('/private/', drop[0]['message'])
        self.assertIn('robots.content_signal_not_applied', [f['check'] for f in warns])

    def test_ard_manifest_without_catalog_fields_is_valid(self):
        write_json(self.root, '.well-known/ard.json', {'entries': [{'identifier': 'urn:air:fixture.example:server:lookup', 'displayName': 'Lookup', 'type': 'application/mcp-server-card+json', 'url': ORIGIN + '/.well-known/mcp/server-card.json', 'representativeQueries': ['find a page', 'read a page']}]})
        code, result = run_verify(self.root)
        self.assertEqual(errors(result), [])
        self.assertEqual(code, 0)
        self.assertIn('ard_manifest.entries_array', {f['check'] for f in result['findings']})

    def test_ard_manifest_url_and_data_is_an_error(self):
        write_json(self.root, '.well-known/ard.json', {'specVersion': '1.0', 'entries': [{'identifier': 'urn:air:fixture.example:server:lookup', 'displayName': 'Lookup', 'type': 'application/json', 'url': ORIGIN + '/x.json', 'data': {}}]})
        code, result = run_verify(self.root)
        self.assertEqual(code, 1)
        self.assertEqual([f['check'] for f in errors(result)], ['ard_manifest.entry_url_data_exclusive'])
        info = [f for f in result['findings'] if f['check'] == 'ard_manifest.other_top_level_members']
        self.assertEqual(info[0]['level'], 'info')

    def test_usage_errors(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            va.main([])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            va.main(['--site-root', str(self.root), '--origin', 'https://fixture.example/path'])

class SharedCheckTests(unittest.TestCase):
    def test_ard_manifest_rules(self):
        empty = ps.check_ard_manifest({'entries': []})['findings']
        self.assertEqual([(f['check'], f['result']) for f in empty], [('entries_array', 'problem')])
        entry = {'identifier': 'weather', 'displayName': 'W', 'type': 'mcp', 'url': '/w.json'}
        results = {f['check']: (f['result'], f['level']) for f in ps.check_ard_manifest({'entries': [entry], 'host': {}})['findings']}
        self.assertEqual(results['entry_required_terms'], ('ok', 'info'))
        self.assertEqual(results['entry_type_media_type'], ('problem', 'warn'))
        self.assertEqual(results['entry_identifier_urn'], ('problem', 'warn'))
        self.assertEqual(results['entry_representative_queries'], ('problem', 'warn'))
        self.assertEqual(results['other_top_level_members'], ('info', 'info'))
        missing = ps.check_ard_manifest({'entries': [{'data': {}}]})['findings']
        self.assertIn(('entry_required_terms', 'problem', 'error'), [(f['check'], f['result'], f['level']) for f in missing])

    def test_ai_home_accepts_html_markdown_or_ilang(self):
        for text, content_type in (('<!DOCTYPE html><html></html>', 'text/html'), ('# AI\n\nText\n', 'text/markdown'), ('::ILANG::v5.0\n', 'text/plain')):
            semantic = ps.semantic_body(text, content_type, True)
            result = {'status': 200, 'expected_representation': 'document', 'error': None, 'body': {'complete': True, 'semantic': semantic, 'content_decode_error': None}}
            self.assertEqual(ps.Probe.classify(result), 'representation_observed', content_type)
        semantic = ps.semantic_body('{"a": 1}', 'application/json', True)
        result = {'status': 200, 'expected_representation': 'document', 'error': None, 'body': {'complete': True, 'semantic': semantic, 'content_decode_error': None}}
        self.assertEqual(ps.Probe.classify(result), 'different_or_empty_representation')

    def test_markdown_h1s_ignore_code_fences(self):
        text = '```\n# auth.md inside a fence\n```\nTitle auth.md\n=====\n'
        self.assertEqual(ps.markdown_h1s(text), [(4, 'Title auth.md')])

    def test_soft_404_json_fallback_relabelled(self):
        rows = [{'id': 'openapi', 'scope': 'origin_root', 'status': 200, 'expected_representation': 'json', 'observation': 'representation_observed', 'body': {'sha256': 'abc'}}]
        soft = {'probes': [{'answers_200': True, 'sha256': 'abc'}]}
        self.assertEqual(ps.mark_soft_404_matches(rows, soft), ['openapi'])
        self.assertEqual(rows[0]['observation'], 'soft_404_fallback_body')
        self.assertEqual(ps.document_state(dict(rows[0], body={'sha256': 'abc', 'complete': True, 'semantic': {'kind': 'json'}}, same_body_as_unknown_path=True), b'{}', 'json')[0], 'soft_404_fallback_body')

if __name__ == '__main__':
    unittest.main()
