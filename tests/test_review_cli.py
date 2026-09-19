"""Review findings 2, 3, 5, 11, 13, 20, 22 and --app-base through the command lines (127.0.0.1 only)."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from fixture_site import FixtureServer, RouteServer, build_site, send_raw, write, write_json
import probe_site as ps
import verify_artifacts as va

SCRIPTS = Path(__file__).resolve().parent.parent / 'scripts'
ORIGIN = 'https://fixture.example'

def strict_json(text):
    return json.loads(text, parse_constant=ps._reject_constant)

def run_script(name, args, encoding, bytecode=False):
    env = dict(os.environ, PYTHONIOENCODING=encoding)
    if bytecode:
        env.pop('PYTHONDONTWRITEBYTECODE', None)
    command = [sys.executable] + ([] if bytecode else ['-B']) + [str(name)] + list(args)
    return subprocess.run(command, capture_output=True, env=env, timeout=120)

class EncodingTests(unittest.TestCase):
    """Finding 2: piped stdout in a legacy code page never crashes or goes silent."""
    def test_probe_cli_under_cp1252_with_cjk_output_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / '证据').mkdir()
            out = tmp / '证据' / 'probe.json'
            with FixtureServer(tmp / 'site') as server:
                build_site(tmp / 'site', server.origin)
                done = run_script(SCRIPTS / 'probe_site.py', [server.origin + '/', '--output', str(out)], 'cp1252')
            self.assertEqual(done.returncode, 0, done.stderr.decode('ascii', 'replace'))
            summary = json.loads(done.stdout.decode('ascii'))
            self.assertEqual(Path(summary['output']).name, 'probe.json')
            self.assertIn('证据', summary['output'])
            report = strict_json(out.read_text(encoding='utf-8'))
            self.assertEqual(report['schema_version'], '2.0')

    def test_verifier_cli_under_cp1252_and_cp936(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'site'
            build_site(root, ORIGIN)
            write(root, 'llms.txt', '# 示例站点 ✅\n\n- [AI entry](/ai/)\n')
            for encoding in ('cp1252', 'cp936'):
                done = run_script(SCRIPTS / 'verify_artifacts.py', ['--site-root', str(root), '--origin', ORIGIN], encoding)
                self.assertEqual(done.returncode, 0, (encoding, done.stderr.decode('ascii', 'replace')))
                result = json.loads(done.stdout.decode('ascii'))
                self.assertEqual(result['counts']['error'], 0)
                self.assertTrue(any('示例' in f['message'] for f in result['findings']))

class HostileDocumentTests(unittest.TestCase):
    """Findings 3 and 5: malformed URLs, lone surrogates, NaN and deep nesting end in evidence."""
    def test_probe_cli_survives_hostile_documents(self):
        home = b'<!DOCTYPE html><html><head><link rel="canonical" href="https://[site_url]/page"><title>x</title></head><body></body></html>'
        routes = {
            '/': lambda h: send_raw(h, 200, home, 'text/html'),
            '/.well-known/api-catalog': lambda h: send_raw(h, 200, b'{"linkset": [{"anchor": "https://[api-host]/v1"}], "\\ud800": 1}', 'application/linkset+json'),
            '/openapi.json': lambda h: send_raw(h, 200, b'{"openapi": "3.1.0", "version": NaN, "paths": {}}', 'application/json'),
            '/.well-known/oauth-protected-resource': lambda h: send_raw(h, 200, b'{"resource": "https://[resource]/", "authorization_servers": ["https://x"]}', 'application/json'),
            '/.well-known/oauth-authorization-server': lambda h: send_raw(h, 200, b'{"issuer": "x", "status": ' + b'[' * 900 + b']' * 900 + b'}', 'application/json'),
            '/robots.txt': lambda h: send_raw(h, 200, b'User-agent: *\nDisallow: /x\nSitemap: https://[your-domain]/sitemap.xml\n', 'text/plain; charset=utf-7'),
        }
        with tempfile.TemporaryDirectory() as tmp, RouteServer(routes) as server:
            out = Path(tmp) / 'probe.json'
            with contextlib.redirect_stdout(io.StringIO()):
                code = ps.main([server.origin + '/', '--output', str(out), '--skip-client-difference', '--timeout', '5'])
            text = out.read_text(encoding='utf-8')
        self.assertEqual(code, 0)
        report = strict_json(text)
        shapes = report['summary']['shape_checks']
        self.assertEqual(shapes['api_catalog']['state'], 'parsed')
        self.assertIn('\\ud800', text)
        self.assertEqual(shapes['openapi']['state'], 'invalid_json')
        self.assertEqual(shapes['oauth_resource_metadata']['state'], 'parsed')
        self.assertEqual(report['summary']['canonical_navigation']['declared_canonical_resolved'], [None])
        robots = next(r for r in report['results']['http'] if r['id'] == 'robots')
        self.assertEqual(robots['body']['charset_rejected'], 'utf-7')

    def test_verifier_survives_hostile_documents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'site'
            build_site(root, ORIGIN)
            write(root, '.well-known/oauth-authorization-server', '{"issuer": "https://fixture.example/\\ud800"}')
            write(root, '.well-known/openid-configuration', '["not", "an", "object"]')
            write(root, 'robots.txt', 'User-agent: *\nAllow: /\nSitemap: https://[your-domain]/sitemap.xml\n')
            write(root, '.well-known/api-catalog', '{"linkset": [{"anchor": "https://[api-host]/v1", "service-doc": [{"href": "https://[x"}]}]}')
            out = Path(tmp) / 'verify.json'
            done = run_script(SCRIPTS / 'verify_artifacts.py', ['--site-root', str(root), '--origin', ORIGIN, '--output', str(out)], 'utf-8')
            self.assertEqual(done.returncode, 1, done.stderr.decode('utf-8', 'replace'))
            written = strict_json(out.read_text(encoding='utf-8'))
            printed = json.loads(done.stdout.decode('ascii'))
        self.assertEqual(written['counts'], printed['counts'])
        checks = {f['check'] for f in printed['findings'] if f['level'] == 'error'}
        self.assertIn('oauth_as.issuer_equals_origin', checks)
        self.assertIn('api_catalog.entry_anchor', checks)
        self.assertFalse(any(check.endswith('.check_error') for check in checks), checks)
        self.assertIn('robots.sitemap_absolute', {f['check'] for f in printed['findings'] if f['level'] == 'warn'})

class EvidenceFallbackTests(unittest.TestCase):
    """Finding 11: fallback pages for optional resources are absent, soft-404 is one warning."""
    def test_spa_fallback_site_in_evidence_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            with FixtureServer(tmp / 'site', block_python_default=False, spa_fallback=True) as server:
                build_site(tmp / 'site', server.origin)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(ps.main([server.origin + '/', '--output', str(tmp / 'p.json'), '--save-raw', str(tmp / 'raw')]), 0)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = va.main(['--evidence', str(tmp / 'p.json'), '--raw-dir', str(tmp / 'raw')])
        result = json.loads(buffer.getvalue())
        errors = [f['check'] for f in result['findings'] if f['level'] == 'error']
        self.assertEqual(errors, ['mcp_card.transport_endpoint'])  # the fixture card points at 127.0.0.1
        self.assertEqual(code, 1)
        soft = [f for f in result['findings'] if f['check'] == 'evidence.soft_404']
        self.assertEqual((len(soft), soft[0]['level']), (1, 'warn'))
        absent = {f['check'] for f in result['findings'] if "absent (the path answers with the site's fallback page)" in f['message'] and f['level'] == 'info'}
        self.assertEqual(absent, {'ard_manifest.json_parses', 'openid.json_parses'})
        optional = ('ard_json', 'openid_configuration', 'a2a_agent_card', 'web_bot_auth_directory')
        noisy = [f for f in result['findings'] if f['level'] != 'info' and any(name in f['file'] for name in optional)]
        self.assertEqual(noisy, [])

class VerifierContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'site'
        build_site(self.root, ORIGIN)

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, origin=ORIGIN):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = va.main(['--site-root', str(self.root), '--origin', origin])
        return code, json.loads(buffer.getvalue())

    def test_default_port_and_trailing_dot_origins(self):
        for origin in ('https://fixture.example:443', 'https://fixture.example.', 'HTTPS://Fixture.Example:443/'):
            code, result = self.verify(origin)
            self.assertEqual((code, [f['check'] for f in result['findings'] if f['level'] == 'error']), (0, []), origin)

    def test_mcp_card_requires_server_info(self):
        write_json(self.root, '.well-known/mcp/server-card.json', {'name': 'fixture', 'version': '1.0.0', 'transport': {'endpoint': '/mcp'}, 'capabilities': {'tools': {}}})
        code, result = self.verify()
        self.assertEqual(code, 1)
        self.assertEqual([f['check'] for f in result['findings'] if f['level'] == 'error'], ['mcp_card.server_identity'])

    def test_verifier_writes_no_bytecode(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / 'scripts'
            shutil.copytree(str(SCRIPTS), str(copy), ignore=shutil.ignore_patterns('__pycache__'))
            done = run_script(copy / 'verify_artifacts.py', ['--site-root', str(self.root), '--origin', ORIGIN], 'utf-8', bytecode=True)
            self.assertEqual(done.returncode, 0, done.stderr.decode('utf-8', 'replace'))
            self.assertFalse((copy / '__pycache__').exists())

class AppBaseTests(unittest.TestCase):
    def test_explicit_app_base_including_a_chinese_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'site'
            with FixtureServer(root, block_python_default=False) as server:
                build_site(root, server.origin)
                write(root, 'docs/index.html', '<!DOCTYPE html><html><head><title>Docs</title></head><body>docs</body></html>')
                write(root, 'docs/llms.txt', '# Docs\n\n- [Home](/docs/)\n')
                write(root, '文档/index.html', '<!DOCTYPE html><html><head><title>CN</title></head><body>cn</body></html>')
                docs = ps.collect(server.origin + '/', ps.Probe(timeout=5), app_base='/docs/', skip_client_difference=True)
                chinese = ps.collect(server.origin + '/', ps.Probe(timeout=5), app_base='/文档/', skip_client_difference=True)
                with contextlib.redirect_stderr(io.StringIO()):
                    rejected = ps.main([server.origin + '/', '--output', str(Path(tmp) / 'x.json'), '--app-base', '/docs/../admin/'])
        rows = {r['id']: r for r in docs['results']['http']}
        self.assertEqual(docs['target']['application_mount']['state'], 'explicitly_supplied')
        self.assertEqual((rows['app_home']['status'], rows['app_llms']['status']), (200, 200))
        self.assertEqual(rows['app_home']['observation'], 'representation_observed')
        self.assertEqual(chinese['target']['application_mount']['path'], '/%E6%96%87%E6%A1%A3/')
        self.assertEqual({r['id']: r for r in chinese['results']['http']}['app_home']['status'], 200)
        self.assertEqual(rejected, 2)

if __name__ == '__main__':
    unittest.main()
