"""Test support: a small agent-ready site folder and a 127.0.0.1 server for it.

Not a test module (no test_ prefix). Fixtures are generated at run time so line
endings and digests cannot be changed by a checkout that rewrites newlines.
"""
from __future__ import annotations

import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
from urllib.parse import unquote, urlsplit

sys.dont_write_bytecode = True  # keep __pycache__ out of the skill folder
SCRIPTS = Path(__file__).resolve().parent.parent / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

def _bypass_proxies_for_loopback():
    """Hermetic tests: loopback never goes through an environment or registry proxy.

    With NO_PROXY set, urllib reads proxies from the environment only (not the Windows
    registry) and bypasses 127.0.0.1 and localhost even when HTTP_PROXY is set.
    """
    for key in ('NO_PROXY', 'no_proxy'):
        current = os.environ.get(key, '')
        if '127.0.0.1' not in current:
            os.environ[key] = (current + ',' if current else '') + '127.0.0.1,localhost'
_bypass_proxies_for_loopback()

SKILL_BYTES = '---\r\nname: site-lookup\r\ndescription: Look up fixture pages\r\n---\r\n# Site lookup\r\n\r\n中文 lookup steps.\r\n'.encode('utf-8')
ROBOTS_PADDING = '# ' + 'padding line for a large robots.txt file\n# ' * 20

def sha256_digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()

def write(root, rel, content):
    path = Path(root, *rel.split('/'))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode('utf-8'))
    return path

def write_json(root, rel, doc):
    return write(root, rel, json.dumps(doc, ensure_ascii=False, indent=2) + '\n')

def build_site(root, origin, extra_wrong_digest_skill=False):
    """A complete, internally consistent site folder for `origin` (no trailing slash)."""
    write(root, 'index.html', '<!DOCTYPE html>\n<html><head><title>Fixture</title><link rel="canonical" href="%s/"></head><body><h1>Fixture site</h1><p>中文内容</p></body></html>\n' % origin)
    write(root, 'index.md', '# Fixture site\n\n中文内容\n')
    write(root, 'ai/index.html', '<!DOCTYPE html>\n<html><head><title>AI</title></head><body><h1>AI entry</h1></body></html>\n')
    write(root, 'robots.txt', ROBOTS_PADDING + '\nUser-agent: GPTBot\nUser-agent: OAI-SearchBot\nContent-Signal: search=yes, ai-input=yes, ai-train=no\nAllow: /\nDisallow: /private/\n\nUser-agent: GPTBot-Extended-Fake\nDisallow: /\n\nUser-agent: ClaudeBot/1.0\nContent-Signal: search=yes, ai-input=no, ai-train=no\nDisallow: /\n\nUser-agent: *\nContent-Signal: search=yes, ai-input=yes, ai-train=no\nAllow: /\nDisallow: /private/\n\nSitemap: %s/sitemap.xml\n' % origin)
    write(root, 'sitemap.xml', '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>%s/</loc></url></urlset>\n' % origin)
    write(root, 'llms.txt', '# Fixture\n\n> A fixture site.\n\n- [AI entry](/ai/)\n- [Auth](%s/auth.md)\n' % origin)
    write_json(root, 'openapi.json', {'openapi': '3.1.0', 'info': {'title': 'Fixture', 'version': '1'}, 'paths': {'/api/lookup': {'get': {'responses': {'200': {'description': 'ok'}}}}}})
    write_json(root, '.well-known/api-catalog', {'linkset': [{'anchor': origin + '/api/lookup', 'service-desc': [{'href': origin + '/openapi.json', 'type': 'application/json'}], 'service-doc': [{'href': origin + '/ai/', 'type': 'text/html'}]}]})
    write(root, '.well-known/agent-skills/site-lookup/SKILL.md', SKILL_BYTES)
    skills = [{'name': 'site-lookup', 'type': 'skill-md', 'description': 'Look up fixture pages', 'url': '/.well-known/agent-skills/site-lookup/SKILL.md', 'digest': sha256_digest(SKILL_BYTES)}]
    if extra_wrong_digest_skill:
        write(root, '.well-known/agent-skills/stale/SKILL.md', '# Stale\n')
        skills.append({'name': 'stale', 'type': 'skill-md', 'description': 'Digest is deliberately wrong', 'url': origin + '/.well-known/agent-skills/stale/SKILL.md', 'digest': sha256_digest(b'# Stale, old text\n')})
    write_json(root, '.well-known/agent-skills/index.json', {'$schema': 'https://schemas.agentskills.io/discovery/0.2.0/schema.json', 'skills': skills})
    write_json(root, '.well-known/mcp/server-card.json', {'serverInfo': {'name': 'fixture', 'version': '1.0.0'}, 'transport': {'type': 'streamable-http', 'endpoint': '/mcp'}, 'capabilities': {'tools': {}}})
    write_json(root, '.well-known/ai-catalog.json', {'specVersion': '1.0', 'host': {'displayName': 'Fixture', 'identifier': 'did:web:fixture.example'}, 'entries': [{'identifier': 'urn:air:fixture.example:server:lookup', 'displayName': 'Lookup', 'type': 'application/mcp-server-card+json', 'url': origin + '/.well-known/mcp/server-card.json'}]})
    marker = {'status': 'under_construction', 'available': False, 'capabilities_status': 'planned_contract_only'}
    write_json(root, '.well-known/oauth-authorization-server', dict(marker, issuer=origin, authorization_endpoint=origin + '/agent-auth/authorize', token_endpoint=origin + '/agent-auth/token', jwks_uri=origin + '/.well-known/jwks.json', grant_types_supported=['authorization_code'], response_types_supported=['code']))
    write_json(root, '.well-known/oauth-protected-resource', dict(marker, resource=origin, authorization_servers=[origin], bearer_methods_supported=['header'], planned_resource_endpoint=origin + '/agent-auth/resource'))
    write_json(root, '.well-known/jwks.json', {'keys': []})
    write(root, 'auth.md', '# Fixture auth.md\n\nComing soon; authentication is not available.\n')

def wants_markdown(accept):
    prefs = {}
    for part in (accept or '').split(','):
        bits = [b.strip() for b in part.split(';')]
        if not bits[0]: continue
        q = 1.0
        for bit in bits[1:]:
            if bit.startswith('q='):
                try: q = float(bit[2:])
                except ValueError: q = 0.0
        prefs[bits[0].lower()] = q
    md = prefs.get('text/markdown', 0.0)
    return md > 0 and md >= prefs.get('text/html', 0.0)

def send_raw(handler, status, body=b'', content_type='text/plain', headers=None, length=True):
    """Write one response exactly as given (routes of RouteServer use this)."""
    handler.send_response(status)
    handler.send_header('Content-Type', content_type)
    if length: handler.send_header('Content-Length', str(len(body)))
    for key, value in (headers or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)

class RouteServer:
    """127.0.0.1 server whose routes are functions(handler) keyed by path; for edge cases."""

    def __init__(self, routes, default=None):
        self.routes, self.default, self.requests = routes, default, []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def do_GET(self):
                server.requests.append({'method': 'GET', 'path': self.path, 'user_agent': self.headers.get('User-Agent'), 'accept': self.headers.get('Accept')})
                route = server.routes.get(self.path.split('?', 1)[0]) or server.default
                try:
                    if route is None:
                        send_raw(self, 404, b'nope')
                    else:
                        route(self)
                except (ConnectionError, OSError):
                    pass  # the client closed early (a redirect body, a deadline)

        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.httpd.daemon_threads = True
        self.origin = 'http://127.0.0.1:%d' % self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

CONTENT_TYPES = {'.html': 'text/html; charset=utf-8', '.md': 'text/markdown; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml', '.json': 'application/json'}

class FixtureServer:
    """Serves a site folder on 127.0.0.1 with negotiation and a few edge behaviours."""

    def __init__(self, root, block_python_default=True, spa_fallback=False):
        self.root, self.block_python_default, self.spa_fallback = Path(root).resolve(), block_python_default, spa_fallback
        self.requests = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def do_GET(self):
                server.requests.append({'method': 'GET', 'path': self.path, 'user_agent': self.headers.get('User-Agent'), 'accept': self.headers.get('Accept')})
                server.respond(self)

            def do_POST(self):
                server.requests.append({'method': 'POST', 'path': self.path})
                self.send_response(405)
                self.send_header('Content-Length', '0')
                self.end_headers()

        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.origin = 'http://127.0.0.1:%d' % self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def send(self, handler, status, body, content_type='text/plain; charset=utf-8', headers=None):
        body = body if isinstance(body, bytes) else body.encode('utf-8')
        extra = dict(headers or {})
        if 'gzip' in (handler.headers.get('Accept-Encoding') or '') and extra.pop('X-Fixture-Gzip', None):
            body = gzip.compress(body)
            extra['Content-Encoding'] = 'gzip'
        extra.pop('X-Fixture-Gzip', None)
        handler.send_response(status)
        handler.send_header('Content-Type', content_type)
        handler.send_header('Content-Length', str(len(body)))
        for key, value in extra.items():
            handler.send_header(key, value)
        handler.end_headers()
        handler.wfile.write(body)

    def respond(self, handler):
        agent = handler.headers.get('User-Agent') or ''
        if self.block_python_default and agent.startswith('Python-urllib'):
            return self.send(handler, 403, 'error code: 1010', headers={'Server': 'cloudflare'})
        path = unquote(urlsplit(handler.path).path)
        if path == '/go-cn':
            # Raw UTF-8 bytes in Location, as some servers send (latin-1 round trip).
            return self.send(handler, 302, '', headers={'Location': '/中文/页面'.encode('utf-8').decode('latin-1')})
        if path == '/go-other-host':
            port = self.httpd.server_address[1]
            return self.send(handler, 302, '', headers={'Location': 'http://localhost:%d/after-scope' % port})
        if path == '/中文/页面':
            return self.send(handler, 200, '<!DOCTYPE html><html><head><title>中文</title></head><body><h1>页面</h1></body></html>', 'text/html; charset=utf-8')
        if path.startswith('/slow-down'):
            seconds = path.rsplit('-', 1)[-1] if path.count('-') > 1 else '3600'
            return self.send(handler, 429, 'Too many requests', headers={'Retry-After': seconds})
        if path == '/':
            if wants_markdown(handler.headers.get('Accept')):
                body = (self.root / 'index.md').read_bytes()
                return self.send(handler, 200, body, 'text/markdown; charset=utf-8', {'Vary': 'Accept', 'x-markdown-tokens': '12'})
            body = (self.root / 'index.html').read_bytes()
            return self.send(handler, 200, body, 'text/html; charset=utf-8', {'Vary': 'Accept', 'Link': '</.well-known/api-catalog>; rel="api-catalog"', 'Content-Signal': 'search=yes, ai-input=yes, ai-train=no'})
        target = self.root / path.lstrip('/')
        if path.endswith('/'):
            target = target / 'index.html'
        if target.is_file() and self.root in target.resolve().parents:
            name = target.name
            content_type = 'application/linkset+json' if name == 'api-catalog' else CONTENT_TYPES.get(target.suffix, 'application/json')
            headers = {'X-Fixture-Gzip': '1'} if name in ('SKILL.md', 'llms.txt') else {}
            return self.send(handler, 200, target.read_bytes(), content_type, headers)
        if self.spa_fallback:
            return self.send(handler, 200, (self.root / 'index.html').read_bytes(), 'text/html; charset=utf-8')
        return self.send(handler, 404, 'Not found')
