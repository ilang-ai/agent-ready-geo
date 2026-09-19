#!/usr/bin/env python3
"""agent-ready-geo-probe: portable, read-only HTTP and DNS evidence collector.

Collects bounded GET evidence about a public website's agent-discovery surfaces.
It never computes the isitagentready.com score, never sends POST, never calls
MCP tools, never executes OAuth and never contacts the scanner.
"""
from __future__ import annotations

import argparse
import codecs
from datetime import datetime, timezone
import email.utils
import hashlib
import http.client
from html.parser import HTMLParser
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import string
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
import urllib.request
from urllib.request import HTTPRedirectHandler, Request, build_opener
import xml.etree.ElementTree as ET
import zlib

VERSION = '2.0'
TOOL = 'agent-ready-geo-probe'
DEFAULT_USER_AGENT = 'agent-ready-geo-probe/1.0 (+https://github.com/ilang-ai/agent-ready-geo)'
PYTHON_DEFAULT_USER_AGENT = 'Python-urllib/' + urllib.request.__version__
SCORE_NOTE = 'This is bounded read-only preflight evidence, NOT the isitagentready.com score or a complete protocol/security assessment. Missing endpoints may be optional, inapplicable, or exposed elsewhere. Shape checks are reports, never scores.'
DNS_PROVIDERS = [('cloudflare', 'https://cloudflare-dns.com/dns-query'), ('google', 'https://dns.google/resolve')]
SELECTED_HEADERS = ('content-type', 'content-encoding', 'content-length', 'link', 'vary', 'cache-control', 'cdn-cache-control', 'cloudflare-cdn-cache-control', 'expires', 'age', 'etag', 'last-modified', 'location', 'content-location', 'server', 'cf-cache-status', 'cf-ray', 'cf-mitigated', 'x-cache', 'server-timing', 'x-content-type-options', 'x-robots-tag', 'access-control-allow-origin', 'content-signal', 'x-markdown-tokens', 'retry-after')
RESOURCES = [
    ('explicit_home_markdown', '/index.md', 'markdown'),
    ('robots', '/robots.txt', 'text'),
    ('sitemap', '/sitemap.xml', 'xml'),
    ('ai_home', '/ai/', 'document'),  # HTML, Markdown or I-Lang are all accepted here
    ('ai_markdown', '/ai/index.md', 'markdown'),
    ('ai_ilang', '/ai/index.ilang', 'text'),
    ('llms', '/llms.txt', 'text'),
    ('llms_full', '/llms-full.txt', 'text'),
    ('openapi', '/openapi.json', 'json'),
    ('api_catalog', '/.well-known/api-catalog', 'json'),
    ('skill_index', '/.well-known/agent-skills/index.json', 'json'),
    ('mcp_card', '/.well-known/mcp/server-card.json', 'json'),
    ('ard', '/.well-known/ai-catalog.json', 'json'),
    ('ard_json', '/.well-known/ard.json', 'json'),
    ('a2a_agent_card', '/.well-known/agent-card.json', 'json'),
    ('web_bot_auth_directory', '/.well-known/http-message-signatures-directory', 'json'),
    ('oauth_authorization_metadata', '/.well-known/oauth-authorization-server', 'json'),
    ('openid_configuration', '/.well-known/openid-configuration', 'json'),
    ('oauth_resource_metadata', '/.well-known/oauth-protected-resource', 'json'),
    ('jwks', '/.well-known/jwks.json', 'json'),
    ('auth_document', '/auth.md', 'markdown'),
]
AI_CRAWLERS = ('GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'Claude-Web', 'anthropic-ai', 'PerplexityBot', 'Perplexity-User', 'Google-Extended', 'Google-CloudVertexBot', 'Google-Agent', 'Googlebot', 'Bingbot', 'Applebot-Extended', 'CCBot', 'Bytespider', 'Amazonbot', 'meta-externalagent', 'cohere-ai', 'Diffbot', 'Timpibot')
# Named by the scanner's ai-rules repair note fetched 2026-09-19 (dated observation):
# each needs its own explicit User-agent group; a wildcard group alone does not count.
SCANNER_AI_RULE_BOTS = ('GPTBot', 'OAI-SearchBot', 'Claude-Web', 'Google-Extended', 'Amazonbot', 'anthropic-ai', 'Bytespider', 'CCBot', 'Applebot-Extended')
CONTENT_SIGNAL_KEYS = ('search', 'ai-input', 'ai-train')
SKILL_ARTIFACT_LIMIT = 10
REQUEST_BUDGET = 150
EDGE_ERROR_CODES = {
    '1010': 'Cloudflare Browser Integrity Check: the site blocks this client signature (User-Agent or client fingerprint)',
    '1015': 'Cloudflare rate limiting',
    '1020': 'Cloudflare firewall (WAF) rule block',
}

class InputRejected(ValueError):
    """The URL is not acceptable input (policy or syntax); nothing was sent."""

class LocalEncodingError(ValueError):
    """The URL could not be encoded locally for the request line; nothing was sent."""

_HEX = frozenset('0123456789abcdefABCDEF')
_UNRESERVED = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~')
_SUB_DELIMS = frozenset("!$&'()*+,;=")
PATH_SAFE = _UNRESERVED | _SUB_DELIMS | frozenset(':@/')
QUERY_SAFE = PATH_SAFE | frozenset('?')
_HOST_CHARS = re.compile(r'[a-z0-9_.-]+')
DEFAULT_PORTS = {'http': 80, 'https': 443}
BOM = '\ufeff'
IDNA_DEVIATION_CHARACTERS = ('\u00df', '\u03c2', '\u200c', '\u200d')  # sharp s, final sigma, ZWNJ, ZWJ

def percent_encode(component, safe):
    """UTF-8 percent-encode one URL component.

    Valid %XX escapes are kept byte-for-byte (no double encoding), characters in
    `safe` are kept (so '=', '&', '/' and '+' keep their structural meaning), and
    everything else, including spaces and a stray '%', is encoded as UTF-8 bytes.
    """
    out, i, n = [], 0, len(component)
    while i < n:
        ch = component[i]
        if ch == '%' and i + 2 < n and component[i + 1] in _HEX and component[i + 2] in _HEX:
            out.append(component[i:i + 3])
            i += 3
            continue
        if ch in safe:
            out.append(ch)
        else:
            try:
                data = ch.encode('utf-8')
            except UnicodeEncodeError as exc:
                raise LocalEncodingError('Character U+%04X cannot be encoded as UTF-8' % ord(ch)) from exc
            out.append(''.join('%%%02X' % byte for byte in data))
        i += 1
    return ''.join(out)

def bracket_host_ok(netloc):
    """A bracketed host must be an IPv6 or IPvFuture literal. urlsplit enforces this only from
    Python 3.11.4; checking it here keeps 3.9-3.13 identical."""
    if '[' not in netloc and ']' not in netloc:
        return True
    start, end = netloc.find('['), netloc.find(']')
    if start == -1 or end < start or netloc.count('[') != 1 or netloc.count(']') != 1:
        return False
    inner = netloc[start + 1:end]
    if inner[:1] in ('v', 'V'):
        return True
    try:
        ipaddress.IPv6Address(inner.split('%', 1)[0])
        return True
    except ValueError:
        return False

def encode_host(hostname):
    """IDNA-encode a host name; IP literals are kept, IPv6 is bracketed."""
    if '%' in hostname:
        raise InputRejected('Percent-encoded or zone-qualified host names are not accepted')
    try:
        address = ipaddress.ip_address(hostname)
        return '[' + address.compressed + ']' if address.version == 6 else str(address)
    except ValueError:
        pass
    deviation = [ch for ch in IDNA_DEVIATION_CHARACTERS if ch in hostname]
    if deviation:
        # IDNA 2003 (the stdlib codec) maps these differently from browsers (UTS 46 / IDNA 2008).
        raise InputRejected('Host name contains an IDNA deviation character (%s) that IDNA 2003 and browsers encode differently; supply the xn-- A-label of the host instead' % ', '.join('U+%04X' % ord(ch) for ch in deviation))
    try:
        ascii_host = hostname.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise InputRejected('Host name cannot be converted with IDNA: ' + str(exc)) from exc
    if not _HOST_CHARS.fullmatch(ascii_host):
        raise InputRejected('Host name contains characters that are not valid in a DNS name')
    return ascii_host

def normalise_url(value):
    """Return (ascii_url, notes) for an HTTP(S) URL.

    Host via IDNA; path and query percent-encoded as UTF-8 while existing valid
    escapes and the query's '='/'&' structure are preserved; fragment dropped.
    Raises InputRejected (policy/syntax) or LocalEncodingError (local encoding).
    """
    if not isinstance(value, str):
        raise InputRejected('URL must be text')
    raw = value.strip()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise InputRejected('URL contains control characters')
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise InputRejected('Unparseable URL: ' + str(exc)) from exc
    scheme = parsed.scheme.lower()
    if scheme not in ('http', 'https'):
        raise InputRejected('Only HTTP and HTTPS URLs are accepted')
    if '@' in parsed.netloc:
        raise InputRejected('URL userinfo is not allowed; use a public unauthenticated URL')
    if not bracket_host_ok(parsed.netloc):
        raise InputRejected('A bracketed host must be an IPv6 literal')
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputRejected('Invalid port') from exc
    if not parsed.hostname:
        raise InputRejected('URL must have a hostname')
    host = encode_host(parsed.hostname)
    path = parsed.path or '/'
    encoded_path = percent_encode(path, PATH_SAFE)
    encoded_query = percent_encode(parsed.query, QUERY_SAFE)
    if port == DEFAULT_PORTS[scheme]:
        port = None  # https://host:443 and https://host are the same origin
    authority = host + (':' + str(port) if port is not None else '')
    url = urlunsplit((scheme, authority, encoded_path, encoded_query, ''))
    try:
        url.encode('ascii')
    except UnicodeEncodeError as exc:
        raise LocalEncodingError('Normalised URL is not ASCII') from exc
    notes = {
        'input': value,
        'normalised': url,
        'changed': url != raw,
        'host_idna_converted': host != (parsed.hostname or ''),
        'path_percent_encoded': encoded_path != path,
        'query_percent_encoded': encoded_query != parsed.query,
        'fragment_dropped': bool(parsed.fragment) or raw.endswith('#'),
    }
    return url, notes

def validated_url(value):
    """Compatibility wrapper (schema 1.0 name): the normalised ASCII URL only."""
    return normalise_url(value)[0]

def readable_header(value, limit=500):
    """http.client decodes headers as ISO-8859-1; recover UTF-8 text for the record."""
    if not value:
        return value
    try:
        value = value.encode('latin-1').decode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return value[:limit]

def origin_of(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, '', '', ''))

def canonical_origin(url):
    """scheme://host[:port] with the default port dropped and a trailing host dot removed."""
    p = urlsplit(url)
    scheme = p.scheme.lower()
    host = (p.hostname or '').rstrip('.')
    host = '[' + host + ']' if ':' in host else host
    port = p.port
    return scheme + '://' + host + (':' + str(port) if port and port != DEFAULT_PORTS.get(scheme) else '')

def same_origin(left, right):
    """Origin equality; any malformed URL (bad brackets, bad port) compares unequal."""
    def key(value):
        p = urlsplit(value)
        if not bracket_host_ok(p.netloc):
            raise ValueError('bracketed host is not an IPv6 literal')
        scheme = p.scheme.lower()
        return scheme, (p.hostname or '').rstrip('.'), p.port or DEFAULT_PORTS.get(scheme)
    try:
        return key(left) == key(right)
    except (ValueError, TypeError, AttributeError):
        return False

def validated_app_base(value, origin):
    """An explicit mount is a same-origin absolute path, never inferred."""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise InputRejected('App base contains control characters')
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment:
        raise InputRejected('App base must not contain a query or fragment')
    if parsed.scheme or parsed.netloc:
        full = validated_url(value)
        if not same_origin(full, origin):
            raise InputRejected('App base full URL must have the same origin as the target')
        path = urlsplit(full).path
    else:
        if not value.startswith('/') or value.startswith('//'):
            raise InputRejected('App base must be an absolute path such as /docs/ or a same-origin HTTP(S) URL')
        path = percent_encode(parsed.path, PATH_SAFE)
    decoded = path
    for _ in range(8):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    if unquote(decoded) != decoded:
        raise InputRejected('App base has excessive nested percent encoding')
    if '\\' in decoded or any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded) or any(part in ('.', '..') for part in decoded.split('/')):
        raise InputRejected('App base must not contain path traversal, backslashes or encoded control characters')
    return path.rstrip('/') + '/'

REDIRECT_STATUSES = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 5
MAX_CONSECUTIVE_UNAVAILABLE = 2

class NoRedirectHandler(HTTPRedirectHandler):
    """Every 3xx surfaces as a response; fetch() follows redirects itself.

    Manual following behaves the same on Python 3.9-3.13 (urllib only learned 308
    in 3.11), never reads a 3xx body, and lets every hop count against the budget.
    """
    def http_error_302(self, req, fp, code, msg, headers):
        return None
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

class SocketWatch:
    """Shuts down every socket of one fetch when its deadline passes (hard wall-clock bound)."""
    def __init__(self):
        self.sockets, self.fired, self.lock = [], False, threading.Lock()

    def add(self, sock):
        with self.lock:
            self.sockets.append(sock)
            fired = self.fired
        if fired: self._shutdown(sock)

    def fire(self):
        with self.lock:
            self.fired = True
            sockets = list(self.sockets)
        for sock in sockets: self._shutdown(sock)

    @staticmethod
    def _shutdown(sock):
        try:
            # The plain-socket method: never tears down an SSL object another thread is reading.
            socket.socket.shutdown(sock, socket.SHUT_RDWR)
        except (OSError, ValueError, TypeError):
            pass

def _watched_connection(http_class, watch):
    class Watched(http_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            create = self._create_connection
            def create_and_watch(*a, **k):
                sock = create(*a, **k)
                watch.add(sock)
                return sock
            self._create_connection = create_and_watch

        def connect(self):
            super().connect()
            watch.add(self.sock)  # the TLS socket replaces the raw one after the handshake
    Watched.__name__ = 'Watched' + http_class.__name__
    return Watched

class WatchedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, watch):
        super().__init__()
        self.watch = watch

    def do_open(self, http_class, req, **kwargs):
        return super().do_open(_watched_connection(http_class, self.watch), req, **kwargs)

def watched_tls_context(watch):
    """Verified default TLS whose sockets join the watch before the handshake starts,
    so a peer that drips the handshake is also cut off at the deadline."""
    context = ssl.create_default_context()
    try:
        context.set_alpn_protocols(['http/1.1'])
    except (NotImplementedError, AttributeError):
        pass

    class WatchedSSLSocket(ssl.SSLSocket):
        def do_handshake(self, *args, **kwargs):
            watch.add(self)
            return super().do_handshake(*args, **kwargs)
    context.sslsocket_class = WatchedSSLSocket
    return context

class WatchedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, watch):
        super().__init__(context=watched_tls_context(watch))
        self.watch = watch

    def do_open(self, http_class, req, **kwargs):
        return super().do_open(_watched_connection(http_class, self.watch), req, **kwargs)

def site_hosts(host, scope):
    """Hosts a redirect may reach: host only, host plus its www/apex twin, or any (None)."""
    if scope == 'any': return None
    host = (host or '').rstrip('.')
    hosts = {host}
    if scope == 'site' and host and not ipaddress_like(host):
        hosts.add(host[4:] if host.startswith('www.') else 'www.' + host)
    return hosts

def proxy_summary(url):
    """Whether an environment/system proxy applies to this URL; the proxy host only, never credentials."""
    try:
        parts = urlsplit(url)
        proxy = urllib.request.getproxies().get(parts.scheme)
        if not proxy:
            return {'configured': False, 'applies_to_target': False}
        bypass = bool(urllib.request.proxy_bypass(parts.hostname or ''))
        return {'configured': True, 'applies_to_target': not bypass, 'proxy_host': urlsplit(proxy if '://' in proxy else 'http://' + proxy).hostname}
    except Exception as exc:
        return {'configured': None, 'error': type(exc).__name__}

def ipaddress_like(host):
    try:
        ipaddress.ip_address(host.strip('[]'))
        return True
    except ValueError:
        return False

class HTMLDeclarations(HTMLParser):
    def __init__(self, body):
        super().__init__(convert_charrefs=True)
        self.canonical, self.links, self.h1_count = [], [], 0
        self.title, self.in_title = [], False
        self.feed(body)

    def handle_starttag(self, tag, pairs):
        a = {key: (val or '') for key, val in pairs}
        if tag == 'title': self.in_title = True
        if tag == 'h1': self.h1_count += 1
        if tag == 'link' and a.get('href'):
            item = {key: a[key] for key in ('rel', 'type', 'href') if key in a}
            self.links.append(item)
            if 'canonical' in a.get('rel', '').lower().split(): self.canonical.append(a['href'])

    def handle_endtag(self, tag):
        if tag == 'title': self.in_title = False

    def handle_data(self, data):
        if self.in_title: self.title.append(data)

_HTML_START_TAG = re.compile(r'(?i)<!doctype\s+html\b|<html\b|<head\b|<body\b')
_HTML_MARKERS = re.compile(r'(?i)<(?:html|head|body|title|h1)\b')
_FIRST_TAG = re.compile(r'<([A-Za-z][A-Za-z0-9-]*)\b')
_WHITESPACE = re.compile(r'\s*')
_MD_HEADING = re.compile(r'(?m)^ {0,3}#{1,6}[ \t]')
_HTML_FIRST_TAGS = frozenset(('meta', 'title', 'script', 'link', 'style', 'div', 'body', 'head', 'p', 'h1', 'span', 'main', 'header', 'noscript', 'base', 'template'))
SNIFF_LIMIT = 65536

def _markup_start(text):
    """Index after an optional XML declaration and any comments (linear; no regex backtracking)."""
    pos = _WHITESPACE.match(text).end()
    if text.startswith('<?xml', pos):
        end = text.find('?>', pos)
        if end == -1: return pos
        pos = _WHITESPACE.match(text, end + 2).end()
    while text.startswith('<!--', pos):
        end = text.find('-->', pos + 4)
        if end == -1: return pos
        pos = _WHITESPACE.match(text, end + 3).end()
    return pos

def looks_like_html(stripped, declared_mime=''):
    """Body sniffing that ignores what the headers claim (BOM already removed)."""
    head = stripped[:SNIFF_LIMIT]
    pos = _markup_start(head)
    if _HTML_START_TAG.match(head, pos):
        return True
    if declared_mime == 'text/markdown' and _MD_HEADING.search(head):
        return False  # Markdown may open with an HTML block such as <p align="center">
    if declared_mime in ('text/html', 'application/xhtml+xml') and _HTML_MARKERS.search(head):
        return True
    first = _FIRST_TAG.match(head, pos)
    return bool(first and first.group(1).lower() in _HTML_FIRST_TAGS)

def edge_block_signature(status, headers, text):
    """Recognise an edge (CDN/WAF) block or challenge page; None when absent."""
    if not status or status < 400:
        return None
    server = headers.get('server', '').lower()
    vendor = 'cloudflare' if ('cloudflare' in server or headers.get('cf-ray')) else 'unknown'
    head = text.lstrip('\ufeff \t\r\n')[:4096]
    match = re.match(r'(?i)error code:\s*(\d{3,5})\b', head)
    if match:
        code = match.group(1)
        return {'vendor': vendor, 'error_code': code, 'meaning': EDGE_ERROR_CODES.get(code, 'Edge error code; see the vendor documentation')}
    if headers.get('cf-mitigated'):
        return {'vendor': 'cloudflare', 'challenge': headers['cf-mitigated'][:80], 'meaning': 'Cloudflare challenge (cf-mitigated header)'}
    if vendor == 'cloudflare' and re.search(r'(?i)<title>\s*(?:just a moment|attention required)', head):
        return {'vendor': 'cloudflare', 'challenge': 'html_challenge_page', 'meaning': 'Cloudflare interstitial challenge page'}
    return None

NON_TEXT_CODECS = frozenset(('utf_7', 'unicode_escape', 'raw_unicode_escape', 'idna', 'punycode', 'undefined', 'unicode_internal'))

def safe_charset(content_type):
    """(charset, rejected): the declared charset when it is a real text codec, else UTF-8."""
    match = re.search(r'charset\s*=\s*["\']?([^;\s"\']+)', content_type or '', re.I)
    if not match:
        return 'utf-8', None
    declared = match.group(1)[:40]
    try:
        info = codecs.lookup(declared)
    except LookupError:
        return 'utf-8', declared
    if info.name.replace('-', '_') in NON_TEXT_CODECS or not getattr(info, '_is_text_encoding', True):
        return 'utf-8', declared
    return info.name, None

def decode_text(data, content_type=''):
    """Decode bytes by a safe declared charset, else UTF-8; never raises, never yields lone surrogates."""
    charset, _ = safe_charset(content_type)
    try:
        return data.decode(charset, errors='replace'), charset
    except (LookupError, UnicodeError, ValueError):
        return data.decode('utf-8', errors='replace'), 'utf-8'

def _reject_constant(name):
    raise ValueError('Non-standard JSON constant %s (JSON.parse rejects it)' % name)

def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('JSON number %s overflows to %s' % (text[:40], value))
    return value

def parse_json_text(text):
    """Strict JSON as browsers parse it: one leading BOM tolerated; NaN/Infinity rejected."""
    return json.loads(text[1:] if text.startswith(BOM) else text, parse_constant=_reject_constant, parse_float=_finite_float)

def json_text_from_bytes(data):
    """fetch().json() decodes UTF-8 whatever charset the header declares."""
    return data.decode('utf-8', errors='replace').lstrip(' \t\r\n')

def semantic_body(text, content_type, complete, raw=None):
    """Classify a body by content. `raw` (bytes) lets JSON be read as UTF-8 and XML by its own declaration."""
    stripped = text.lstrip(BOM + ' \t\r\n')
    out = {'kind': 'empty' if not stripped else 'text', 'declared_mime': (content_type or '').split(';', 1)[0].lower().strip()}
    if text.startswith(BOM): out['bom'] = True
    if not stripped: return out
    if looks_like_html(stripped, out['declared_mime']):
        out['kind'] = 'html'
        try:
            doc = HTMLDeclarations(text[:SNIFF_LIMIT])
            out.update(title=''.join(doc.title).strip()[:500], h1_count=doc.h1_count, canonical=doc.canonical[:8], link_declarations=doc.links[:32], declarations_scope='first %d characters' % SNIFF_LIMIT)
        except Exception as exc: out['parse_error'] = type(exc).__name__
        return out
    raw_start = raw.lstrip(b'\xef\xbb\xbf \t\r\n')[:1] if raw is not None else b''
    if stripped.startswith(('{', '[')) or raw_start in (b'{', b'[') or 'json' in out['declared_mime']:
        try:
            parsed = parse_json_text(json_text_from_bytes(raw) if raw is not None else text.lstrip(' \t\r\n'))
            out['kind'] = 'json'
            out['json_type'] = type(parsed).__name__
            if isinstance(parsed, dict):
                out['top_level_keys'] = list(parsed)[:60]
                out['markers'] = {key: parsed[key] for key in ('openapi', 'swagger', 'schema_version', '$schema', 'specVersion', 'version') if isinstance(parsed.get(key), (str, int, float, bool))}
            elif isinstance(parsed, list): out['array_length'] = len(parsed)
        except (ValueError, RecursionError) as exc:
            out['kind'] = 'json_incomplete' if not complete else 'invalid_json'
            out['parse_error'] = str(exc)[:250]
        return out
    if stripped.startswith('<?xml') or 'xml' in out['declared_mime'] or re.match(r'<(?:urlset|sitemapindex|rss|feed)\b', stripped):
        try:
            if raw is not None:
                xml_bytes = raw if raw.startswith((b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff')) else raw.lstrip(b' \t\r\n')
            else:
                xml_bytes = stripped.encode('utf-8')
            out['xml_root'] = ET.fromstring(xml_bytes).tag
            out['kind'] = 'xml'
        except (ET.ParseError, ValueError, LookupError) as exc:
            out['kind'] = 'xml_incomplete' if not complete else 'invalid_xml'
            out['parse_error'] = str(exc)[:250]
        return out
    if '::ILANG' in stripped[:300]: out['kind'] = 'ilang'
    elif out['declared_mime'] == 'text/markdown' or re.search(r'(?m)^(?:#{1,6} |```|[-*] \[)', stripped[:SNIFF_LIMIT]): out['kind'] = 'markdown'
    return out

def parse_content_signal(value):
    """'search=yes, ai-train=no' -> {'search': 'yes', 'ai-train': 'no'} (keys lowercased)."""
    parsed = {}
    for part in (value or '').split(','):
        if '=' in part:
            key, val = part.split('=', 1)
            if key.strip(): parsed[key.strip().lower()] = val.strip().lower()
    return parsed

ROOT_DISALLOW_PATTERNS = frozenset(('/', '/*', '*', '/*$', '*$'))
_UA_TOKEN = re.compile(r'[A-Za-z_-]+')

def product_tokens(value):
    """User-agent value -> [token] as Google's reference parser matches it.

    '*' (alone or followed by whitespace) is the wildcard; otherwise only the leading
    [A-Za-z_-]+ token counts, so 'GPTBot/1.1' is GPTBot, 'GPTBot, CCBot' names only
    GPTBot, and 'Mozilla/5.0 (compatible; GPTBot/1.1)' names neither.
    """
    value = (value or '').strip()
    if value.startswith('*') and (len(value) == 1 or value[1].isspace()):
        return ['*']
    match = _UA_TOKEN.match(value)
    return [match.group(0).lower()] if match else []

def _merged_signals(group):
    """Content-Signal values of one group; later lines override earlier ones."""
    merged = {}
    for signal in group['content_signals']: merged.update(signal['parsed'])
    values = {key: merged.get(key) for key in CONTENT_SIGNAL_KEYS}
    extra = {key: val for key, val in merged.items() if key not in CONTENT_SIGNAL_KEYS}
    if extra: values['other_keys'] = extra
    return values

def _disallow_kept(path, disallows):
    """True when `disallows` blocks `path` too: same path, or a wildcard-free prefix of it."""
    literal = re.split(r'[*$]', path, maxsplit=1)[0]
    for rule in disallows:
        if rule == path or rule in ROOT_DISALLOW_PATTERNS: return True
        base = rule[:-1] if rule.endswith('*') and '*' not in rule[:-1] else rule
        if '*' not in base and not base.endswith('$') and literal.startswith(base): return True
    return False

def effective_rules(name, groups, tokens_by_group):
    """RFC 9309 effective group for one bot: its named group(s), else the * group(s)."""
    named = [g for g, tokens in zip(groups, tokens_by_group) if name.lower() in tokens]
    star = [g for g, tokens in zip(groups, tokens_by_group) if '*' in tokens]
    chosen = named or star
    disallows = [p for g in chosen for p in g['disallow_paths']]
    star_disallows = list(dict.fromkeys(p for g in star for p in g['disallow_paths']))
    signals = [s for g in chosen for s in g['content_signals']]
    star_signals = [s for g in star for s in g['content_signals']]
    merged = {}
    for signal in signals: merged.update(signal['parsed'])
    missing = [p for p in star_disallows if not _disallow_kept(p, disallows)] if named else []
    if not chosen: verdict = 'no_group_applies'
    elif not named: verdict = 'uses_star_group'
    elif not star_disallows: verdict = 'no_star_disallow_to_compare'
    elif missing: verdict = 'named_group_drops_star_disallow'
    else: verdict = 'named_group_keeps_star_disallows'
    return {
        'name': name,
        'scanner_named': name in SCANNER_AI_RULE_BOTS,
        'effective_group': 'named' if named else ('star' if star else 'none'),
        'group_lines': [g['line'] for g in chosen],
        'disallow_paths': list(dict.fromkeys(disallows))[:50],
        'allow_paths': list(dict.fromkeys(p for g in chosen for p in g['allow_paths']))[:50],
        'disallow_root': any(g['disallow_root'] for g in chosen),
        'verdict': verdict,
        'missing_star_disallow_paths': missing[:50],
        'content_signal_applies': bool(signals),
        'content_signal_values': {key: merged.get(key) for key in CONTENT_SIGNAL_KEYS} if signals else None,
        'star_content_signal_not_inherited': bool(named and star_signals and not signals),
    }

def analyze_robots(text, header_signals=None):
    """Parse the complete robots.txt body into RFC 9309 groups and derived facts."""
    groups, current, in_agent_run = [], None, False
    sitemaps, signals, other, orphan_rules, invalid_lines = [], [], {}, 0, 0
    body = text[1:] if text.startswith(BOM) else text
    # Only CR, LF and CRLF end a line (str.splitlines would also split at U+2028 or NEL).
    for number, raw in enumerate(re.split(r'\r\n|\r|\n', body), 1):
        line = raw.split('#', 1)[0].strip()
        if not line: continue
        if ':' not in line:
            invalid_lines += 1
            continue
        key, value = line.split(':', 1)
        key, value = key.strip().lower(), value.strip()
        if key in ('user-agent', 'useragent'):
            if current is None or not in_agent_run:
                current = {'line': number, 'user_agents': [], 'allow': 0, 'disallow': 0, 'empty_allow': 0, 'empty_disallow': 0, 'disallow_root': False, 'allow_paths': [], 'disallow_paths': [], 'content_signals': [], 'other_directives': {}}
                groups.append(current)
            current['user_agents'].append(value[:200])
            in_agent_run = True
            continue
        if key == 'sitemap':
            sitemaps.append(value[:500])
            continue
        # As in Google's reference parser, only Allow/Disallow end a run of user-agent
        # lines; Content-Signal, Crawl-delay, Agentmap and unknown keys attach to the group.
        if key == 'content-signal':
            entry = {'line': number, 'value': value[:300], 'parsed': parse_content_signal(value), 'user_agents': list(current['user_agents']) if current else []}
            signals.append(entry)
            if current is not None: current['content_signals'].append({'line': number, 'value': value[:300], 'parsed': entry['parsed']})
            continue
        if key in ('allow', 'disallow'):
            in_agent_run = False
            if current is None:
                orphan_rules += 1
                continue
            if not value:
                current['empty_' + key] += 1  # an empty Allow or Disallow is not a rule
                continue
            current[key] += 1
            if key == 'disallow' and value in ROOT_DISALLOW_PATTERNS: current['disallow_root'] = True
            current[key + '_paths'].append(value[:300])
            continue
        target = current['other_directives'] if current is not None else other
        target[key] = target.get(key, 0) + 1
    tokens_by_group = [set(t for ua in g['user_agents'] for t in product_tokens(ua)) for g in groups]
    wildcard = [g for g, tokens in zip(groups, tokens_by_group) if '*' in tokens]
    def bot_entry(name):
        hits = [g for g, tokens in zip(groups, tokens_by_group) if name.lower() in tokens]
        if not hits: return None
        return {'name': name, 'group_lines': [g['line'] for g in hits], 'allow': sum(g['allow'] for g in hits), 'disallow': sum(g['disallow'] for g in hits), 'disallow_root': any(g['disallow_root'] for g in hits), 'content_signals': [s['parsed'] for g in hits for s in g['content_signals']]}
    named = [entry for entry in (bot_entry(name) for name in AI_CRAWLERS) if entry]
    scanner_named = {name: bool(bot_entry(name)) for name in SCANNER_AI_RULE_BOTS}
    effective = [effective_rules(name, groups, tokens_by_group) for name in AI_CRAWLERS]
    known = {name.lower() for name in AI_CRAWLERS} | {'*'}
    header_signals = {k: v for k, v in (header_signals or {}).items() if v}
    return {
        'parsed_from': 'complete_body',
        'bytes_analyzed': len(body.encode('utf-8', errors='replace')),
        'group_count': len(groups),
        'groups': [dict(g, allow_paths=g['allow_paths'][:50], disallow_paths=g['disallow_paths'][:50]) for g in groups[:200]],
        'groups_truncated': len(groups) > 200,
        'allow_rules': sum(g['allow'] for g in groups),
        'disallow_rules': sum(g['disallow'] for g in groups),
        'empty_disallow_rules': sum(g['empty_disallow'] for g in groups),
        'empty_allow_rules': sum(g['empty_allow'] for g in groups),
        'rules_outside_groups': orphan_rules,
        'unparseable_lines': invalid_lines,
        'non_group_directives': other,
        'sitemaps': sitemaps[:50],
        'sitemap_count': len(sitemaps),
        'content_signal': {
            'body_lines': signals[:50],
            'values_by_group': [{'group_line': g['line'], 'user_agents': g['user_agents'][:50], 'values': _merged_signals(g)} for g in groups if g['content_signals']],
            'headers': header_signals,
            'headers_parsed': {k: parse_content_signal(v) for k, v in header_signals.items()},
            'present_in_body': bool(signals),
            'present_in_header': bool(header_signals),
        },
        'named_ai_crawlers': named,
        'named_ai_crawler_names': [entry['name'] for entry in named],
        'scanner_ai_rules_bots': {
            'source': 'isitagentready.com ai-rules repair note, dated 2026-09-19; a wildcard group alone does not satisfy it',
            'explicit_group_present': scanner_named,
            'missing': [name for name, ok in scanner_named.items() if not ok],
        },
        'effective_rules_by_bot': effective,
        'bots_dropping_star_disallows': [item['name'] for item in effective if item['verdict'] == 'named_group_drops_star_disallow'],
        'bots_without_applicable_content_signal': [item['name'] for item in effective if item['effective_group'] != 'none' and not item['content_signal_applies']],
        'effective_rules_note': 'RFC 9309: a crawler obeys only the group(s) naming it and ignores *; with no named group it obeys *. A * Disallow path counts as kept when the named group disallows the same path or a wildcard-free prefix of it; Allow rules are not weighed.',
        'other_user_agents': sorted({t for tokens in tokens_by_group for t in tokens} - known)[:100],
        'wildcard_group_present': bool(wildcard),
        'disallow_all_for_wildcard': (any(g['disallow_root'] for g in wildcard) and not any(g['allow'] for g in wildcard)) if wildcard else None,
    }

def vary_tokens(value):
    return {token.strip().lower() for token in (value or '').split(',') if token.strip()}

def _row_facts(row):
    """Negotiation facts: the declared type comes from the response header; the body kind
    only counts when the body was read and decoded without error (else it is unknown)."""
    body = row.get('body') or {}
    semantic = body.get('semantic') or {}
    headers = row.get('headers') or {}
    clean = row.get('status') is not None and not row.get('error') and not body.get('content_decode_error') and semantic.get('kind') is not None
    return {'status': row.get('status'), 'declared_mime': (headers.get('content-type') or '').split(';', 1)[0].strip().lower() or None,
            'kind': semantic.get('kind') if clean else None, 'clean': clean, 'sha256': body.get('sha256'), 'complete': bool(body.get('complete')) and clean,
            'vary': headers.get('vary'), 'x_markdown_tokens': headers.get('x-markdown-tokens')}

def _served_markdown(f):
    if f['status'] is None: return None
    if f['status'] != 200 or f['declared_mime'] != 'text/markdown': return False
    if not f['clean']: return None
    return f['kind'] in ('markdown', 'ilang', 'text')

def _is_html(f):
    if f['status'] is None: return None
    if f['status'] != 200 or f['declared_mime'] == 'text/markdown': return False
    if not f['clean']: return None
    return f['kind'] == 'html'

def _returned_markdown(f):
    if f['status'] is None: return None
    if f['declared_mime'] == 'text/markdown': return True
    if not f['clean']: return None
    return f['kind'] in ('markdown', 'ilang')

def _all_or_none(values):
    """True/False when every item is decided; None (unknown) when nothing is decidable."""
    decided = [v for v in values if v is not None]
    if not decided: return None
    return all(decided) if len(decided) == len(values) else (False if not all(decided) else None)

def negotiation_verdicts(order_rows, q0_rows, default_row=None):
    """Explicit Markdown-negotiation verdicts from the alternating six-request run.

    Each verdict is True, False or None (unknown: not collected, read error or
    undecodable body). default_row is the homepage requested without Accept.
    """
    html = [_row_facts(r) for r in order_rows if r.get('accept') == 'text/html']
    md = [_row_facts(r) for r in order_rows if r.get('accept') == 'text/markdown']
    q0 = [_row_facts(r) for r in q0_rows]
    served_markdown, is_html, returned_markdown = _served_markdown, _is_html, _returned_markdown
    md_ok = [f for f in md if f['status'] == 200]
    html_ok = [f for f in html if f['status'] == 200]
    md_hashes = {f['sha256'] for f in md_ok if f['complete']}
    html_hashes = {f['sha256'] for f in html_ok if f['complete']}
    if md_hashes and html_hashes:
        differs = not (md_hashes & html_hashes)
    elif md_ok and html_ok and all(f['kind'] not in ('html', None) for f in md_ok) and all(f['kind'] == 'html' for f in html_ok):
        differs = True  # A body sniffed as Markdown/I-Lang cannot equal one sniffed as HTML, even when truncated.
    else:
        differs = None
    vary_values = [f['vary'] for f in md + html if f['status'] is not None]
    vary_accept = None if not vary_values else all(bool(vary_tokens(v) & {'accept', '*'}) for v in vary_values)
    def stable(facts):
        if not facts or not all(f['complete'] and f['status'] == 200 for f in facts): return None
        return len({f['sha256'] for f in facts}) == 1
    verdicts = {
        'markdown_served_for_text_markdown': _all_or_none([served_markdown(f) for f in md]),
        'markdown_declared_types': [f['declared_mime'] for f in md],
        'markdown_body_kinds': [f['kind'] for f in md],
        'markdown_body_differs_from_html': differs,
        'html_served_for_text_html': _all_or_none([is_html(f) for f in html]),
        'html_after_markdown_still_html': _all_or_none([is_html(f) for f in html[1:]]),
        'q0_requests_did_not_return_markdown': _all_or_none([None if returned_markdown(f) is None else not returned_markdown(f) for f in q0]),
        'vary_includes_accept': vary_accept,
        'vary_values': sorted({v for v in vary_values if v}),
        'html_hash_stable': stable(html),
        'markdown_hash_stable': stable(md),
        'x_markdown_tokens_values': [f['x_markdown_tokens'] for f in md if f['x_markdown_tokens']],
    }
    core = ('markdown_served_for_text_markdown', 'markdown_body_differs_from_html', 'html_after_markdown_still_html', 'q0_requests_did_not_return_markdown', 'vary_includes_accept')
    if default_row is not None:
        verdicts['html_served_without_accept_header'] = is_html(_row_facts(default_row))
        core += ('html_served_without_accept_header',)
    failed = [name for name in core if verdicts[name] is False]
    unknown = [name for name in core if verdicts[name] is None]
    verdicts['summary'] = 'markdown_negotiation_observed' if not failed and not unknown else ('markdown_negotiation_problems' if failed else 'markdown_negotiation_unknown')
    verdicts['failed_verdicts'] = failed
    verdicts['unknown_verdicts'] = unknown
    verdicts['note'] = 'Vary: Accept is necessary but not sufficient; the alternating order (HTML after Markdown) is the cache-isolation evidence.'
    return verdicts

def parse_retry_after(value, now=None):
    """Retry-After (delta-seconds or HTTP-date) -> whole seconds to wait, or None."""
    if not value: return None
    value = value.strip()
    if value.isascii() and value.isdigit(): return int(value)  # a superscript digit passes isdigit() but not int()
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None: return None
    if when.tzinfo is None: when = when.replace(tzinfo=timezone.utc)
    delta = (when - (now or datetime.now(timezone.utc))).total_seconds()
    return max(0, int(delta + 0.999))

def _tls_kind(err):
    """A chain that stops at 'unable to get local issuer certificate' often means the local
    trust store is missing (python.org macOS builds need 'Install Certificates.command')."""
    text = '%s %s' % (getattr(err, 'verify_message', '') or '', err)
    if 'unable to get local issuer certificate' in text:
        return 'tls_certificate_unverified', 'possibly_local'
    return 'tls_error', 'remote'

def classify_exception(exc):
    """Map an exception to (kind, side); side separates local problems from remote ones."""
    if isinstance(exc, InputRejected): return 'input_rejected', 'local_input'
    if isinstance(exc, LocalEncodingError): return 'local_encoding_error', 'local_encoding'
    if isinstance(exc, (UnicodeError, http.client.InvalidURL)): return 'local_encoding_error', 'local_encoding'
    if isinstance(exc, URLError):
        reason = exc.reason
        if isinstance(reason, (socket.timeout, TimeoutError)): return 'timeout', 'remote'
        if isinstance(reason, ssl.SSLError): return _tls_kind(reason)
        if isinstance(reason, socket.gaierror): return 'dns_resolution_failed', 'remote'
        if isinstance(reason, ConnectionRefusedError): return 'connection_refused', 'remote'
        if isinstance(reason, (UnicodeError, http.client.InvalidURL)): return 'local_encoding_error', 'local_encoding'
        return 'network_error', 'remote'
    if isinstance(exc, (socket.timeout, TimeoutError)): return 'timeout', 'remote'
    if isinstance(exc, ssl.SSLError): return _tls_kind(exc)
    if isinstance(exc, http.client.HTTPException): return 'http_protocol_error', 'remote'
    if isinstance(exc, OSError): return 'network_error', 'remote'
    if isinstance(exc, ValueError): return 'local_value_error', 'local_input'
    return type(exc).__name__, 'unknown'

def gunzip_bounded(data, limit, input_complete=True):
    """Decode gzip member(s) into at most limit+1 bytes; never raises.

    Returns (decoded, error, note). A corrupt stream keeps the decoded prefix and
    reports the error; bytes after the last member are ignored and noted; a stream
    cut short by the probe's own wire cap is a bounded prefix, not a decode error.
    """
    out, total, rest, note = [], 0, data, None
    while rest:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        offset = 0
        try:
            while offset < len(rest) and not decoder.eof:
                chunk = rest[offset:offset + 65536]
                offset += len(chunk)
                piece = decoder.decompress(chunk, limit + 1 - total)
                out.append(piece)
                total += len(piece)
                if total > limit or decoder.unconsumed_tail:
                    return b''.join(out), None, None
        except zlib.error as exc:
            return b''.join(out), 'Corrupt gzip data: %s' % str(exc)[:200], None
        if not decoder.eof:
            return b''.join(out), (None if not input_complete else 'Truncated gzip stream (no end-of-member marker)'), None
        rest = decoder.unused_data + rest[offset:]
        if rest[:2] != b'\x1f\x8b':
            if rest.strip(b'\x00'):
                note = 'Ignored %d bytes after the last gzip member' % len(rest)
            break
    return b''.join(out), None, note

class Probe:
    def __init__(self, timeout=10.0, max_body=262144, snippet_chars=1200, user_agent=DEFAULT_USER_AGENT, max_retry_after=30, request_budget=REQUEST_BUDGET, redirect_scope='site'):
        self.timeout, self.max_body, self.snippet_chars = timeout, max_body, snippet_chars
        self.user_agent = user_agent
        self.redirect_scope = redirect_scope
        self.site_hosts = set()
        self.max_retry_after = max_retry_after
        self.request_budget = request_budget
        self.requests_sent = 0
        self.raw_decoded = {}
        self.not_before = {}
        self.paused_seconds = {}
        self.consecutive_unavailable = {}
        self.halted = {}
        self.retry_after_events = []

    def _not_sent(self, result, kind, side, message):
        result['error'] = {'kind': kind, 'side': side, 'message': message[:450]}
        result['elapsed_ms'] = 0
        result['observation'] = self.classify(result)
        return result

    def _redirect_step(self, current, status, location, allowed, hops, visited):
        """Decide one redirect hop: (next URL or None, history record, error or None)."""
        record = {'status': status, 'from': current, 'location_header': readable_header(location)}
        try:
            # As urllib does: the Location bytes arrive decoded as ISO-8859-1; restore them as %XX.
            recovered = quote(location.strip(), encoding='iso-8859-1', safe=string.punctuation)
            target = normalise_url(urljoin(current, recovered))[0]
        except (ValueError, UnicodeError) as exc:
            record.update(destination_rejected=True, followed=False, reason=str(exc)[:200])
            return None, record, {'kind': 'redirect_rejected', 'side': 'local_policy', 'message': 'Redirect rejected: ' + str(exc)[:300]}
        record['to'] = target
        target_host = (urlsplit(target).hostname or '').rstrip('.')
        if allowed is not None and target_host not in allowed:
            record.update(followed=False, reason='Outside the redirect scope; no request was sent to this host')
            return None, record, {'kind': 'redirect_outside_scope', 'side': 'local_policy', 'message': 'Redirect target is outside --redirect-scope %s; recorded, not followed' % self.redirect_scope}
        if hops >= MAX_REDIRECTS or visited.get(target, 0) >= 2:
            record.update(followed=False, reason='Redirect limit (%d hops) or loop' % MAX_REDIRECTS)
            return None, record, {'kind': 'redirect_limit_or_loop', 'side': 'remote', 'message': 'Redirect not followed: limit of %d hops or a loop' % MAX_REDIRECTS}
        if target_host in self.halted:
            record.update(followed=False, reason=self.halted[target_host])
            return None, record, {'kind': 'not_collected_retry_after', 'side': 'local_policy', 'message': self.halted[target_host][:300]}
        if self.requests_sent >= self.request_budget:
            record.update(followed=False, reason='Request budget reached')
            return None, record, {'kind': 'not_collected_request_budget', 'side': 'local_policy', 'message': 'Request budget of %d reached during redirects' % self.request_budget}
        visited[target] = visited.get(target, 0) + 1
        record['followed'] = True
        return target, record, None

    def fetch(self, ident, url, expected='unknown', accept=None, scope='target_document', client='probe'):
        """One bounded GET: redirects followed here, every hop a counted request, one deadline.

        client='probe' sends the probe UA; 'python_default' sends none (urllib's default).
        Never raises: every failure becomes evidence in result['error'].
        """
        ua = self.user_agent if client == 'probe' else PYTHON_DEFAULT_USER_AGENT
        history = []
        result = {'id': ident, 'scope': scope, 'method': 'GET', 'client': client, 'user_agent': ua, 'requested_url': url, 'accept': accept, 'expected_representation': expected, 'status': None, 'final_url': url, 'redirects': history, 'headers': {}, 'error': None}
        try:
            url, notes = normalise_url(url)
        except (InputRejected, LocalEncodingError) as exc:
            return self._not_sent(result, *classify_exception(exc), str(exc))
        if notes['changed']: result['input_url'] = notes['input']
        result['requested_url'] = result['final_url'] = url
        host = (urlsplit(url).hostname or '').rstrip('.')
        allowed = site_hosts(host, self.redirect_scope)
        if allowed is not None: allowed = allowed | self.site_hosts
        if host in self.halted:
            return self._not_sent(result, 'not_collected_retry_after', 'local_policy', self.halted[host])
        if self.requests_sent >= self.request_budget:
            return self._not_sent(result, 'not_collected_request_budget', 'local_policy', 'Request budget of %d reached' % self.request_budget)
        wait = self.not_before.get(host, 0) - time.monotonic()
        if wait > 0:
            time.sleep(wait)
            result['waited_for_retry_after_ms'] = round(wait * 1000)
        request_headers = {'Accept-Encoding': 'gzip'}
        if client == 'probe': request_headers['User-Agent'] = self.user_agent
        if accept is not None: request_headers['Accept'] = accept
        # No authentication handler, cookie jar or TLS override; environment proxies apply (recorded in collection.proxy).
        started = time.monotonic()
        deadline = started + self.timeout
        watch = SocketWatch()
        timer = threading.Timer(self.timeout, watch.fire)
        timer.daemon = True
        timer.start()
        response, current, visited = None, url, {url: 1}
        try:
            while True:
                self.requests_sent += 1
                opener = build_opener(NoRedirectHandler(), WatchedHTTPHandler(watch), WatchedHTTPSHandler(watch))
                try:
                    response = opener.open(Request(current, headers=request_headers, method='GET'), timeout=max(0.1, deadline - time.monotonic()))
                except HTTPError as exc:
                    response = exc
                location = response.headers.get('Location') if response.status in REDIRECT_STATUSES else None
                if not location:
                    break
                if time.monotonic() >= deadline or watch.fired:
                    result['error'] = {'kind': 'fetch_deadline', 'side': 'remote', 'message': 'Per-fetch deadline of %ss (all hops) reached before the next redirect' % self.timeout}
                    break
                target, record, error = self._redirect_step(current, response.status, location, allowed, len(history), visited)
                history.append(record)
                if target is None:
                    result['error'] = error
                    break
                response.close()  # a 3xx body is never read
                response = None
                current = target
            result['status'] = response.status
            result['final_url'] = current
            result['headers'] = {key: readable_header(', '.join(response.headers.get_all(key)), 2000) for key in SELECTED_HEADERS if response.headers.get_all(key)}
            chunks, observed, timed_out, read_error = [], 0, False, None
            reader = getattr(response, 'read1', response.read)
            while observed <= self.max_body:
                if time.monotonic() >= deadline or watch.fired:
                    timed_out = True
                    break
                try:
                    chunk = reader(min(65536, self.max_body + 1 - observed))
                except http.client.IncompleteRead as exc:
                    if exc.partial:
                        chunks.append(exc.partial)
                        observed += len(exc.partial)
                    read_error = exc
                    break
                except (OSError, ValueError, http.client.HTTPException) as exc:
                    read_error = exc
                    break
                if not chunk: break
                chunks.append(chunk)
                observed += len(chunk)
            timed_out = timed_out or watch.fired
            wire = b''.join(chunks)
            wire_truncated = len(wire) > self.max_body or timed_out or read_error is not None
            wire = wire[:self.max_body]
            encoding = result['headers'].get('content-encoding', 'identity').strip().lower()
            claimed_length = result['headers'].get('content-length', '')
            premature_eof = claimed_length.isascii() and claimed_length.isdigit() and len(wire) < int(claimed_length) and not wire_truncated
            if premature_eof: wire_truncated = True
            body = {'wire_bytes_retained': len(wire), 'wire_sha256': hashlib.sha256(wire).hexdigest(), 'wire_complete': not wire_truncated, 'encoding': result['headers'].get('content-encoding', 'identity')}
            decoded, decode_error, decode_note = wire, None, None
            if encoding in ('gzip', 'x-gzip'):
                decoded, decode_error, decode_note = gunzip_bounded(wire, self.max_body, input_complete=not wire_truncated)
            elif encoding not in ('identity', ''):
                decoded, decode_error = b'', 'Unsupported Content-Encoding %r; compressed bytes were not interpreted as text' % encoding[:40]
            complete = not wire_truncated and len(decoded) <= self.max_body and decode_error is None
            decoded = decoded[:self.max_body]
            body.update(decoded_bytes_retained=len(decoded), complete=complete, sha256=hashlib.sha256(decoded).hexdigest(), hash_scope='complete_decoded_body' if complete else 'retained_decoded_prefix', content_decode_error=decode_error)
            if decode_note: body['content_decode_note'] = decode_note
            content_type = result['headers'].get('content-type', '')
            charset, rejected = safe_charset(content_type)
            text, charset = decode_text(decoded, content_type)
            if rejected: body['charset_rejected'] = rejected
            body.update(charset_used=charset, replacement_characters=text.count('\ufffd'), snippet=text[:self.snippet_chars], semantic=semantic_body(text, content_type, complete, raw=decoded))
            result['body'] = body
            self.raw_decoded[ident] = decoded
            block = edge_block_signature(result['status'], result['headers'], text)
            if block: result['edge_block'] = block
            if result['error'] is None:
                if timed_out:
                    result['error'] = {'kind': 'fetch_deadline', 'side': 'remote', 'message': 'Per-fetch deadline of %ss (all hops) reached; retained prefix only' % self.timeout}
                elif read_error is not None:
                    result['error'] = {'kind': 'body_read_error', 'side': classify_exception(read_error)[1], 'message': 'Body read failed (%s: %s); retained prefix only' % (type(read_error).__name__, str(read_error)[:200])}
                elif premature_eof:
                    result['error'] = {'kind': 'premature_eof', 'side': 'remote', 'message': 'Body ended before the declared Content-Length'}
            self._note_status(ident, (urlsplit(current).hostname or '').rstrip('.'), result)
        except Exception as exc:  # any failure is evidence, never a crash of the whole run
            kind, side = classify_exception(exc)
            if watch.fired: kind, side = 'fetch_deadline', 'remote'
            prefix = ('Per-fetch deadline of %ss reached; ' % self.timeout) if watch.fired else ''
            result['error'] = {'kind': kind, 'side': side, 'message': prefix + ('%s: %s' % (type(exc).__name__, exc))[:400]}
        finally:
            timer.cancel()
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
        result['observation'] = self.classify(result)
        return result

    def _note_status(self, ident, host, result):
        """Rate-limit bookkeeping: pause for Retry-After within a per-host allowance; halt a
        host after MAX_CONSECUTIVE_UNAVAILABLE consecutive 429/503 or when the allowance is spent."""
        status = result['status']
        if status is None: return
        if status not in (429, 503):
            self.consecutive_unavailable[host] = 0
            return
        count = self.consecutive_unavailable.get(host, 0) + 1
        self.consecutive_unavailable[host] = count
        seconds = parse_retry_after(result['headers'].get('retry-after'))
        if seconds is not None: result['retry_after_seconds'] = seconds
        event = {'id': ident, 'host': host, 'status': status, 'retry_after_seconds': seconds, 'consecutive_429_or_503': count}
        paused = self.paused_seconds.get(host, 0)
        if count >= MAX_CONSECUTIVE_UNAVAILABLE:
            self.halted[host] = '%d consecutive 429/503 responses; further requests to this host were not sent' % count
            event['action'] = 'stopped_further_requests_to_host'
        elif seconds is None:
            event['action'] = 'recorded_without_retry_after'
        elif paused + seconds > self.max_retry_after:
            self.halted[host] = 'Retry-After of %ss would exceed the %ss pause allowance for this host; further requests were not sent' % (seconds, self.max_retry_after)
            event['action'] = 'stopped_further_requests_to_host'
        else:
            self.paused_seconds[host] = paused + seconds
            self.not_before[host] = max(self.not_before.get(host, 0), time.monotonic() + seconds)
            event['action'] = 'paused_before_next_request_to_host'
        self.retry_after_events.append(event)

    @staticmethod
    def classify(result):
        status = result['status']
        error = result.get('error') or {}
        if status is None:
            if error.get('side') in ('local_input', 'local_encoding'): return 'not_requested_local_error'
            if error.get('kind') == 'redirect_rejected': return 'redirect_rejected'
            if error.get('kind', '').startswith('not_collected'): return 'not_collected'
            return 'request_failed'
        if result.get('edge_block'): return 'edge_block_response'
        if status in (404, 410): return 'not_found_applicability_unknown'
        if status >= 400: return 'http_error_applicability_unknown'
        if status >= 300: return 'redirect_not_followed'
        body = result.get('body', {})
        actual = body.get('semantic', {}).get('kind')
        expected = result['expected_representation']
        if actual == 'html' and expected in ('json', 'markdown', 'xml', 'text'):
            return 'html_response_instead_of_requested_representation'
        if body.get('content_decode_error') or result['error']: return 'incomplete_collection'
        if not body.get('complete', False): return 'bounded_prefix_only'
        if actual in ('invalid_json', 'invalid_xml'): return 'invalid_structured_body'
        compatible = {'html': {'html'}, 'document': {'html', 'markdown', 'ilang'}, 'json': {'json'}, 'markdown': {'markdown', 'ilang'}, 'xml': {'xml'}, 'text': {'text', 'markdown', 'ilang'}}
        if expected in compatible and actual not in compatible[expected]: return 'different_or_empty_representation'
        return 'representation_observed'

    def dns(self, hostname, skip=False):
        if skip: return [{'state': 'not_collected', 'reason': 'Explicit --skip-dns', 'hostname': hostname}]
        try:
            ipaddress.ip_address((hostname or '').strip('[]'))
            return [{'state': 'not_applicable', 'reason': 'Resolved target URL uses an IP literal, not a DNS hostname', 'hostname': hostname}]
        except ValueError: pass
        if hostname == 'localhost' or hostname.endswith('.localhost'):
            return [{'state': 'not_applicable', 'reason': 'Localhost hostname', 'hostname': hostname}]
        name = '_index._agents.' + hostname.rstrip('.')
        rows = []
        for provider, endpoint in DNS_PROVIDERS:
            url = endpoint + '?' + urlencode({'name': name, 'type': '64', 'do': 'true', 'cd': 'false'})
            result = self.fetch('dns_' + provider, url, 'json', 'application/dns-json', scope='dns_resolver')
            evidence = {'provider': provider, 'query_name': name, 'query_type': 'SVCB (64)', 'http': result, 'Status': None, 'AD': None}
            try:
                payload = parse_json_text(self.raw_decoded.get('dns_' + provider, b'').decode('utf-8', errors='replace'))
                if not isinstance(payload, dict): raise ValueError('DNS JSON was not an object')
                evidence.update({key: payload[key] for key in ('Status', 'AD', 'CD', 'TC', 'RD', 'RA', 'Question', 'Answer', 'Authority', 'Additional', 'Comment') if key in payload})
                evidence['state'] = 'dns_response' if 'Status' in payload else 'unexpected_json_shape'
            except (ValueError, RecursionError) as exc:
                evidence.update(state='unavailable_or_unparseable', error=str(exc)[:200])
            rows.append(evidence)
        return rows

# --- Known-resource shape checks: pure functions shared with verify_artifacts.py ---
# Each finding: check, result (ok | problem | info), detail, level (verify severity
# hint for a problem: error | warn). The probe reports them and never scores them.
KNOWN_SKILLS_SCHEMA = 'https://schemas.agentskills.io/discovery/0.2.0/schema.json'
OAUTH_AS_REQUIRED = ('issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'grant_types_supported', 'response_types_supported')
CONSTRUCTION_MARKERS = ('status', 'available', 'capabilities_status')
SHA256_DIGEST = re.compile(r'sha256:[0-9a-fA-F]{64}')
LOCAL_ONLY_HOST = re.compile(r'(?i)^(?:localhost|.+\.localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|::1|.+\.local|.+\.internal)$')
# Link text excludes '[' and the destination excludes parentheses except one balanced
# (...) group; every repetition is bounded, so hostile lines stay linear.
MD_LINK = re.compile(r'\[[^\[\]\n]{0,1000}\]\([ \t]{0,20}<?((?:[^()\s<>]|\([^()\s<>]{0,200}\)){1,500})>?(?:[ \t]{1,20}["\'][^)\n]{0,300}["\'])?[ \t]{0,20}\)')
BARE_URL = re.compile(r'(?<![(<\w])https?://[^\s)<>\]"\']+')

def _f(check, result, detail='', level='error'):
    return {'check': check, 'result': result, 'detail': detail, 'level': level if result == 'problem' else 'info'}

def _is_str(value):
    return isinstance(value, str) and bool(value.strip())

def _nonempty_list(value):
    return isinstance(value, list) and bool(value)

def _join(base, href):
    """urljoin that returns None for malformed input (unbalanced or non-IP brackets, bad ports)."""
    try:
        joined = urljoin(base, href)
        parts = urlsplit(joined)
        parts.port
        return joined if bracket_host_ok(parts.netloc) else None
    except (ValueError, TypeError, AttributeError):
        return None

def _url_scheme(value):
    """The URL's scheme, 'relative' when it has none, or None when it does not parse."""
    try:
        parts = urlsplit(value)
        parts.port
    except (ValueError, TypeError, AttributeError):
        return None
    if not bracket_host_ok(parts.netloc):
        return None
    return parts.scheme.lower() or 'relative'

def _url_host(value):
    try:
        return urlsplit(value).hostname or ''
    except (ValueError, TypeError, AttributeError):
        return ''

def construction_markers(doc):
    return {key: doc.get(key) for key in CONSTRUCTION_MARKERS if key in doc} or None

def _marker_findings(doc):
    markers = construction_markers(doc)
    if not markers: return []
    out = [_f('construction_markers', 'info', 'Declared state: ' + ', '.join('%s=%s' % (k, json.dumps(v)) for k, v in markers.items()))]
    if doc.get('available') is False:
        out.append(_f('declared_unavailable', 'info', 'available=false: a planned-contract declaration, not a working service'))
    return out

def check_api_catalog(doc, base_url):
    findings, hrefs = [], []
    linkset = doc.get('linkset') if isinstance(doc, dict) else None
    if not isinstance(linkset, list):
        return {'findings': [_f('linkset_array', 'problem', 'Top-level "linkset" array is missing')], 'hrefs': hrefs}
    findings.append(_f('linkset_array', 'ok' if linkset else 'problem', '%d entries' % len(linkset) if linkset else '"linkset" is empty'))
    for index, entry in enumerate(linkset):
        label = 'linkset[%d]' % index
        if not isinstance(entry, dict):
            findings.append(_f('entry_object', 'problem', label + ' is not an object'))
            continue
        anchor = entry.get('anchor')
        if not _is_str(anchor):
            findings.append(_f('entry_anchor', 'problem', label + ' has no anchor'))
        elif not _url_scheme(anchor):
            findings.append(_f('entry_anchor', 'problem', label + ' anchor is not a valid URL: ' + anchor[:200]))
        elif _url_scheme(anchor) == 'relative':
            findings.append(_f('entry_anchor', 'problem', label + ' anchor is relative; use an absolute URI', 'warn'))
        else:
            findings.append(_f('entry_anchor', 'ok', label + ' anchor ' + anchor[:200]))
        found = []
        for rel in ('service-desc', 'service-doc', 'status', 'service-meta'):
            targets = entry.get(rel)
            if targets is None: continue
            if not isinstance(targets, list):
                findings.append(_f('entry_relation_shape', 'problem', '%s "%s" must be an array of link objects' % (label, rel)))
                continue
            for target in targets:
                if isinstance(target, dict) and _is_str(target.get('href')):
                    found.append(rel)
                    hrefs.append({'entry': index, 'rel': rel, 'href': target['href'], 'resolved': _join(base_url, target['href']), 'type': target.get('type')})
                else:
                    findings.append(_f('entry_relation_shape', 'problem', '%s "%s" has a target without href' % (label, rel)))
        if not any(rel in found for rel in ('service-desc', 'service-doc')):
            findings.append(_f('entry_service_links', 'problem', label + ' has no service-desc or service-doc href'))
        else:
            missing = [rel for rel in ('service-desc', 'service-doc') if rel not in found]
            findings.append(_f('entry_service_links', 'problem' if missing else 'ok', label + (' lacks ' + ' and '.join(missing) if missing else ' has service-desc and service-doc'), 'warn'))
    return {'findings': findings, 'hrefs': hrefs}

def check_skill_index(doc):
    findings, skills = [], []
    if not isinstance(doc, dict):
        return {'findings': [_f('index_object', 'problem', 'Index is not a JSON object')], 'skills': skills}
    schema = doc.get('$schema')
    if not _is_str(schema):
        findings.append(_f('schema_field', 'problem', '"$schema" is missing'))
    elif schema != KNOWN_SKILLS_SCHEMA:
        findings.append(_f('schema_field', 'info', '"$schema" is %s; the dated 0.2.0 URL is %s; re-check the current draft' % (schema[:200], KNOWN_SKILLS_SCHEMA)))
    else:
        findings.append(_f('schema_field', 'ok', schema))
    entries = doc.get('skills')
    if not _nonempty_list(entries):
        findings.append(_f('skills_array', 'problem', '"skills" must be a non-empty array'))
        return {'findings': findings, 'skills': skills}
    findings.append(_f('skills_array', 'ok', '%d skills' % len(entries)))
    for index, entry in enumerate(entries):
        label = 'skills[%d]' % index
        if not isinstance(entry, dict):
            findings.append(_f('skill_fields', 'problem', label + ' is not an object'))
            continue
        missing = [key for key in ('name', 'type', 'description', 'url', 'digest') if not _is_str(entry.get(key))]
        findings.append(_f('skill_fields', 'problem' if missing else 'ok', label + (' missing ' + ', '.join(missing) if missing else ' ' + entry['name'][:80])))
        if _is_str(entry.get('name')) and not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', entry['name']):
            findings.append(_f('skill_name_format', 'problem', label + ' name should be lowercase alphanumeric with hyphens', 'warn'))
        if _is_str(entry.get('type')) and entry['type'] not in ('skill-md', 'archive'):
            findings.append(_f('skill_type', 'problem', label + ' type %r is neither skill-md nor archive' % entry['type'][:40], 'warn'))
        if _is_str(entry.get('digest')) and not SHA256_DIGEST.fullmatch(entry['digest'].strip()):
            findings.append(_f('skill_digest_format', 'problem', label + ' digest must be sha256:<64 hex digits>'))
        skills.append({'index': index, 'name': entry.get('name'), 'type': entry.get('type'), 'url': entry.get('url'), 'digest': entry.get('digest')})
    return {'findings': findings, 'skills': skills}

def mcp_endpoint(doc):
    """Find the card's transport endpoint in the scanner shape or a current equivalent."""
    candidates = [('endpoint', doc.get('endpoint'))]
    transport = doc.get('transport')
    if isinstance(transport, dict):
        candidates += [('transport.endpoint', transport.get('endpoint')), ('transport.url', transport.get('url'))]
    candidates.append(('url', doc.get('url')))
    for key in ('remotes', 'endpoints', 'transports'):
        items = doc.get(key)
        if isinstance(items, list):
            candidates += [('%s[%d].url' % (key, i), item.get('url') or item.get('endpoint')) for i, item in enumerate(items) if isinstance(item, dict)]
    for where, value in candidates:
        if _is_str(value): return where, value
    return None, None

def check_mcp_card(doc, base_url):
    if not isinstance(doc, dict):
        return {'findings': [_f('card_object', 'problem', 'Card is not a JSON object')], 'endpoint': None}
    findings = []
    info = doc.get('serverInfo')
    if isinstance(info, dict) and _is_str(info.get('name')) and _is_str(info.get('version')):
        findings.append(_f('server_identity', 'ok', 'serverInfo %s %s' % (info['name'][:80], info['version'][:40])))
    elif _is_str(doc.get('name')) and _is_str(doc.get('version')):
        findings.append(_f('server_identity', 'problem', 'serverInfo.name and serverInfo.version are required (the scanner reads serverInfo); only top-level name/version found'))
    else:
        findings.append(_f('server_identity', 'problem', 'serverInfo.name and serverInfo.version are missing'))
    where, endpoint = mcp_endpoint(doc)
    resolved = _join(base_url, endpoint) if endpoint else None
    if not endpoint:
        findings.append(_f('transport_endpoint', 'problem', 'No transport endpoint URL (endpoint, transport.endpoint, url or remotes[].url)'))
    else:
        if _url_scheme(resolved or '') not in ('http', 'https'):
            findings.append(_f('transport_endpoint', 'problem', '%s is not a valid HTTP(S) URL: %s' % (where, endpoint[:200])))
        elif LOCAL_ONLY_HOST.match(_url_host(resolved)[:260]):
            findings.append(_f('transport_endpoint', 'problem', '%s points to a local-only host: %s' % (where, resolved[:200])))
        else:
            findings.append(_f('transport_endpoint', 'ok', '%s: %s' % (where, resolved[:200])))
    capabilities = doc.get('capabilities')
    findings.append(_f('capabilities', 'ok' if isinstance(capabilities, (dict, list)) and capabilities else 'problem', 'capabilities declared' if capabilities else '"capabilities" missing or empty', 'warn'))
    return {'findings': findings, 'endpoint': resolved, 'endpoint_field': where}

def check_ard(doc):
    if not isinstance(doc, dict):
        return {'findings': [_f('catalog_object', 'problem', 'Catalog is not a JSON object')], 'entry_urls': []}
    findings, urls = [], []
    findings.append(_f('spec_version', 'ok' if _is_str(doc.get('specVersion')) else 'problem', 'specVersion %s' % str(doc.get('specVersion'))[:40] if _is_str(doc.get('specVersion')) else '"specVersion" must be a non-empty string'))
    host = doc.get('host')
    host_ok = isinstance(host, dict) and _is_str(host.get('displayName')) and _is_str(host.get('identifier'))
    findings.append(_f('host_identity', 'ok' if host_ok else 'problem', 'host %s' % host.get('identifier', '')[:120] if host_ok else 'host.displayName and host.identifier are expected', 'warn'))
    entries = doc.get('entries')
    if not _nonempty_list(entries):
        findings.append(_f('entries_array', 'problem', '"entries" must be a non-empty array'))
        return {'findings': findings, 'entry_urls': urls}
    findings.append(_f('entries_array', 'ok', '%d entries' % len(entries)))
    for index, entry in enumerate(entries):
        label = 'entries[%d]' % index
        if not isinstance(entry, dict):
            findings.append(_f('entry_object', 'problem', label + ' is not an object'))
            continue
        has_url, has_data = entry.get('url') is not None, entry.get('data') is not None
        if has_url and has_data:
            findings.append(_f('entry_url_data_exclusive', 'problem', label + ' has both url and data; exactly one is allowed'))
        elif not has_url and not has_data:
            findings.append(_f('entry_url_data_exclusive', 'problem', label + ' has neither url nor data; exactly one is required'))
        else:
            findings.append(_f('entry_url_data_exclusive', 'ok', label + (' url' if has_url else ' data')))
        missing = [key for key in ('identifier', 'displayName', 'type') if not _is_str(entry.get(key))]
        if missing: findings.append(_f('entry_fields', 'problem', label + ' missing ' + ', '.join(missing), 'warn'))
        if _is_str(entry.get('identifier')) and not entry['identifier'].startswith('urn:air:'):
            findings.append(_f('entry_identifier_form', 'info', label + ' identifier is not urn:air:...; the scanner reports but does not fail this'))
        if has_url and _is_str(entry.get('url')): urls.append({'entry': index, 'url': entry['url'], 'type': entry.get('type')})
    return {'findings': findings, 'entry_urls': urls}

MEDIA_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*")

def is_air_urn(value):
    """urn:air:<fqdn>:<namespace>:<name>, checked by splitting (no regex backtracking)."""
    if len(value) > 2048 or any(ch.isspace() for ch in value): return False
    parts = value.split(':')
    if len(parts) < 5 or parts[0].lower() != 'urn' or parts[1].lower() != 'air': return False
    return '.' in parts[2].strip('.') and bool(parts[3]) and bool(':'.join(parts[4:]))

def check_ard_manifest(doc):
    """/.well-known/ard.json per the ARD v0.91 Proposal text (sec. 5.1, sec. 4.2, sec. 4.3, App. C, sec. D.2).

    The manifest is a JSON document with an entries array; other top-level members
    are ignored by ARD (reported as info). specVersion and host are not required.
    """
    if not isinstance(doc, dict):
        return {'findings': [_f('manifest_object', 'problem', 'Manifest is not a JSON object with an "entries" array')], 'entry_urls': []}
    findings, urls = [], []
    entries = doc.get('entries')
    if not isinstance(entries, list):
        findings.append(_f('entries_array', 'problem', '"entries" array is missing (sec. 5.1)'))
    elif not entries:
        findings.append(_f('entries_array', 'problem', '"entries" is empty; nothing is discoverable'))
    else:
        findings.append(_f('entries_array', 'ok', '%d entries' % len(entries)))
    other = [key for key in doc if key != 'entries']
    if other:
        findings.append(_f('other_top_level_members', 'info', 'Ignored by ARD (sec. 5.1, transport-defined): ' + ', '.join(other[:20])))
    for index, entry in enumerate(entries if isinstance(entries, list) else []):
        label = 'entries[%d]' % index
        if not isinstance(entry, dict):
            findings.append(_f('entry_object', 'problem', label + ' is not an object'))
            continue
        missing = [key for key in ('identifier', 'displayName', 'type') if not _is_str(entry.get(key))]
        findings.append(_f('entry_required_terms', 'problem' if missing else 'ok', label + (' missing MUST terms (sec. 4.2): ' + ', '.join(missing) if missing else ' identifier, displayName, type present')))
        has_url, has_data = entry.get('url') is not None, entry.get('data') is not None
        if has_url == has_data:
            findings.append(_f('entry_url_data_exclusive', 'problem', label + (' carries both url and data' if has_url else ' carries neither url nor data') + '; exactly one is required (sec. 4.3)'))
        else:
            findings.append(_f('entry_url_data_exclusive', 'ok', label + (' url' if has_url else ' data')))
        if _is_str(entry.get('type')) and not MEDIA_TYPE.fullmatch(entry['type'].split(';', 1)[0].strip()):
            findings.append(_f('entry_type_media_type', 'problem', label + ' type %r is not a type/subtype media type (sec. 4.2)' % entry['type'][:80], 'warn'))
        if _is_str(entry.get('identifier')) and not is_air_urn(entry['identifier']):
            findings.append(_f('entry_identifier_urn', 'problem', label + ' identifier is not urn:air:<fqdn>:<namespace>:<name> (Appendix C)', 'warn'))
        queries = entry.get('representativeQueries')
        if not (isinstance(queries, list) and 2 <= len(queries) <= 5):
            findings.append(_f('entry_representative_queries', 'problem', label + ' representativeQueries should hold 2-5 examples (sec. 4.2, sec. D.2 warning)', 'warn'))
        if has_url and _is_str(entry.get('url')): urls.append({'entry': index, 'url': entry['url'], 'type': entry.get('type')})
    return {'findings': findings, 'entry_urls': urls}

def check_oauth_as(doc, origin):
    if not isinstance(doc, dict):
        return {'findings': [_f('metadata_object', 'problem', 'Metadata is not a JSON object')], 'issuer': None}
    findings = []
    issuer = doc.get('issuer')
    if not _is_str(issuer):
        findings.append(_f('issuer_equals_origin', 'problem', '"issuer" is missing'))
    elif issuer == origin:
        findings.append(_f('issuer_equals_origin', 'ok', 'issuer equals the origin ' + origin))
    elif issuer.rstrip('/') == origin:
        findings.append(_f('issuer_equals_origin', 'problem', 'issuer %s has a trailing slash; exact-match consumers compare it with %s' % (issuer[:200], origin), 'warn'))
    else:
        findings.append(_f('issuer_equals_origin', 'problem', 'issuer %s does not equal the origin %s' % (issuer[:200], origin)))
    missing = [key for key in OAUTH_AS_REQUIRED[1:] if not (_nonempty_list(doc.get(key)) if key.endswith('_supported') else _is_str(doc.get(key)))]
    findings.append(_f('scanner_required_fields', 'problem' if missing else 'ok', 'Missing or empty: ' + ', '.join(missing) if missing else 'issuer, authorization_endpoint, token_endpoint, jwks_uri, grant_types_supported, response_types_supported present'))
    if isinstance(doc.get('agent_auth'), dict):
        findings.append(_f('agent_auth_block', 'info', 'agent_auth block present'))
    findings.extend(_marker_findings(doc))
    return {'findings': findings, 'issuer': issuer if _is_str(issuer) else None, 'construction_markers': construction_markers(doc)}

def check_prm(doc, origin, as_issuers=(), resource_path=''):
    """RFC 9728: the resource must equal the identifier the well-known URL was built from.

    resource_path is '' for /.well-known/oauth-protected-resource and '/api' for
    /.well-known/oauth-protected-resource/api (path-scoped metadata).
    """
    if not isinstance(doc, dict):
        return {'findings': [_f('metadata_object', 'problem', 'Metadata is not a JSON object')], 'resource': None}
    findings, expected = [], origin + resource_path
    resource = doc.get('resource')
    relation = None
    if not _is_str(resource):
        findings.append(_f('resource_identity', 'problem', '"resource" is missing'))
    elif resource == expected:
        relation = 'equals_origin' if not resource_path else 'equals_path_scoped_identifier'
        findings.append(_f('resource_identity', 'ok', 'resource equals ' + expected))
    elif resource.rstrip('/') == expected.rstrip('/'):
        relation = 'trailing_slash_differs'
        findings.append(_f('resource_identity', 'problem', 'resource %s differs from %s only by a trailing slash' % (resource[:200], expected), 'warn'))
    elif same_origin(resource, origin):
        relation = 'path_scoped_same_origin'
        findings.append(_f('resource_identity', 'problem', 'resource %s is path-scoped, but this document is published for %s; RFC 9728 requires them to be identical (path-scoped metadata lives at /.well-known/oauth-protected-resource/<path>). A planned endpoint belongs in a separate field such as planned_resource_endpoint' % (resource[:200], expected)))
    else:
        relation = 'different_origin'
        findings.append(_f('resource_identity', 'problem', 'resource %s is not on the origin %s' % (resource[:200], origin)))
    servers = doc.get('authorization_servers')
    if not _nonempty_list(servers) or not all(_is_str(s) for s in servers):
        findings.append(_f('authorization_servers', 'problem', '"authorization_servers" must be a non-empty array of issuer URLs'))
    else:
        known = [issuer for issuer in as_issuers if issuer]
        if known and not any(issuer in servers for issuer in known):
            findings.append(_f('authorization_servers', 'problem', 'authorization_servers %s does not include the published AS issuer %s' % (json.dumps(servers)[:300], ', '.join(known))))
        else:
            findings.append(_f('authorization_servers', 'ok', json.dumps(servers)[:300] + (' includes the AS issuer' if known else ' (no AS metadata to compare)')))
    bearer = doc.get('bearer_methods_supported')
    findings.append(_f('bearer_methods', 'ok' if isinstance(bearer, list) and 'header' in bearer else 'problem', 'bearer_methods_supported includes header' if isinstance(bearer, list) and 'header' in bearer else 'bearer_methods_supported should include "header"', 'warn'))
    findings.extend(_marker_findings(doc))
    return {'findings': findings, 'resource': resource if _is_str(resource) else None, 'resource_relation': relation, 'construction_markers': construction_markers(doc)}

MD_LINE_BREAK = re.compile(r'\r\n|\r|\n')

def _atx_h1(line):
    """Text of an ATX H1 line, else None (manual parse: linear on hostile input)."""
    rest = line.lstrip(' ')
    if len(line) - len(rest) > 3 or not rest.startswith('#') or rest.startswith('##'):
        return None
    content = rest[1:]
    if content and content[0] not in ' \t':
        return None
    content = content.strip(' \t')
    without_closing = content.rstrip('#')
    if without_closing != content and (not without_closing or without_closing[-1] in ' \t'):
        content = without_closing.rstrip(' \t')
    return content

def _setext_h1_underline(line):
    rest = line.lstrip(' ')
    body = rest.rstrip(' \t')
    return len(line) - len(rest) <= 3 and bool(body) and set(body) == {'='}

def markdown_lines(text):
    """Split on CR, LF and CRLF only (str.splitlines also splits at U+2028 and NEL)."""
    return MD_LINE_BREAK.split(text[1:] if text.startswith(BOM) else text)

def markdown_h1s(text):
    """(line, text) for ATX and Setext H1 headings outside fenced code blocks."""
    found, fenced = [], False
    lines = markdown_lines(text)
    for index, line in enumerate(lines):
        rest = line.lstrip(' ')
        if len(line) - len(rest) <= 3 and rest.startswith(('```', '~~~')):
            fenced = not fenced
            continue
        if fenced: continue
        title = _atx_h1(line)
        if title is not None:
            found.append((index + 1, title))
        elif line.strip() and not line.startswith(('    ', '\t')) and index + 1 < len(lines) and _setext_h1_underline(lines[index + 1]):
            found.append((index + 1, line.strip()))
    return found

def check_auth_md(text):
    h1s = markdown_h1s(text)
    hit = next((h for h in h1s if 'auth.md' in h[1].lower()), None)
    if hit: return {'findings': [_f('h1_contains_auth_md', 'ok', 'Line %d: # %s' % (hit[0], hit[1][:120]))]}
    detail = 'No H1 contains "auth.md"' + ('; H1s found: ' + '; '.join(h[1][:60] for h in h1s[:3]) if h1s else '; no H1 found')
    return {'findings': [_f('h1_contains_auth_md', 'problem', detail)]}

def check_llms_txt(text):
    stripped = text[1:] if text.startswith(BOM) else text
    first = next((line for line in markdown_lines(stripped) if line.strip()), '')
    findings = [_f('starts_with_h1', 'ok' if _atx_h1(first) else 'problem', 'First line: ' + first[:120])]
    links = MD_LINK.findall(stripped)
    linked = set(links)
    bare = [url for url in (found.rstrip('.,;:!?') for found in BARE_URL.findall(stripped)) if url not in linked]
    findings.append(_f('link_count', 'ok' if links or bare else 'problem', '%d Markdown links, %d bare URLs' % (len(links), len(bare)), 'warn'))
    return {'findings': findings, 'links': (links + bare)[:500], 'link_count': len(links) + len(bare)}

def check_agent_card(doc):
    if not isinstance(doc, dict):
        return {'findings': [_f('card_object', 'problem', 'Agent card is not a JSON object')]}
    interfaces = doc.get('supportedInterfaces')
    url = doc.get('url') if _is_str(doc.get('url')) else next((i.get('url') for i in interfaces if isinstance(i, dict) and _is_str(i.get('url'))), None) if isinstance(interfaces, list) else None
    return {'findings': [
        _f('name', 'ok' if _is_str(doc.get('name')) else 'problem', str(doc.get('name'))[:120] if _is_str(doc.get('name')) else '"name" is missing'),
        _f('service_url', 'ok' if url else 'problem', url[:200] if url else 'No "url" or supportedInterfaces[].url'),
    ]}

def check_key_set(doc, empty_level):
    """Web Bot Auth directory (empty_level=warn) or JWKS (empty_level=info)."""
    if not isinstance(doc, dict) or not isinstance(doc.get('keys'), list):
        return {'findings': [_f('keys_array', 'problem', '"keys" array is missing')]}
    keys = doc['keys']
    if keys:
        return {'findings': [_f('keys_array', 'ok', '%d keys' % len(keys))], 'key_count': len(keys)}
    if empty_level == 'info':
        return {'findings': [_f('keys_array', 'info', 'Empty key set: acceptable only as a disclosed disabled planned-contract JWKS, never as working token validation')], 'key_count': 0}
    return {'findings': [_f('keys_array', 'problem', 'Empty key set: no public key to verify signatures', empty_level)], 'key_count': 0}

def check_openapi(doc):
    if not isinstance(doc, dict):
        return {'findings': [_f('openapi_object', 'problem', 'OpenAPI document is not a JSON object')]}
    version = doc.get('openapi') or doc.get('swagger')
    return {'findings': [
        _f('openapi_version', 'ok' if _is_str(version) else 'problem', 'openapi ' + str(version)[:20] if _is_str(version) else '"openapi" version field is missing', 'warn'),
        _f('paths', 'ok' if isinstance(doc.get('paths'), dict) and doc['paths'] else 'problem', '%d paths' % len(doc['paths']) if isinstance(doc.get('paths'), dict) else '"paths" is missing', 'warn'),
    ]}

def document_state(result, data, want='json'):
    """(state, parsed) for a fetched resource; only complete, non-HTML bodies are parsed."""
    if result is None: return 'not_fetched', None
    status = result.get('status')
    if status is None: return 'request_failed', None
    if status in (404, 410): return 'absent', None
    if status >= 400: return 'http_error_%d' % status, None
    if status >= 300: return 'redirect_not_followed', None
    body = result.get('body', {})
    if body.get('semantic', {}).get('kind') == 'html': return 'html_fallback', None
    if result.get('same_body_as_unknown_path'): return 'soft_404_fallback_body', None
    if not body.get('complete'): return 'incomplete_body', None
    if want == 'json':
        text = json_text_from_bytes(data or b'')  # fetch().json() reads UTF-8 whatever the charset says
        if not text.strip(BOM + ' \t\r\n'): return 'empty', None
        try:
            return 'parsed', parse_json_text(text)
        except (ValueError, RecursionError):
            return 'invalid_json', None
    text = decode_text(data or b'', result.get('headers', {}).get('content-type', ''))[0]
    if not text.strip(BOM + ' \t\r\n'): return 'empty', None
    return 'parsed', text

def compare_digest(row, data, advertised):
    """Compare sha256 of the decoded complete artifact body with the advertised digest."""
    if row.get('status') != 200:
        return {'state': 'artifact_not_retrieved', 'status': row.get('status')}
    if not row.get('body', {}).get('complete'):
        return {'state': 'unknown_incomplete_body'}
    actual = 'sha256:' + hashlib.sha256(data or b'').hexdigest()
    out = {'actual_digest': actual, 'digest_scope': 'sha256 of the Content-Encoding-decoded complete body', 'artifact_body_kind': row['body'].get('semantic', {}).get('kind')}
    if not _is_str(advertised) or not SHA256_DIGEST.fullmatch(advertised.strip()):
        out['state'] = 'unknown_advertised_digest_invalid'
    else:
        out['state'] = 'match' if advertised.strip().lower() == actual else 'mismatch'
    return out

def _public(findings):
    return [{key: val for key, val in item.items() if key != 'level'} for item in findings]

def shape_checks(by_id, raw, origin):
    """Structural reports for known resources; unparsed documents stay unknown."""
    out = {}
    def run(ident, want, check):
        result = by_id.get(ident)
        entry = {'url': result.get('final_url') if result else None}
        try:
            state, doc = document_state(result, raw.get(ident), want)
            entry['state'] = state
            if state == 'parsed':
                checked = check(doc, result['final_url'])
                entry.update({key: val for key, val in checked.items() if key not in ('findings', 'links')})
                entry['findings'] = _public(checked['findings'])
                entry['problem_count'] = sum(item['result'] == 'problem' for item in checked['findings'])
            else:
                entry['findings'] = []
                entry['note'] = 'Not evaluated; every field stays unknown (not false).'
        except Exception as exc:  # a hostile document must not stop the run
            entry.update(state='check_error', findings=[], error='%s: %s' % (type(exc).__name__, str(exc)[:200]), note='Check failed; every field stays unknown (not false).')
        out[ident] = entry
        return entry
    run('api_catalog', 'json', lambda doc, url: check_api_catalog(doc, url))
    run('skill_index', 'json', lambda doc, url: check_skill_index(doc))
    run('mcp_card', 'json', lambda doc, url: check_mcp_card(doc, url))
    run('ard', 'json', lambda doc, url: check_ard(doc))
    run('ard_json', 'json', lambda doc, url: check_ard_manifest(doc))
    oauth = run('oauth_authorization_metadata', 'json', lambda doc, url: check_oauth_as(doc, origin))
    oidc = run('openid_configuration', 'json', lambda doc, url: check_oauth_as(doc, origin))
    run('oauth_resource_metadata', 'json', lambda doc, url: check_prm(doc, origin, [oauth.get('issuer'), oidc.get('issuer')]))
    run('auth_document', 'text', lambda doc, url: check_auth_md(doc))
    run('llms', 'text', lambda doc, url: check_llms_txt(doc))
    run('a2a_agent_card', 'json', lambda doc, url: check_agent_card(doc))
    run('web_bot_auth_directory', 'json', lambda doc, url: check_key_set(doc, 'warn'))
    run('jwks', 'json', lambda doc, url: check_key_set(doc, 'info'))
    run('openapi', 'json', lambda doc, url: check_openapi(doc))
    return out

def soft_404_probe(probe, origin, http):
    """Two random nonexistent .json paths: one at the root, one under /.well-known/."""
    token = secrets.token_hex(6)
    probes = []
    for ident, path in (('soft_404_root', '/agent-ready-geo-probe-%s.json' % token), ('soft_404_well_known', '/.well-known/agent-ready-geo-probe-%s.json' % token)):
        row = probe.fetch(ident, origin + path, 'json', scope='soft_404_probe')
        http.append(row)
        status, kind = row['status'], row.get('body', {}).get('semantic', {}).get('kind')
        probes.append({'id': ident, 'path': path, 'status': status, 'content_type': row['headers'].get('content-type'), 'body_kind': kind, 'answers_200': None if status is None else status == 200, 'html_fallback': None if status is None else (status == 200 and kind == 'html'), 'sha256': row.get('body', {}).get('sha256')})
    decided = [item for item in probes if item['status'] is not None]
    answers_200 = any(item['answers_200'] for item in decided) if decided else None
    return {
        'probes': probes,
        'unknown_paths_answer_200': answers_200,
        'html_fallback_for_unknown_json': any(item['html_fallback'] for item in decided) if decided else None,
        'implication': 'Unknown paths answer 200: judge every 200 in this report by its body (kind, parse state, fallback match), never by status.' if answers_200 else 'Unknown paths do not answer 200; every 200 is still judged by its body.' if decided else 'Unknown: the soft-404 probes were not collected.',
    }

def mark_soft_404_matches(http, soft):
    """Flag 200 responses whose body equals an unknown-path fallback body."""
    hashes = {item['sha256'] for item in soft['probes'] if item['answers_200'] and item['sha256']}
    matches = []
    for row in http:
        if not hashes or row['scope'] == 'soft_404_probe' or row['id'].startswith('homepage_') or row['status'] != 200: continue
        if row.get('body', {}).get('sha256') in hashes:
            row['same_body_as_unknown_path'] = True
            matches.append(row['id'])
            # HTML fallbacks keep html_response_instead_of_requested_representation (v1.0
            # summary.html_fallbacks); other bodies equal to the fallback are relabelled.
            if row['expected_representation'] in ('json', 'xml', 'text', 'markdown') and row['observation'] != 'html_response_instead_of_requested_representation':
                row['observation'] = 'soft_404_fallback_body'
    return matches

def skill_artifacts(probe, by_id, shapes, origin, http):
    """GET each same-origin artifact in the agent-skills index (bounded) and compare digests."""
    index = by_id.get('skill_index') or {}
    skills = (shapes.get('skill_index') or {}).get('skills') or []
    records, fetched = [], 0
    for skill in skills:
        record = {'name': skill.get('name'), 'type': skill.get('type'), 'url': skill.get('url'), 'advertised_digest': skill.get('digest')}
        resolved = _join(index.get('final_url', origin + '/'), skill['url']) if _is_str(skill.get('url')) else None
        if not resolved:
            record['state'] = 'no_usable_url'
        elif not same_origin(resolved, origin):
            record.update(resolved_url=resolved, state='not_fetched_cross_origin')
        elif fetched >= SKILL_ARTIFACT_LIMIT:
            record.update(resolved_url=resolved, state='not_fetched_limit_%d' % SKILL_ARTIFACT_LIMIT)
        else:
            fetched += 1
            ident = 'skill_artifact_%d' % fetched
            row = probe.fetch(ident, resolved, 'markdown' if skill.get('type') == 'skill-md' else 'unknown', scope='skill_artifact')
            http.append(row)
            record.update(resolved_url=row['requested_url'], result_id=ident, status=row['status'])
            record.update(compare_digest(row, probe.raw_decoded.get(ident), skill.get('digest')))
        records.append(record)
    states = [item['state'] for item in records]
    return {'index_state': (shapes.get('skill_index') or {}).get('state'), 'artifacts': records, 'fetched': fetched, 'matches': states.count('match'), 'mismatches': states.count('mismatch'), 'other': len(states) - states.count('match') - states.count('mismatch')}

BLOCKING_EDGE_CODES = frozenset(('1010', '1020'))
RATE_LIMIT_EDGE_CODES = frozenset(('1015',))

def access_state(row):
    """ok | blocked | rate_limited_or_unavailable | other | unknown for one response."""
    status = row.get('status')
    if status is None: return 'unknown'
    block = row.get('edge_block') or {}
    code = block.get('error_code')
    if code in RATE_LIMIT_EDGE_CODES or status in (429, 503): return 'rate_limited_or_unavailable'
    if status in (401, 403) or code in BLOCKING_EDGE_CODES or block.get('challenge'): return 'blocked'
    if 200 <= status < 300: return 'ok'
    return 'other'

def _difference_verdict(reference, row):
    """Compare a probe-UA response (reference) with the default-client response to the same URL."""
    ref, default = access_state(reference), access_state(row)
    if 'unknown' in (ref, default): return 'unknown'
    if 'rate_limited_or_unavailable' in (ref, default): return 'rate_limited_or_unavailable'
    if ref == 'ok' and default == 'blocked': return 'default_python_client_blocked'
    if ref == 'blocked' and default == 'ok': return 'probe_client_blocked'
    if ref == 'blocked' and default == 'blocked': return 'both_clients_blocked'
    return 'same_status' if reference['status'] == row['status'] else 'status_differs'

def _client_facts(row, user_agent, data):
    return {'user_agent': user_agent, 'status': row['status'], 'server': row['headers'].get('server'), 'observation': row.get('observation'), 'first_120_body_bytes': (data or b'')[:120].decode('utf-8', errors='replace'), 'edge_block': row.get('edge_block'), 'error': row['error']}

def client_difference(probe, by_id, origin, target_url):
    """Three URLs, each fetched with Python's default client (no User-Agent override) and then,
    immediately, with the probe UA; each pair is compared, so rate limiting late in a burst
    is not mistaken for User-Agent blocking."""
    llms = by_id.get('llms') or {}
    llms_present = llms.get('status') == 200 and llms.get('body', {}).get('semantic', {}).get('kind') not in ('html', 'empty')
    plan = [('homepage', target_url, 'html'), ('robots', origin + '/robots.txt', 'text'),
            ('llms', origin + '/llms.txt', 'text') if llms_present else ('sitemap', origin + '/sitemap.xml', 'xml')]
    rows, comparisons = [], []
    for name, url, expected in plan:
        default = probe.fetch('client_default_' + name, url, expected, scope='client_difference', client='python_default')
        paired = probe.fetch('client_probe_' + name, url, expected, scope='client_difference', client='probe')
        rows += [default, paired]
        comparisons.append({
            'resource': name, 'url': default['requested_url'],
            'probe_client': _client_facts(paired, probe.user_agent, probe.raw_decoded.get(paired['id'])),
            'default_python_client': _client_facts(default, PYTHON_DEFAULT_USER_AGENT, probe.raw_decoded.get(default['id'])),
            'verdict': _difference_verdict(paired, default),
        })
    verdicts = [item['verdict'] for item in comparisons]
    if 'default_python_client_blocked' in verdicts: overall = 'default_python_client_blocked'
    elif 'probe_client_blocked' in verdicts: overall = 'probe_client_blocked_default_allowed'
    elif 'rate_limited_or_unavailable' in verdicts: overall = 'rate_limited_or_unavailable'
    elif all(v == 'same_status' for v in verdicts): overall = 'no_difference_observed'
    elif all(v in ('same_status', 'both_clients_blocked') for v in verdicts): overall = 'both_clients_blocked'
    elif all(v in ('same_status', 'unknown') for v in verdicts): overall = 'unknown'
    else: overall = 'status_differs'
    codes = sorted({item['default_python_client']['edge_block']['error_code'] for item in comparisons if (item['default_python_client'].get('edge_block') or {}).get('error_code')})
    return {
        'enabled': True, 'verdict': overall, 'default_client_edge_error_codes': codes, 'comparisons': comparisons,
        'note': 'Each URL is fetched with Python urllib and no User-Agent override (a stand-in for library-default agent clients), then immediately with the probe UA. Only 401/403, edge codes 1010/1020 or a challenge count as blocking; 429, 503 and 1015 are reported as rate_limited_or_unavailable. A block the probe UA does not get is a finding for the site owner to confirm as intended or fix (T31); it does not show how browsers or named AI crawlers are treated.',
    }, rows

SCHEMA_CHANGES = [
    {'field': 'schema_version', 'from_1_0': '1.0', 'to_2_0': '2.0'},
    {'field': 'tool', 'from_1_0': 'ar100-readonly-preflight', 'to_2_0': TOOL},
    {'field': 'collection.user_agent', 'from_1_0': 'text: default Python-urllib UA, not overridden', 'to_2_0': 'object {value, source}; the probe UA is sent on every request except results.client_difference'},
    {'field': 'results.http[].client, user_agent', 'from_1_0': 'absent', 'to_2_0': 'client (probe | python_default) and the User-Agent value sent'},
    {'field': 'results.http[].error', 'from_1_0': '{kind, message}', 'to_2_0': '{kind, side, message}; side: local_input | local_encoding | local_policy | remote | unknown'},
    {'field': 'results.http[].requested_url, input_url', 'from_1_0': 'requested_url only', 'to_2_0': 'requested_url is the normalised ASCII URL; input_url keeps the original when normalisation changed it'},
    {'field': 'results.http[].redirects[].location_header', 'from_1_0': 'absent', 'to_2_0': 'raw Location value with UTF-8 recovered'},
    {'field': 'collection.redirect_scope, redirect_scope_hosts', 'from_1_0': 'absent; redirects followed to any HTTP(S) host', 'to_2_0': 'default site (request host plus its www/apex twin); an out-of-scope Location is recorded with followed=false and error kind redirect_outside_scope, and no request is sent to it'},
    {'field': 'results.http[].headers', 'from_1_0': '21 selected headers', 'to_2_0': 'adds content-signal, x-markdown-tokens, retry-after, cf-mitigated, x-cache'},
    {'field': 'results.http[].edge_block, retry_after_seconds, waited_for_retry_after_ms, same_body_as_unknown_path, body.raw_file', 'from_1_0': 'absent', 'to_2_0': 'present when applicable'},
    {'field': 'results.http[].observation', 'from_1_0': '9 values', 'to_2_0': 'adds not_requested_local_error, redirect_rejected, not_collected, edge_block_response, redirect_not_followed, soft_404_fallback_body'},
    {'field': 'results.http[] origin_root resources', 'from_1_0': '16', 'to_2_0': 'adds ard_json, a2a_agent_card, web_bot_auth_directory, openid_configuration, jwks'},
    {'field': 'results.http[].scope', 'from_1_0': 'target_document | origin_root | application_mount | dns_resolver', 'to_2_0': 'adds soft_404_probe, skill_artifact'},
    {'field': 'results.client_difference', 'from_1_0': 'absent', 'to_2_0': 'default-client rows (client python_default)'},
    {'field': 'summary.robots, negotiation_verdicts, soft_404, soft_404_fallback_matches, shape_checks, skill_artifacts, client_difference, retry_after_events, error_sides, requests_sent', 'from_1_0': 'absent', 'to_2_0': 'added'},
    {'field': 'summary.collection_errors', 'from_1_0': 'ids with any error', 'to_2_0': 'unchanged; summary.error_sides groups the same ids by side'},
    {'field': 'target.input_normalisation', 'from_1_0': 'absent', 'to_2_0': 'normalisation notes for the target URL'},
    {'field': 'results.http[id=ai_home].expected_representation', 'from_1_0': 'html', 'to_2_0': 'document (HTML, Markdown or I-Lang accepted)'},
    {'field': 'summary.robots.effective_rules_by_bot, bots_dropping_star_disallows, bots_without_applicable_content_signal', 'from_1_0': 'absent', 'to_2_0': 'RFC 9309 effective group per AI bot, dropped * Disallow paths, applicable Content-Signal'},
    {'field': 'summary.shape_checks.ard_json', 'from_1_0': 'absent', 'to_2_0': 'ARD v0.91 manifest checks (entries, MUST terms, url/data); distinct from the ai-catalog.json shape'},
    {'field': 'collection.socket_timeout_seconds, body_collection_deadline_seconds', 'from_1_0': 'per-socket timeout and body-read deadline', 'to_2_0': 'replaced by fetch_deadline_seconds: one wall-clock deadline per fetch across every hop, enforced by a socket watchdog'},
    {'field': 'collection.proxy, redirect_bodies_read, request_budget_counts, retry_after_pause_allowance, max_consecutive_429_or_503_per_host', 'from_1_0': 'absent', 'to_2_0': 'added (proxy records the proxy host only, never credentials)'},
    {'field': 'summary.requests_sent', 'from_1_0': 'absent', 'to_2_0': 'every wire request, including each redirect hop and DoH query'},
    {'field': 'results.http[].redirects[]', 'from_1_0': 'followed by urllib (308 not followed before Python 3.11)', 'to_2_0': 'followed by the probe on every Python version; 3xx bodies are never read; each hop has followed true/false'},
    {'field': 'results.http[].error.kind', 'from_1_0': 'exception class names; body_deadline', 'to_2_0': 'fetch_deadline (replaces body_deadline), body_read_error (partial body kept), redirect_rejected/redirect_outside_scope/redirect_limit_or_loop (with the 3xx status), tls_certificate_unverified (side possibly_local)'},
    {'field': 'results.http[].body.content_decode_note, charset_rejected', 'from_1_0': 'absent', 'to_2_0': 'gzip trailing bytes ignored; declared charset that is not a real text codec (UTF-8 used instead)'},
    {'field': 'summary.retry_after_events[], halted_hosts', 'from_1_0': 'absent', 'to_2_0': 'every 429/503 with its consecutive count and action; a host is halted after 2 consecutive 429/503 or when its pause allowance is spent'},
    {'field': 'summary.negotiation_verdicts.html_served_without_accept_header', 'from_1_0': 'absent', 'to_2_0': 'the homepage without an Accept header must be HTML; verdicts use the Content-Type header and stay unknown after read or decode errors'},
    {'field': 'summary.client_difference', 'from_1_0': 'absent', 'to_2_0': 'each default-client request is paired with an immediate probe-UA request (results.client_difference ids client_default_* and client_probe_*); 429/503/1015 are rate_limited_or_unavailable, not blocking'},
    {'field': 'summary.robots grouping', 'from_1_0': 'absent', 'to_2_0': "Google reference parser: only Allow/Disallow end a user-agent run, the leading product token is matched, lines end only at CR/LF, an empty Allow is not a rule, '*', '/*' and '/*$' disallow everything"},
    {'field': 'target.metadata_origin', 'from_1_0': 'scheme://netloc of the final homepage URL', 'to_2_0': 'canonical origin: default port dropped, trailing host dot removed; URLs with an explicit default port are normalised without it; IDNA deviation characters are rejected'},
    {'field': 'body.semantic', 'from_1_0': 'HTML by leading markers; BOM JSON invalid', 'to_2_0': 'also XHTML prolog and tag-led HTML; one leading BOM tolerated for JSON (bom: true)'},
]

def stable_variant(rows, accept):
    selected = [r for r in rows if r['accept'] == accept]
    complete = all(r.get('body', {}).get('complete') for r in selected)
    hashes = [r.get('body', {}).get('sha256') for r in selected]
    return {'requests': len(selected), 'all_200': all(r['status'] == 200 for r in selected), 'all_bodies_complete': complete, 'stable_hashes': len(set(hashes)) == 1 if complete and selected else None, 'sha256_sequence': hashes, 'semantic_kinds': [r.get('body', {}).get('semantic', {}).get('kind') for r in selected]}

def robots_summary(by_id, raw, homepage):
    row = by_id.get('robots')
    headers = {'robots_response': (row or {}).get('headers', {}).get('content-signal'), 'homepage_response': homepage.get('headers', {}).get('content-signal')}
    state, text = document_state(row, raw.get('robots'), 'text')
    if state != 'parsed':
        return {'state': state, 'content_signal_headers': {k: v for k, v in headers.items() if v}, 'note': 'robots.txt body not analysed; rule facts stay unknown (not false).'}
    return dict({'state': 'parsed', 'url': row['final_url']}, **analyze_robots(text, headers))

def _guarded(label, compute, fallback):
    """Run one summary step; a failure becomes a recorded check_error instead of a crash."""
    try:
        return compute()
    except Exception as exc:
        failed = dict(fallback)
        failed.update(state='check_error', error='%s failed: %s: %s' % (label, type(exc).__name__, str(exc)[:200]))
        return failed

def collect(target, probe, skip_dns=False, app_base=None, skip_client_difference=False, target_notes=None):
    probe.site_hosts = site_hosts(urlsplit(target).hostname, probe.redirect_scope) or set()
    initial = probe.fetch('homepage_default', target, 'html')
    actual_home = initial['final_url'] if initial['status'] and initial['status'] < 400 else initial['requested_url']
    origin = canonical_origin(actual_home)
    host = urlsplit(actual_home).hostname
    http = [initial]
    order = []
    for index, accept in enumerate(['text/html', 'text/markdown', 'text/html', 'text/markdown', 'text/html', 'text/markdown'], 1):
        result = probe.fetch('homepage_order_' + str(index), actual_home, 'markdown' if accept == 'text/markdown' else 'html', accept)
        order.append(result)
        http.append(result)
    q0, q0_rows = [], []
    for index, accept in enumerate(['text/markdown;q=0', 'text/html,text/markdown;q=0'], 1):
        result = probe.fetch('homepage_q0_' + str(index), actual_home, 'html', accept)
        http.append(result)
        q0_rows.append(result)
        q0.append({'accept': accept, 'status': result['status'], 'declared_mime': (result['headers'].get('content-type') or '').split(';', 1)[0].strip().lower() or None, 'semantic_kind': result.get('body', {}).get('semantic', {}).get('kind'), 'sha256': result.get('body', {}).get('sha256')})
    for ident, route, expected in RESOURCES:
        http.append(probe.fetch(ident, origin + route, expected, scope='origin_root'))
    mount = {'state': 'unknown_not_supplied', 'inferred_from_target_path': False, 'ownership': 'not_established_by_http_probe'}
    if app_base is not None:
        try:
            mount_path = validated_app_base(app_base, origin)
            mount = {'state': 'explicitly_supplied', 'requested': app_base, 'url': origin + mount_path, 'path': mount_path, 'inferred_from_target_path': False, 'ownership': 'not_established_by_http_probe'}
            http.append(probe.fetch('app_home', origin + mount_path, 'document', scope='application_mount'))
            for ident, route, expected in RESOURCES:
                if route.startswith('/.well-known/') or route == '/robots.txt': continue
                http.append(probe.fetch('app_' + ident, origin + mount_path + route.lstrip('/'), expected, scope='application_mount'))
        except ValueError as exc:
            mount = {'state': 'not_probed_origin_validation_failed', 'requested': app_base, 'reason': str(exc), 'inferred_from_target_path': False, 'ownership': 'not_established_by_http_probe'}
    soft = soft_404_probe(probe, origin, http)
    fallback_matches = mark_soft_404_matches(http, soft)
    by_id = {r['id']: r for r in http}
    shapes = _guarded('shape checks', lambda: shape_checks(by_id, probe.raw_decoded, origin), {})
    artifacts = _guarded('skill artifacts', lambda: skill_artifacts(probe, by_id, shapes, origin, http), {'artifacts': [], 'fetched': 0, 'matches': 0, 'mismatches': 0, 'other': 0})
    fallback_matches = sorted(set(fallback_matches) | set(mark_soft_404_matches(http, soft)))
    by_id = {r['id']: r for r in http}
    difference_rows = []
    if skip_client_difference:
        difference = {'enabled': False, 'verdict': 'not_collected', 'reason': 'Explicit --skip-client-difference'}
    else:
        def run_difference():
            summary, rows = client_difference(probe, by_id, origin, initial['requested_url'])
            difference_rows.extend(rows)
            return summary
        difference = _guarded('client difference', run_difference, {'enabled': True, 'verdict': 'unknown'})
    dns = probe.dns(host, skip_dns)
    canonical = initial.get('body', {}).get('semantic', {}).get('canonical', [])
    all_rows = http + difference_rows
    sides = {}
    for row in all_rows:
        if row['error']: sides.setdefault(row['error'].get('side', 'unknown'), []).append(row['id'])
    summary = {
        'canonical_navigation': {'requested': target, 'final': initial['final_url'], 'redirects': initial['redirects'], 'declared_canonical': canonical, 'declared_canonical_resolved': [_join(actual_home, x) for x in canonical]},
        'homepage_status_with_probe_user_agent': initial['status'],
        'homepage_request_order': [r['accept'] for r in order],
        'html_variant': stable_variant(order, 'text/html'),
        'markdown_variant': stable_variant(order, 'text/markdown'),
        'markdown_q0_observations': q0,
        'negotiation_verdicts': _guarded('negotiation verdicts', lambda: negotiation_verdicts(order, q0_rows, initial), {'summary': 'markdown_negotiation_unknown'}),
        'robots': _guarded('robots analysis', lambda: robots_summary(by_id, probe.raw_decoded, initial), {}),
        'soft_404': soft,
        'soft_404_fallback_matches': fallback_matches,
        'shape_checks': shapes,
        'skill_artifacts': artifacts,
        'client_difference': difference,
        'http_observation_counts': {state: sum(r['observation'] == state for r in http) for state in sorted({r['observation'] for r in http})},
        'metadata_absences_not_assigned_mandatory_failure': [r['id'] for r in http if r['status'] in (404, 410)],
        'html_fallbacks': [r['id'] for r in http if r['observation'] == 'html_response_instead_of_requested_representation'],
        'collection_errors': [r['id'] for r in all_rows if r['error']],
        'error_sides': sides,
        'retry_after_events': probe.retry_after_events,
        'halted_hosts': dict(probe.halted),
        'requests_sent': probe.requests_sent,
        'application_mount': mount,
        'declared_links_are_observed_only': True,
    }
    collection = {
        'method': 'GET only',
        'user_agent': {'value': probe.user_agent, 'source': getattr(probe, 'user_agent_source', 'built_in_default')},
        'client_difference_user_agent': None if skip_client_difference else PYTHON_DEFAULT_USER_AGENT + ' (Python default, not overridden)',
        'tls_verification': 'Default verified TLS',
        'proxy': proxy_summary(target),
        'fetch_deadline_seconds': probe.timeout,
        'fetch_deadline_scope': 'one wall-clock deadline per fetch across every redirect hop, connection and body read; a watchdog shuts the socket down at the deadline',
        'max_wire_bytes_per_response': probe.max_body,
        'max_decoded_bytes_per_response': probe.max_body,
        'snippet_characters': probe.snippet_chars,
        'redirect_limit': MAX_REDIRECTS,
        'redirect_bodies_read': False,
        'redirect_scope': probe.redirect_scope,
        'redirect_scope_hosts': sorted(probe.site_hosts) if probe.redirect_scope != 'any' else None,
        'request_budget': probe.request_budget,
        'request_budget_counts': 'every wire request, including each redirect hop and DoH query',
        'max_retry_after_seconds': probe.max_retry_after,
        'retry_after_pause_allowance': 'Retry-After pauses total at most max_retry_after_seconds per host; a longer wait halts the host',
        'max_consecutive_429_or_503_per_host': MAX_CONSECUTIVE_UNAVAILABLE,
        'skill_artifact_limit': SKILL_ARTIFACT_LIMIT,
        'cookies_authentication_or_environment_inspection': False,
        'declared_links_followed': False,
        'raw_bodies_saved': False,
    }
    limitations = [
        'Bounds: at most %d HTTP requests per run (each redirect hop and DoH query counts); each fetch (connect, TLS handshake, headers, body, all redirect hops) ends by its %ss deadline, enforced by a watchdog that shuts the socket down; Retry-After pauses total at most %ss per host; a host is halted after %d consecutive 429/503. OS name resolution (getaddrinfo) runs before a socket exists and is bounded only by the resolver.' % (probe.request_budget, probe.timeout, probe.max_retry_after, MAX_CONSECUTIVE_UNAVAILABLE),
        'Root resource probes remain origin_root. Explicit --app-base adds separate application_mount content probes; it never relocates .well-known or robots, establishes ownership, or substitutes for origin-root support.',
        'No application mount is inferred from an arbitrary target/article URL. Declared links are recorded, not crawled; alternate routes outside explicit candidates can be missed.',
        'No POST, MCP call, OAuth execution, authentication, mutation, device operation, scanner call or score calculation.',
        'Client difference compares the Python default client with an immediate probe-UA request to the same URL; browsers and named AI crawlers are not impersonated.',
        'Soft-404 detection uses two random paths; rewrite rules for other paths can differ.',
        'Shape checks are structural reports on complete bodies; missing documents leave every field unknown. Skill digests are compared only for same-origin artifacts (at most %d).' % SKILL_ARTIFACT_LIMIT,
        'robots.txt is grouped as Google\'s reference parser does (only Allow/Disallow end a user-agent run; the leading product token is matched); other crawlers may parse differently.',
        'Hashes may differ because of dynamic content or edge script injection; a difference is evidence for review, not automatic cache poisoning.',
        'Body limits can prevent complete JSON/XML parsing and whole-document parity conclusions.',
        'AD is the queried resolver assertion, not an independently validated DNSSEC chain; Status or AD absence remains unknown.',
    ]
    return {'schema_version': VERSION, 'tool': TOOL, 'schema_changes': SCHEMA_CHANGES, 'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'target': {'requested_url': target, 'input_normalisation': target_notes, 'homepage_final_url': initial['final_url'], 'metadata_origin': origin, 'dns_hostname': host, 'application_mount': mount}, 'collection': collection, 'summary': summary, 'results': {'http': http, 'client_difference': difference_rows, 'dns': dns}, 'score_note': SCORE_NOTE, 'limitations': limitations}

RAW_EXTENSIONS = {'html': '.html', 'json': '.json', 'invalid_json': '.json', 'json_incomplete': '.json', 'markdown': '.md', 'ilang': '.ilang', 'xml': '.xml', 'invalid_xml': '.xml', 'xml_incomplete': '.xml', 'text': '.txt', 'empty': '.txt'}

def _finite_json(value):
    if isinstance(value, float) and not math.isfinite(value): return repr(value)
    if isinstance(value, dict): return {key: _finite_json(item) for key, item in value.items()}
    if isinstance(value, list): return [_finite_json(item) for item in value]
    return value

def dump_json_text(obj, ensure_ascii=False):
    """Strict JSON text: NaN/Infinity never appear (they are written as strings if present)."""
    try:
        return json.dumps(obj, ensure_ascii=ensure_ascii, indent=2, allow_nan=False)
    except ValueError:
        return json.dumps(_finite_json(obj), ensure_ascii=ensure_ascii, indent=2, allow_nan=False)

def write_json_file(path, obj, overwrite=False):
    """Atomic UTF-8 JSON write. A lone surrogate from hostile input becomes a valid \\udXXX
    escape instead of a crash, and a failed write never leaves a truncated file behind."""
    path = Path(path)
    data = (dump_json_text(obj) + '\n').encode('utf-8', 'backslashreplace')
    if path.exists() and not overwrite:
        raise FileExistsError('%s already exists' % path)
    handle, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
        os.replace(temporary, str(path))
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

def configure_streams():
    """Never die on a console or pipe that cannot encode a character (e.g. cp1252, cp936)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure is not None:
            try:
                reconfigure(errors='backslashreplace')
            except (ValueError, OSError):
                pass

def save_raw(report, probe, directory, overwrite=False):
    """Write each decoded body (never headers or request data) as DIR/<result id>.<ext>."""
    directory.mkdir(exist_ok=True)
    rows = report['results']['http'] + report['results']['client_difference'] + [item['http'] for item in report['results']['dns'] if isinstance(item.get('http'), dict)]
    manifest = {}
    for row in rows:
        data = probe.raw_decoded.get(row['id'])
        if data is None or 'body' not in row: continue
        kind = row['body'].get('semantic', {}).get('kind')
        url_ext = Path(unquote(urlsplit(row['final_url']).path)).suffix.lower()
        ext = url_ext if kind in ('text', 'markdown', 'ilang', 'empty') and url_ext in ('.txt', '.md', '.ilang') else RAW_EXTENSIONS.get(kind, '.bin')
        name = re.sub(r'[^A-Za-z0-9._-]', '_', row['id']) + ext
        with (directory / name).open('wb' if overwrite else 'xb') as stream:
            stream.write(data)
        row['body']['raw_file'] = name
        manifest[row['id']] = {'file': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'complete': row['body'].get('complete'), 'url': row['final_url'], 'status': row['status'], 'content_type': row['headers'].get('content-type')}
    write_json_file(directory / '_manifest.json', {'tool': TOOL, 'schema_version': VERSION, 'target': report['target']['requested_url'], 'timestamp_utc': report['timestamp_utc'], 'bodies': manifest}, overwrite)
    report['collection']['raw_bodies_saved'] = True
    return len(manifest)

def _local_error_exit(kind, message):
    print(json.dumps({'error': {'kind': kind, 'side': 'local_input' if kind == 'input_rejected' else 'local_encoding', 'message': message}, 'requests_sent': 0}, ensure_ascii=True), file=sys.stderr)
    return 2

def main(argv=None):
    configure_streams()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target_url', help='Public HTTP(S) homepage URL without userinfo')
    parser.add_argument('--output', type=Path, required=True, help='New JSON evidence path')
    parser.add_argument('--overwrite', action='store_true', help='Explicitly allow replacing the chosen evidence file (and raw files)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Per-fetch wall-clock deadline across all redirect hops, seconds (0.1-60)')
    parser.add_argument('--max-body-bytes', type=int, default=262144, help='Separate wire/decoded retained body caps (1024-2097152)')
    parser.add_argument('--snippet-chars', type=int, default=1200, help='Maximum body snippet characters per response (0-8192)')
    parser.add_argument('--skip-dns', action='store_true', help='Explicitly omit public DoH queries; omission is recorded')
    parser.add_argument('--app-base', help='Explicit application mount, e.g. /docs/ or same-origin full URL; root probes remain separate')
    parser.add_argument('--user-agent', help='User-Agent for every probe request (default: %s)' % DEFAULT_USER_AGENT)
    parser.add_argument('--skip-client-difference', action='store_true', help='Do not repeat requests with the Python default client')
    parser.add_argument('--save-raw', type=Path, metavar='DIR', help='Write each decoded body to DIR (off by default; no headers or request data)')
    parser.add_argument('--max-retry-after', type=int, default=30, help='Total Retry-After pause allowed per host, seconds (0-120); a longer wait halts that host')
    parser.add_argument('--redirect-scope', choices=('host', 'site', 'any'), default='site', help='Hosts a redirect may reach: the request host only, host plus its www/apex twin (default), or any host')
    args = parser.parse_args(argv)
    try:
        target, target_notes = normalise_url(args.target_url)
    except InputRejected as exc:
        return _local_error_exit('input_rejected', str(exc))
    except LocalEncodingError as exc:
        return _local_error_exit('local_encoding_error', str(exc))
    if args.app_base is not None:
        try: validated_app_base(args.app_base, origin_of(target))
        except ValueError as exc: return _local_error_exit('input_rejected', 'App base: ' + str(exc))
    if args.user_agent is not None and (not args.user_agent.strip() or any(ord(ch) < 32 or ord(ch) > 126 for ch in args.user_agent)):
        parser.error('--user-agent must be non-empty printable ASCII')
    if not 0.1 <= args.timeout <= 60: parser.error('--timeout must be between 0.1 and 60')
    if not 1024 <= args.max_body_bytes <= 2097152: parser.error('--max-body-bytes must be between 1024 and 2097152')
    if not 0 <= args.snippet_chars <= 8192: parser.error('--snippet-chars must be between 0 and 8192')
    if not 0 <= args.max_retry_after <= 120: parser.error('--max-retry-after must be between 0 and 120')
    if args.output.exists() and not args.overwrite: parser.error('Output already exists; choose a new path or explicitly pass --overwrite')
    if not args.output.parent.is_dir(): parser.error('Output parent directory does not exist')
    if args.save_raw is not None:
        if not args.save_raw.parent.is_dir(): parser.error('--save-raw parent directory does not exist')
        if args.save_raw.exists() and (not args.save_raw.is_dir() or (any(args.save_raw.iterdir()) and not args.overwrite)):
            parser.error('--save-raw directory exists and is not empty; choose a new directory or pass --overwrite')
    probe = Probe(args.timeout, args.max_body_bytes, args.snippet_chars, args.user_agent or DEFAULT_USER_AGENT, args.max_retry_after, redirect_scope=args.redirect_scope)
    probe.user_agent_source = '--user-agent' if args.user_agent else 'built_in_default'
    report = collect(target, probe, args.skip_dns, args.app_base, args.skip_client_difference, target_notes)
    saved = None
    try:
        if args.save_raw is not None: saved = save_raw(report, probe, args.save_raw, args.overwrite)
        write_json_file(args.output, report, args.overwrite)
    except OSError as exc:
        print('Cannot write evidence: ' + str(exc), file=sys.stderr)
        return 2
    summary = report['summary']
    # ensure_ascii keeps stdout valid on any console or pipe encoding.
    print(json.dumps({'output': str(args.output.resolve()), 'homepage_status': summary['homepage_status_with_probe_user_agent'], 'http_requests': len(report['results']['http']) + len(report['results']['client_difference']), 'dns_entries': len(report['results']['dns']), 'client_difference': summary['client_difference'].get('verdict'), 'negotiation': summary['negotiation_verdicts'].get('summary'), 'unknown_paths_answer_200': summary['soft_404']['unknown_paths_answer_200'], 'skill_digests': {'match': summary['skill_artifacts'].get('matches'), 'mismatch': summary['skill_artifacts'].get('mismatches')}, 'raw_bodies_saved': saved, 'requests_sent': summary['requests_sent'], 'observations': summary['http_observation_counts'], 'official_score': None, 'note': 'Evidence collection completed; no official score or mandatory-pass claim.'}, ensure_ascii=True))
    return 0

if __name__ == '__main__':
    sys.exit(main())
