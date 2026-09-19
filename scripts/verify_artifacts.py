#!/usr/bin/env python3
"""agent-ready-geo verify: check agent-discovery artifacts before or after deployment.

Site mode (before deployment):
    verify_artifacts.py --site-root DIR --origin https://example.com
Evidence mode (after a probe run with --save-raw):
    verify_artifacts.py --evidence probe.json --raw-dir DIR
Both modes can run together. Output is a JSON findings list (level error | warn |
info, file, check, message); the exit code is 1 when any finding is an error.
Local files are hashed exactly as they are stored: no newline or encoding changes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import unquote, urljoin, urlsplit

sys.dont_write_bytecode = True  # running the verifier must not write __pycache__ into the skill folder
sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_site as ps  # noqa: E402  (sibling module; shared shape checks)

TOOL = 'agent-ready-geo-verify'
VERSION = '1.0'
EXTENSIONLESS_JSON = ('api-catalog', 'oauth-authorization-server', 'oauth-protected-resource', 'openid-configuration', 'http-message-signatures-directory')
ROUTE_TO_ID = {route: ident for ident, route, _ in ps.RESOURCES}
# Optional resources: a fallback page at these paths means "not published" (info), not a defect.
OPTIONAL_PATHS = frozenset(('/.well-known/ard.json', '/.well-known/openid-configuration', '/.well-known/agent-card.json', '/.well-known/http-message-signatures-directory'))

def _scheme(value):
    """URL scheme, '' for a relative reference, None when the URL does not parse."""
    try:
        parts = urlsplit(value)
        parts.port
    except (ValueError, TypeError, AttributeError):
        return None
    return parts.scheme.lower() if ps.bracket_host_ok(parts.netloc) else None

class Findings:
    def __init__(self):
        self.items = []

    def add(self, level, file, check, message, source):
        self.items.append({'level': level, 'file': file, 'check': check, 'message': message, 'source': source})

    def extend_shape(self, results, file, source, prefix):
        """Map shared shape-check results: problem -> its level hint, ok/info -> info."""
        for item in results:
            level = item['level'] if item['result'] == 'problem' else 'info'
            message = item['detail'] if item['result'] != 'ok' else 'ok: ' + item['detail']
            self.add(level, file, prefix + '.' + item['check'], message, source)

class SiteSource:
    """A local folder that will be published as the site root."""
    kind = 'site'

    def __init__(self, root, origin):
        self.root = Path(root).resolve()
        self.origin = origin

    def label(self, path):
        return path.lstrip('/')

    def _walk(self, rel):
        """Case-exact lookup: Windows and macOS disks ignore case, many servers do not."""
        current, mismatch = self.root, False
        for segment in [s for s in rel.split('/') if s]:
            try:
                names = os.listdir(current)
            except OSError:
                return None, mismatch
            if segment not in names:
                if segment.lower() in {name.lower() for name in names}: mismatch = True
                return None, mismatch
            current = current / segment
        return (current if current.is_file() else None), mismatch

    def get(self, path):
        found, mismatch = self._walk(path.lstrip('/'))
        if found is None:
            return ('case_mismatch' if mismatch else 'absent'), None
        return 'present', found.read_bytes()

    def locate(self, url):
        """(True | False | None, detail) for a URL; None means not decidable locally."""
        if not ps.same_origin(url, self.origin):
            return None, 'cross-origin; not checked locally'
        try:
            path = unquote(urlsplit(url).path or '/', errors='strict')
        except UnicodeDecodeError:
            return False, 'path is not valid percent-encoded UTF-8'
        except ValueError:
            return False, 'not a valid URL'
        segments = path.split('/')
        if any(s in ('.', '..') for s in segments) or '\\' in path or '\x00' in path:
            return False, 'path traversal or backslash in URL path'
        rel = path.lstrip('/')
        if rel == '' or rel.endswith('/'):
            candidates = [rel + 'index.html', rel + 'index.htm']
        elif rel.startswith('.well-known/') or '.' in rel.rsplit('/', 1)[-1]:
            candidates = [rel]
        else:
            candidates = [rel, rel + '.html', rel + '/index.html']
        mismatch = False
        for candidate in candidates:
            found, case = self._walk(candidate)
            mismatch = mismatch or case
            if found is not None:
                return True, 'resolves to ' + candidate
        return False, 'no file for %s (tried %s)%s' % (path, ', '.join(candidates), '; a file differs only by letter case' if mismatch else '')

    def artifact_bytes(self, url):
        ok, detail = self.locate(url)
        if not ok: return None, detail
        rel = detail[len('resolves to '):]
        return (self.root / rel).read_bytes(), detail

class EvidenceSource:
    """A probe report (schema 2.0) plus the directory written by --save-raw."""
    kind = 'evidence'

    def __init__(self, report, raw_dir, origin, findings):
        self.report, self.raw_dir, self.origin = report, Path(raw_dir), origin
        self.rows = list(report.get('results', {}).get('http', [])) + list(report.get('results', {}).get('client_difference', []))
        self.rows += [item['http'] for item in report.get('results', {}).get('dns', []) if isinstance(item.get('http'), dict)]
        self.by_id = {row['id']: row for row in self.rows}
        self.data = {}
        for row in self.rows:
            name = row.get('body', {}).get('raw_file')
            if not name:
                continue
            path = self.raw_dir / name
            if not path.is_file():
                findings.add('error', name, 'evidence.raw_file_present', 'Raw body for %s is missing from the raw directory' % row['id'], self.kind)
                continue
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != row['body'].get('sha256'):
                findings.add('error', name, 'evidence.raw_file_integrity', 'sha256 of the saved body differs from the report for %s' % row['id'], self.kind)
                continue
            self.data[row['id']] = data

    def label(self, path):
        row = self.by_id.get(ROUTE_TO_ID.get(path, ''))
        return (row or {}).get('body', {}).get('raw_file') or path

    def get(self, path):
        row = self.by_id.get(ROUTE_TO_ID.get(path, ''))
        if row is None:
            return 'not_collected', None
        if row.get('body') and row['id'] not in self.data and row.get('status') == 200:
            return 'raw_body_not_saved', None
        state, _ = ps.document_state(row, self.data.get(row['id']), 'text')
        if state == 'parsed': return 'present', self.data[row['id']]
        if state in ('html_fallback', 'soft_404_fallback_body') and path in OPTIONAL_PATHS:
            return 'absent_fallback', None
        return state, None

    def _row_for(self, url):
        try:
            wanted = ps.normalise_url(url)[0]
        except ValueError:
            return None
        for row in self.rows:
            if wanted in (row.get('requested_url'), row.get('final_url')) and row.get('scope') != 'client_difference':
                return row
        return None

    def locate(self, url):
        if not ps.same_origin(url, self.origin):
            return None, 'cross-origin; not checked'
        row = self._row_for(url)
        if row is None: return None, 'not collected by the probe; verify it separately'
        status, kind = row.get('status'), row.get('body', {}).get('semantic', {}).get('kind')
        if status == 200 and not row.get('same_body_as_unknown_path'):
            return True, 'probe saw %s (%s)' % (status, kind)
        return False, 'probe saw status %s, body kind %s' % (status, kind)

    def artifact_bytes(self, url):
        row = self._row_for(url)
        if row is None: return None, 'artifact not collected by the probe'
        if row.get('status') != 200: return None, 'probe saw status %s' % row.get('status')
        if not row.get('body', {}).get('complete'): return None, 'probe retained only a prefix of the artifact'
        if row['id'] not in self.data: return None, 'raw body not saved for ' + row['id']
        return self.data[row['id']], 'probe body ' + row['body'].get('raw_file', row['id'])

UNAVAILABLE_LEVEL = {'html_fallback': 'warn', 'soft_404_fallback_body': 'warn', 'empty': 'error', 'invalid_json': 'error', 'case_mismatch': 'error', 'incomplete_body': 'warn', 'not_collected': 'info', 'absent': 'info', 'absent_fallback': 'info', 'request_failed': 'warn', 'redirect_not_followed': 'warn'}
STATE_TEXT = {'absent_fallback': "absent (the path answers with the site's fallback page)", 'html_fallback': 'the path answers with an HTML fallback page', 'soft_404_fallback_body': 'the body equals the unknown-path fallback'}

def _state_text(state):
    return STATE_TEXT.get(state, state.replace('_', ' '))

def load_json(source, path, findings, check='json_parses'):
    """Fetch and parse one JSON document from a source; None when unavailable."""
    state, data = source.get(path)
    file = source.label(path)
    if state != 'present':
        findings.add(UNAVAILABLE_LEVEL.get(state, 'warn'), file, check, 'Not evaluated: %s' % _state_text(state), source.kind)
        return None
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        findings.add('error', file, check, 'Not valid UTF-8', source.kind)
        return None
    if text.startswith(ps.BOM):
        findings.add('warn', file, check, 'Starts with a UTF-8 BOM; JSON (RFC 8259) must not add one', source.kind)
    try:
        doc = ps.parse_json_text(text)  # rejects NaN/Infinity as JSON.parse does
    except (ValueError, RecursionError) as exc:
        findings.add('error', file, check, 'Does not parse as JSON: %s' % str(exc)[:200], source.kind)
        return None
    findings.add('info', file, check, 'ok: parses as JSON', source.kind)
    return doc

def load_text(source, path, findings, check):
    state, data = source.get(path)
    file = source.label(path)
    if state != 'present':
        findings.add(UNAVAILABLE_LEVEL.get(state, 'warn'), file, check, 'Not evaluated: %s' % _state_text(state), source.kind)
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        findings.add('error', file, check, 'Not valid UTF-8', source.kind)
        return None

def sweep_site_json(source, findings):
    """Site mode: every .json under .well-known/, known extensionless JSON files, openapi.json."""
    well_known = source.root / '.well-known'
    paths = []
    if well_known.is_dir():
        for path in sorted(well_known.rglob('*')):
            if not path.is_file(): continue
            rel = path.relative_to(source.root).as_posix()
            parts = rel.split('/')
            if path.suffix.lower() == '.json' or parts[1] in EXTENSIONLESS_JSON:
                paths.append('/' + rel)
    if (source.root / 'openapi.json').is_file(): paths.append('/openapi.json')
    for path in paths:
        load_json(source, path, findings)
    if not paths:
        findings.add('info', '.well-known/', 'json_parses', 'No JSON documents found under .well-known/ or openapi.json', source.kind)

def resolve_links(source, findings, file, check, links, base, relative_level, absolute_level):
    for link in links:
        target = ps._join(base, link)
        if not target or _scheme(target) not in ('http', 'https'):
            if _scheme(link) is None:
                findings.add('warn', file, check, '%s is not a valid URL' % link[:200], source.kind)
            continue
        found, detail = source.locate(target)
        if found is True:
            findings.add('info', file, check, 'ok: %s %s' % (link[:200], detail), source.kind)
        elif found is False:
            level = relative_level if not _scheme(link) else absolute_level
            findings.add(level, file, check, '%s: %s' % (link[:200], detail), source.kind)
        else:
            findings.add('info', file, check, '%s: %s' % (link[:200], detail), source.kind)

def verify_api_catalog(source, findings):
    path = '/.well-known/api-catalog'
    doc = load_json(source, path, findings, 'api_catalog.json_parses')
    if doc is None: return
    file = source.label(path)
    checked = ps.check_api_catalog(doc, source.origin + path)
    findings.extend_shape(checked['findings'], file, source.kind, 'api_catalog')
    for href in checked['hrefs']:
        if href['rel'] not in ('service-desc', 'service-doc'):
            findings.add('info', file, 'api_catalog.href_resolves', '%s %s is not checked as a file (usually a live endpoint)' % (href['rel'], href['href'][:200]), source.kind)
            continue
        # A service-desc/service-doc target may be a dynamic route that has no file: warn, not error.
        resolve_links(source, findings, file, 'api_catalog.href_resolves', [href['href']], source.origin + path, 'warn', 'warn')

def verify_skills(source, findings):
    path = '/.well-known/agent-skills/index.json'
    doc = load_json(source, path, findings, 'agent_skills.json_parses')
    if doc is None: return
    file = source.label(path)
    checked = ps.check_skill_index(doc)
    findings.extend_shape(checked['findings'], file, source.kind, 'agent_skills')
    for skill in checked['skills']:
        label = 'skills[%d]' % skill['index']
        if not ps._is_str(skill.get('url')) or not ps._is_str(skill.get('digest')): continue
        url = ps._join(source.origin + path, skill['url'])
        if not url or not ps.same_origin(url, source.origin):
            findings.add('warn', file, 'agent_skills.digest', '%s url %s is cross-origin; digest not verifiable here' % (label, skill['url'][:200]), source.kind)
            continue
        data, detail = source.artifact_bytes(url)
        if data is None:
            findings.add('error' if source.kind == 'site' else 'warn', file, 'agent_skills.digest', '%s artifact %s: %s' % (label, skill['url'][:200], detail), source.kind)
            continue
        actual = 'sha256:' + hashlib.sha256(data).hexdigest()
        if skill['digest'].strip().lower() == actual:
            findings.add('info', file, 'agent_skills.digest', 'ok: %s digest matches %s (%s)' % (label, actual, detail), source.kind)
        else:
            findings.add('error', file, 'agent_skills.digest', '%s advertised %s but the artifact bytes hash to %s (%s)' % (label, skill['digest'][:80], actual, detail), source.kind)

def verify_ard(source, findings):
    # ai-catalog.json keeps the scanner's catalog shape; ard.json follows the ARD manifest text.
    for path, prefix, check in (('/.well-known/ai-catalog.json', 'ard', ps.check_ard), ('/.well-known/ard.json', 'ard_manifest', ps.check_ard_manifest)):
        doc = load_json(source, path, findings, prefix + '.json_parses')
        if doc is None: continue
        file = source.label(path)
        checked = check(doc)
        findings.extend_shape(checked['findings'], file, source.kind, prefix)
        resolve_links(source, findings, file, prefix + '.entry_url_resolves', [item['url'] for item in checked['entry_urls']], source.origin + path, 'warn', 'warn')

def verify_mcp_card(source, findings):
    path = '/.well-known/mcp/server-card.json'
    doc = load_json(source, path, findings, 'mcp_card.json_parses')
    if doc is None: return
    checked = ps.check_mcp_card(doc, source.origin + path)
    findings.extend_shape(checked['findings'], source.label(path), source.kind, 'mcp_card')

def verify_oauth(source, findings):
    issuers = []
    for path, prefix in (('/.well-known/oauth-authorization-server', 'oauth_as'), ('/.well-known/openid-configuration', 'openid')):
        doc = load_json(source, path, findings, prefix + '.json_parses')
        if doc is None: continue
        checked = ps.check_oauth_as(doc, source.origin)
        findings.extend_shape(checked['findings'], source.label(path), source.kind, prefix)
        if not isinstance(doc, dict): continue  # valid JSON that is not an object ([], "text")
        if checked['issuer']: issuers.append(checked['issuer'])
        if ps._is_str(doc.get('jwks_uri')):
            resolve_links(source, findings, source.label(path), prefix + '.jwks_uri_resolves', [doc['jwks_uri']], source.origin + path, 'warn', 'warn')
    prm_docs = [('/.well-known/oauth-protected-resource', '')]
    if source.kind == 'site' and (source.root / '.well-known' / 'oauth-protected-resource').is_dir():
        base = source.root / '.well-known' / 'oauth-protected-resource'
        prm_docs = [('/.well-known/oauth-protected-resource/' + p.relative_to(base).as_posix(), '/' + p.relative_to(base).as_posix()) for p in sorted(base.rglob('*')) if p.is_file()]
    for path, resource_path in prm_docs:
        doc = load_json(source, path, findings, 'prm.json_parses')
        if doc is None: continue
        checked = ps.check_prm(doc, source.origin, issuers, resource_path)
        findings.extend_shape(checked['findings'], source.label(path), source.kind, 'prm')
        if not isinstance(doc, dict): continue
        servers = doc.get('authorization_servers') if isinstance(doc.get('authorization_servers'), list) else []
        if not issuers and any(ps._is_str(s) and ps.same_origin(s, source.origin) for s in servers):
            findings.add('warn', source.label(path), 'prm.authorization_server_metadata', 'authorization_servers names this origin but no /.well-known/oauth-authorization-server metadata was found', source.kind)

def verify_auth_md(source, findings):
    text = load_text(source, '/auth.md', findings, 'auth_md.h1')
    if text is not None:
        findings.extend_shape(ps.check_auth_md(text)['findings'], source.label('/auth.md'), source.kind, 'auth_md')

def verify_llms(source, findings):
    text = load_text(source, '/llms.txt', findings, 'llms_txt.h1')
    if text is None: return
    file = source.label('/llms.txt')
    checked = ps.check_llms_txt(text)
    findings.extend_shape(checked['findings'], file, source.kind, 'llms_txt')
    # Relative links can point at dynamic CMS routes with no file in the folder: warn, not error.
    resolve_links(source, findings, file, 'llms_txt.link_resolves', checked['links'], source.origin + '/llms.txt', 'warn', 'warn')

def verify_robots(source, findings):
    text = load_text(source, '/robots.txt', findings, 'robots.groups')
    if text is None: return
    file = source.label('/robots.txt')
    facts = ps.analyze_robots(text)
    if not facts['group_count']:
        findings.add('error', file, 'robots.groups', 'No User-agent groups parsed', source.kind)
    else:
        findings.add('info', file, 'robots.groups', 'ok: %d groups, %d allow and %d disallow rules' % (facts['group_count'], facts['allow_rules'], facts['disallow_rules']), source.kind)
    if facts['rules_outside_groups']:
        findings.add('warn', file, 'robots.rules_outside_groups', '%d Allow/Disallow lines appear before any User-agent line' % facts['rules_outside_groups'], source.kind)
    if facts['unparseable_lines']:
        findings.add('warn', file, 'robots.unparseable_lines', '%d non-comment lines have no "key: value" form' % facts['unparseable_lines'], source.kind)
    if facts['disallow_all_for_wildcard']:
        findings.add('warn', file, 'robots.disallow_all', 'User-agent * is disallowed from the whole site', source.kind)
    for sitemap in facts['sitemaps']:
        scheme = _scheme(sitemap)
        if scheme is None:
            findings.add('warn', file, 'robots.sitemap_absolute', 'Sitemap %s is not a valid URL' % sitemap[:200], source.kind)
        elif not scheme:
            findings.add('warn', file, 'robots.sitemap_absolute', 'Sitemap %s is not an absolute URL' % sitemap[:200], source.kind)
    signal = facts['content_signal']
    findings.add('info', file, 'robots.content_signal', 'Content-Signal lines: %d' % len(signal['body_lines']), source.kind)
    missing = facts['scanner_ai_rules_bots']['missing']
    findings.add('info', file, 'robots.scanner_ai_rule_bots', 'No explicit group for: ' + ', '.join(missing) if missing else 'ok: explicit groups for all nine scanner-named AI bots', source.kind)
    for bot in facts['effective_rules_by_bot']:
        if bot['verdict'] == 'named_group_drops_star_disallow':
            # A warning: dropping a * rule for a named bot can be deliberate.
            findings.add('warn', file, 'robots.named_group_drops_star_disallow', '%s obeys only its own group (line %s), which lacks the * Disallow path(s): %s; confirm this is intended' % (bot['name'], ', '.join(map(str, bot['group_lines'])), ', '.join(bot['missing_star_disallow_paths'])), source.kind)
        if bot['star_content_signal_not_inherited']:
            findings.add('warn', file, 'robots.content_signal_not_applied', '%s has its own group without Content-Signal; the * group signal does not apply to it' % bot['name'], source.kind)

def verify_misc(source, findings):
    for path, prefix, check in (('/.well-known/agent-card.json', 'a2a_agent_card', ps.check_agent_card), ('/.well-known/http-message-signatures-directory', 'web_bot_auth', lambda d: ps.check_key_set(d, 'warn')), ('/.well-known/jwks.json', 'jwks', lambda d: ps.check_key_set(d, 'info')), ('/openapi.json', 'openapi', ps.check_openapi)):
        state, _ = source.get(path)
        if state in ('absent', 'absent_fallback', 'not_collected'): continue
        doc = load_json(source, path, findings, prefix + '.json_parses')
        if doc is not None:
            findings.extend_shape(check(doc)['findings'], source.label(path), source.kind, prefix)

def verify_evidence_summary(source, findings):
    """Cross-check the report's recorded digest verdicts against the saved bytes."""
    recorded = source.report.get('summary', {}).get('skill_artifacts', {}).get('artifacts', [])
    for item in recorded:
        ident = item.get('result_id')
        if not ident or ident not in source.data or item.get('state') not in ('match', 'mismatch'): continue
        actual = 'sha256:' + hashlib.sha256(source.data[ident]).hexdigest()
        state = 'match' if (item.get('advertised_digest') or '').strip().lower() == actual else 'mismatch'
        if state != item['state']:
            findings.add('error', ident, 'evidence.recorded_digest_verdict', 'Report says %s but the saved bytes give %s' % (item['state'], state), source.kind)

def verify_site_behaviour(source, findings):
    """Evidence mode: report soft-404 behaviour once, as a site-level warning."""
    soft = source.report.get('summary', {}).get('soft_404') or {}
    if soft.get('unknown_paths_answer_200'):
        findings.add('warn', 'site', 'evidence.soft_404', 'Unknown paths answer 200%s; each resource above is judged by its body, and fallback pages for optional resources count as absent' % (' with an HTML fallback page' if soft.get('html_fallback_for_unknown_json') else ''), source.kind)

def run_checks(source, findings):
    checks = [verify_api_catalog, verify_skills, verify_ard, verify_mcp_card, verify_oauth, verify_auth_md, verify_llms, verify_robots, verify_misc]
    if source.kind == 'site':
        checks.insert(0, sweep_site_json)
    else:
        checks += [verify_evidence_summary, verify_site_behaviour]
    for check in checks:
        try:
            check(source, findings)
        except Exception as exc:  # hostile input must not crash the verifier; an unfinished check is an error
            findings.add('error', '-', check.__name__ + '.check_error', 'Check could not finish (%s: %s); its result is unknown' % (type(exc).__name__, str(exc)[:200]), source.kind)

def validated_origin(value):
    """A canonical origin: explicit default port and trailing host dot removed."""
    url = ps.validated_url(value)
    parts = urlsplit(url)
    if parts.path not in ('', '/') or parts.query:
        raise ValueError('--origin must be an origin such as https://example.com (no path or query)')
    return ps.canonical_origin(url)

def main(argv=None):
    ps.configure_streams()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--site-root', type=Path, help='Local folder that is published as the site root')
    parser.add_argument('--origin', help='Canonical origin the folder is served from, e.g. https://example.com')
    parser.add_argument('--evidence', type=Path, help='Probe report (schema 2.0) written by probe_site.py')
    parser.add_argument('--raw-dir', type=Path, help='Directory written by probe_site.py --save-raw')
    parser.add_argument('--output', type=Path, help='Also write the JSON result to this new file (UTF-8)')
    args = parser.parse_args(argv)
    if args.site_root is None and args.evidence is None:
        parser.error('Give --site-root DIR --origin URL, or --evidence FILE --raw-dir DIR, or both')
    origin = None
    if args.origin:
        try: origin = validated_origin(args.origin)
        except ValueError as exc: parser.error(str(exc))
    if args.output is not None and args.output.exists():
        parser.error('--output already exists; choose a new path')
    findings, modes = Findings(), []
    if args.site_root is not None:
        if origin is None: parser.error('--site-root needs --origin')
        if not args.site_root.is_dir(): parser.error('--site-root is not a directory')
        run_checks(SiteSource(args.site_root, origin), findings)
        modes.append('site')
    if args.evidence is not None:
        if args.raw_dir is None or not args.raw_dir.is_dir(): parser.error('--evidence needs an existing --raw-dir')
        try:
            report = json.loads(args.evidence.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            parser.error('Cannot read the evidence report: %s' % exc)
        if not isinstance(report, dict):
            parser.error('The evidence report is not a JSON object')
        if report.get('schema_version') != ps.VERSION:
            findings.add('warn', str(args.evidence.name), 'evidence.schema_version', 'Report schema_version is %r; this verifier expects %s' % (report.get('schema_version'), ps.VERSION), 'evidence')
        evidence_origin = origin or (report.get('target') or {}).get('metadata_origin')
        if not evidence_origin: parser.error('The report has no target.metadata_origin; pass --origin')
        try:
            evidence_origin = validated_origin(evidence_origin)
        except ValueError as exc:
            parser.error('Evidence origin: %s' % exc)
        run_checks(EvidenceSource(report, args.raw_dir, evidence_origin, findings), findings)
        modes.append('evidence')
    counts = {level: sum(item['level'] == level for item in findings.items) for level in ('error', 'warn', 'info')}
    result = {'tool': TOOL, 'version': VERSION, 'modes': modes, 'counts': counts, 'findings': findings.items, 'note': 'Structural checks only; no score. Live behaviour (MCP, OAuth, APIs) is not exercised.'}
    if args.output is not None:
        try:
            ps.write_json_file(args.output, result)
        except OSError as exc:
            print('Cannot write output: %s' % exc, file=sys.stderr)
            return 2
    # ensure_ascii keeps stdout valid JSON on any console or pipe encoding (cp1252, cp936, ...).
    print(ps.dump_json_text(result, ensure_ascii=True))
    return 1 if counts['error'] else 0

if __name__ == '__main__':
    sys.exit(main())
