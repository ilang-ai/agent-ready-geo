"""Markdown negotiation verdicts: declared type and body, parity, q=0, Vary, stability."""
import unittest

import fixture_site  # noqa: F401
import probe_site as ps

HTML = '<!DOCTYPE html><html><body><h1>Home</h1></body></html>'
MD = '# Home\n\nText.\n'
ORDER = ['text/html', 'text/markdown'] * 3

def row(accept, text, content_type, vary='Accept', status=200):
    semantic = ps.semantic_body(text, content_type, True)
    headers = {'content-type': content_type}
    if vary: headers['vary'] = vary
    return {'accept': accept, 'status': status, 'error': None, 'headers': headers, 'body': {'complete': True, 'sha256': str(hash(text)), 'semantic': semantic}}

def good_order():
    return [row(a, MD if a == 'text/markdown' else HTML, 'text/markdown' if a == 'text/markdown' else 'text/html') for a in ORDER]

def good_q0():
    return [row('text/markdown;q=0', HTML, 'text/html'), row('text/html,text/markdown;q=0', HTML, 'text/html')]

class NegotiationTests(unittest.TestCase):
    def test_good_site(self):
        verdicts = ps.negotiation_verdicts(good_order(), good_q0())
        self.assertEqual(verdicts['summary'], 'markdown_negotiation_observed')
        for name in ('markdown_served_for_text_markdown', 'markdown_body_differs_from_html', 'html_after_markdown_still_html', 'q0_requests_did_not_return_markdown', 'vary_includes_accept', 'html_hash_stable', 'markdown_hash_stable'):
            self.assertIs(verdicts[name], True, name)

    def test_header_changed_but_body_still_html(self):
        order = [row(a, HTML, 'text/markdown' if a == 'text/markdown' else 'text/html') for a in ORDER]
        verdicts = ps.negotiation_verdicts(order, good_q0())
        self.assertIs(verdicts['markdown_served_for_text_markdown'], False)
        self.assertIs(verdicts['markdown_body_differs_from_html'], False)
        self.assertEqual(verdicts['summary'], 'markdown_negotiation_problems')

    def test_q0_returning_markdown(self):
        q0 = [row('text/markdown;q=0', MD, 'text/markdown'), row('text/html,text/markdown;q=0', HTML, 'text/html')]
        self.assertIs(ps.negotiation_verdicts(good_order(), q0)['q0_requests_did_not_return_markdown'], False)

    def test_vary_accept_encoding_is_not_accept(self):
        order = [row(a, MD if a == 'text/markdown' else HTML, 'text/markdown' if a == 'text/markdown' else 'text/html', vary='Accept-Encoding') for a in ORDER]
        self.assertIs(ps.negotiation_verdicts(order, good_q0())['vary_includes_accept'], False)

    def test_cache_contamination(self):
        order = good_order()
        order[2] = row('text/html', MD, 'text/markdown')
        verdicts = ps.negotiation_verdicts(order, good_q0())
        self.assertIs(verdicts['html_after_markdown_still_html'], False)
        self.assertIs(verdicts['html_hash_stable'], False)

    def test_truncated_html_still_decides_difference_by_kind(self):
        order = good_order()
        for r in order:
            if r['accept'] == 'text/html': r['body']['complete'] = False
        verdicts = ps.negotiation_verdicts(order, good_q0())
        self.assertIs(verdicts['markdown_body_differs_from_html'], True)
        self.assertIsNone(verdicts['html_hash_stable'])
        same_kind = [row(a, HTML, 'text/markdown' if a == 'text/markdown' else 'text/html') for a in ORDER]
        for r in same_kind:
            if r['accept'] == 'text/html': r['body']['complete'] = False
        self.assertIsNone(ps.negotiation_verdicts(same_kind, good_q0())['markdown_body_differs_from_html'])

    def test_unknown_when_not_collected(self):
        order = [dict(r, status=None, body={}) for r in good_order()]
        q0 = [dict(r, status=None, body={}) for r in good_q0()]
        verdicts = ps.negotiation_verdicts(order, q0)
        self.assertIsNone(verdicts['markdown_served_for_text_markdown'])
        self.assertEqual(verdicts['summary'], 'markdown_negotiation_unknown')

if __name__ == '__main__':
    unittest.main()
