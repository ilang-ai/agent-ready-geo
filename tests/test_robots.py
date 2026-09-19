"""robots.txt analysis runs on the complete body, never on a leading snippet."""
import unittest

import fixture_site  # noqa: F401
import probe_site as ps

class RobotsTests(unittest.TestCase):
    def test_content_signal_after_byte_600(self):
        body = '# ' + 'x' * 700 + '\nUser-agent: *\nContent-Signal: ai-train=no, search=yes, ai-input=yes\nAllow: /\n'
        self.assertGreater(body.index('Content-Signal'), 600)
        facts = ps.analyze_robots(body)
        signal = facts['content_signal']
        self.assertTrue(signal['present_in_body'])
        self.assertEqual(signal['values_by_group'][0]['values'], {'search': 'yes', 'ai-input': 'yes', 'ai-train': 'no'})
        self.assertEqual(signal['values_by_group'][0]['user_agents'], ['*'])

    def test_content_signal_header_recorded(self):
        facts = ps.analyze_robots('User-agent: *\nAllow: /\n', {'homepage_response': 'search=yes, ai-train=no', 'robots_response': None})
        self.assertFalse(facts['content_signal']['present_in_body'])
        self.assertTrue(facts['content_signal']['present_in_header'])
        self.assertEqual(facts['content_signal']['headers_parsed']['homepage_response'], {'search': 'yes', 'ai-train': 'no'})

    def test_ai_bots_matched_as_whole_tokens(self):
        body = '\n'.join([
            '# GPTBot is mentioned only in a comment here',
            'User-agent: GPTBot-Extended-Fake', 'Disallow: /',
            'User-agent: NotClaudeBot', 'Disallow: /',
            'User-agent: gptbot', 'Allow: /',
            'User-agent: ClaudeBot/1.0', 'Disallow: /private/',
        ])
        facts = ps.analyze_robots(body)
        names = facts['named_ai_crawler_names']
        self.assertIn('GPTBot', names)
        self.assertIn('ClaudeBot', names)
        gpt = next(item for item in facts['named_ai_crawlers'] if item['name'] == 'GPTBot')
        self.assertEqual(gpt['group_lines'], [6])
        self.assertIn('gptbot-extended-fake', facts['other_user_agents'])
        self.assertIn('notclaudebot', facts['other_user_agents'])

    def test_disallow_all_detection(self):
        self.assertTrue(ps.analyze_robots('User-agent: *\nDisallow: /\n')['disallow_all_for_wildcard'])
        self.assertFalse(ps.analyze_robots('User-agent: *\nDisallow: /\nAllow: /public/\n')['disallow_all_for_wildcard'])
        self.assertFalse(ps.analyze_robots('User-agent: *\nDisallow: /private/\n')['disallow_all_for_wildcard'])
        self.assertIsNone(ps.analyze_robots('User-agent: GPTBot\nDisallow: /\n')['disallow_all_for_wildcard'])

    def test_groups_counts_and_sitemaps(self):
        body = 'Disallow: /orphan\nUser-agent: a\nUser-agent: b\nDisallow: /x\nDisallow:\n\nUser-agent: c\nAllow: /\nSitemap: https://e.com/sitemap.xml\nno colon here\n'
        facts = ps.analyze_robots(body)
        self.assertEqual(facts['group_count'], 2)
        self.assertEqual(facts['groups'][0]['user_agents'], ['a', 'b'])
        self.assertEqual((facts['disallow_rules'], facts['empty_disallow_rules'], facts['allow_rules']), (1, 1, 1))
        self.assertEqual(facts['rules_outside_groups'], 1)
        self.assertEqual(facts['unparseable_lines'], 1)
        self.assertEqual(facts['sitemaps'], ['https://e.com/sitemap.xml'])

    def test_scanner_named_bots_need_explicit_groups(self):
        wildcard_only = ps.analyze_robots('User-agent: *\nAllow: /\n')['scanner_ai_rules_bots']
        self.assertEqual(sorted(wildcard_only['missing']), sorted(ps.SCANNER_AI_RULE_BOTS))
        body = ''.join('User-agent: %s\nAllow: /\n\n' % name for name in ps.SCANNER_AI_RULE_BOTS)
        explicit = ps.analyze_robots(body)['scanner_ai_rules_bots']
        self.assertEqual(explicit['missing'], [])
        self.assertTrue(all(explicit['explicit_group_present'].values()))

    def effective(self, body, name):
        return next(item for item in ps.analyze_robots(body)['effective_rules_by_bot'] if item['name'] == name)

    def test_named_allow_all_group_drops_star_disallow(self):
        body = 'User-agent: *\nDisallow: /private/\nDisallow: /tmp/\n\nUser-agent: GPTBot\nAllow: /\n'
        gpt = self.effective(body, 'GPTBot')
        self.assertEqual((gpt['effective_group'], gpt['verdict']), ('named', 'named_group_drops_star_disallow'))
        self.assertEqual(gpt['missing_star_disallow_paths'], ['/private/', '/tmp/'])
        self.assertEqual(ps.analyze_robots(body)['bots_dropping_star_disallows'], ['GPTBot'])

    def test_named_group_repeating_star_rules_has_no_finding(self):
        body = 'User-agent: *\nDisallow: /private/\nDisallow: /*.pdf$\n\nUser-agent: GPTBot\nAllow: /\nDisallow: /private/\nDisallow: /*.pdf$\n\nUser-agent: CCBot\nDisallow: /\n'
        facts = ps.analyze_robots(body)
        self.assertEqual(self.effective(body, 'GPTBot')['verdict'], 'named_group_keeps_star_disallows')
        self.assertEqual(self.effective(body, 'CCBot')['verdict'], 'named_group_keeps_star_disallows')
        self.assertEqual(facts['bots_dropping_star_disallows'], [])
        amazon = self.effective(body, 'Amazonbot')
        self.assertEqual((amazon['effective_group'], amazon['verdict'], amazon['disallow_paths']), ('star', 'uses_star_group', ['/private/', '/*.pdf$']))

    def test_content_signal_only_under_star(self):
        body = 'User-agent: *\nContent-Signal: search=yes, ai-train=no\nAllow: /\n\nUser-agent: GPTBot\nAllow: /\n'
        gpt = self.effective(body, 'GPTBot')
        self.assertFalse(gpt['content_signal_applies'])
        self.assertTrue(gpt['star_content_signal_not_inherited'])
        self.assertIsNone(gpt['content_signal_values'])
        ccbot = self.effective(body, 'CCBot')
        self.assertTrue(ccbot['content_signal_applies'])
        self.assertEqual(ccbot['content_signal_values'], {'search': 'yes', 'ai-input': None, 'ai-train': 'no'})
        facts = ps.analyze_robots(body)
        self.assertIn('GPTBot', facts['bots_without_applicable_content_signal'])
        self.assertNotIn('CCBot', facts['bots_without_applicable_content_signal'])

    def test_no_star_group_and_no_rules(self):
        body = 'User-agent: GPTBot\nDisallow: /x/\n'
        self.assertEqual(self.effective(body, 'GPTBot')['verdict'], 'no_star_disallow_to_compare')
        self.assertEqual(self.effective(body, 'CCBot')['verdict'], 'no_group_applies')

    def test_bom_and_crlf(self):
        facts = ps.analyze_robots('\ufeffUser-agent: *\r\nDisallow: /\r\n')
        self.assertEqual(facts['groups'][0]['user_agents'], ['*'])
        self.assertTrue(facts['disallow_all_for_wildcard'])

if __name__ == '__main__':
    unittest.main()
