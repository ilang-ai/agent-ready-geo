"""URL normalisation: IDNA hosts, UTF-8 percent-encoding, no double encoding (book S22/T04)."""
import string
import unittest
from urllib.parse import quote, urljoin

import fixture_site  # noqa: F401  (puts scripts/ on sys.path)
import probe_site as ps

def norm(url):
    return ps.normalise_url(url)[0]

class NormaliseUrlTests(unittest.TestCase):
    def test_chinese_path(self):
        self.assertEqual(norm('https://example.com/中文/路径'), 'https://example.com/%E4%B8%AD%E6%96%87/%E8%B7%AF%E5%BE%84')

    def test_chinese_query_keeps_structure(self):
        self.assertEqual(norm('https://example.com/s?q=中文&lang=zh&empty='), 'https://example.com/s?q=%E4%B8%AD%E6%96%87&lang=zh&empty=')

    def test_spaces_encoded_as_percent_20(self):
        self.assertEqual(norm('https://example.com/a b/c?x=1 2'), 'https://example.com/a%20b/c?x=1%202')

    def test_plus_and_equals_keep_their_meaning(self):
        self.assertEqual(norm('https://example.com/a+b?c=d+e&f==g'), 'https://example.com/a+b?c=d+e&f==g')

    def test_idn_host(self):
        url, notes = ps.normalise_url('https://例子.测试/')
        self.assertEqual(url, 'https://xn--fsqu00a.xn--0zwm56d/')
        self.assertTrue(notes['host_idna_converted'])

    def test_punycode_host_unchanged(self):
        self.assertEqual(norm('https://xn--fsqu00a.xn--0zwm56d/'), 'https://xn--fsqu00a.xn--0zwm56d/')

    def test_already_encoded_is_not_double_encoded(self):
        encoded = 'https://example.com/%E4%B8%AD%E6%96%87?q=%E4%B8%AD&x=%2F'
        self.assertEqual(norm(encoded), encoded)

    def test_lowercase_escapes_preserved_byte_for_byte(self):
        self.assertEqual(norm('https://example.com/%e4%b8%ad'), 'https://example.com/%e4%b8%ad')

    def test_mixed_raw_and_encoded(self):
        self.assertEqual(norm('https://example.com/已%E7%BC%96码/?k=值%20v'), 'https://example.com/%E5%B7%B2%E7%BC%96%E7%A0%81/?k=%E5%80%BC%20v')

    def test_stray_percent_is_encoded(self):
        self.assertEqual(norm('https://example.com/100%?p=5%'), 'https://example.com/100%25?p=5%25')

    def test_idempotent(self):
        for url in ('https://例子.测试/中文 路径?q=中文&a=b#x', 'https://example.com/%E4%B8%AD%20x?q=%26', 'http://[::1]:8080/p'):
            once = norm(url)
            self.assertEqual(norm(once), once)

    def test_fragment_dropped(self):
        url, notes = ps.normalise_url('https://example.com/page#section-中文')
        self.assertEqual(url, 'https://example.com/page')
        self.assertTrue(notes['fragment_dropped'])

    def test_empty_path_becomes_slash_and_scheme_host_lowercased(self):
        self.assertEqual(norm('HTTPS://Example.COM:8443'), 'https://example.com:8443/')

    def test_ipv6_literal(self):
        self.assertEqual(norm('http://[::1]:8080/x'), 'http://[::1]:8080/x')

    def test_userinfo_rejected(self):
        for url in ('https://user:pw@example.com/', 'https://user@example.com/', 'https://@example.com/'):
            with self.assertRaises(ps.InputRejected):
                ps.normalise_url(url)

    def test_other_rejections(self):
        for url in ('ftp://example.com/', 'https:///path', 'https://exa mple.com/', 'https://a..b/', 'https://example.com/\x00', 'https://example.com:99999/', 'https://%E4%BE%8B.com/'):
            with self.assertRaises(ps.InputRejected, msg=url):
                ps.normalise_url(url)

    def test_local_encoding_error_is_distinct(self):
        with self.assertRaises(ps.LocalEncodingError):
            ps.normalise_url('https://example.com/\udcff')
        self.assertEqual(ps.classify_exception(ps.LocalEncodingError('x')), ('local_encoding_error', 'local_encoding'))
        self.assertEqual(ps.classify_exception(ps.InputRejected('x')), ('input_rejected', 'local_input'))

    def test_redirect_to_chinese_path(self):
        # urllib decodes Location as ISO-8859-1 and re-quotes it before redirect_request;
        # a raw UTF-8 Location therefore arrives as %XX and must stay single-encoded.
        raw_header = '/中文/页面?q=值'.encode('utf-8').decode('latin-1')
        pre_quoted = quote(raw_header, encoding='iso-8859-1', safe=string.punctuation)
        joined = urljoin('https://example.com/start', pre_quoted)
        self.assertEqual(norm(joined), 'https://example.com/%E4%B8%AD%E6%96%87/%E9%A1%B5%E9%9D%A2?q=%E5%80%BC')
        self.assertEqual(ps.readable_header(raw_header), '/中文/页面?q=值')

    def test_app_base_chinese_path(self):
        self.assertEqual(ps.validated_app_base('/文档/', 'https://example.com'), '/%E6%96%87%E6%A1%A3/')
        with self.assertRaises(ValueError):
            ps.validated_app_base('/docs/../admin/', 'https://example.com')
        with self.assertRaises(ValueError):
            ps.validated_app_base('https://other.example/docs/', 'https://example.com')

if __name__ == '__main__':
    unittest.main()
