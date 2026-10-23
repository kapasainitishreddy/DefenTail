import json
import os
import textwrap
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defentail.core import scan, compare, parse_betterleaks, parse_semgrep, parse_osv, parse_trivy, digest_valid
from defentail.intelligence import bundled_data, _validate_kev, update_kev, KEV_URL, KEV_MIRROR
from defentail.ui import render_page


class DefenTailTests(unittest.TestCase):
    def test_builtin_finds_unsafe_tls_and_hides_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'server.py').write_text('requests.get("https://example.com", verify=False)\n'
                                            'secret = "-----BEGIN PRIVATE KEY-----"\n', encoding='utf-8')
            result = scan(root, profile='basic')
            self.assertTrue(digest_valid(result))
            self.assertFalse(result['gate']['passed'])
            ids = {f['rule_id'] for f in result['findings']}
            self.assertIn('DT-TLS-VERIFY-DISABLED', ids)
            self.assertIn('DT-PRIVATE-KEY-IN-FILE', ids)
            self.assertNotIn('-----BEGIN PRIVATE KEY-----', json.dumps(result))

    def test_incident_version_from_lockfile(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'package-lock.json').write_text(json.dumps({
                'lockfileVersion': 3,
                'packages': {
                    'node_modules/next': {'version': '15.2.2'},
                    'node_modules/react-server-dom-webpack': {'version': '19.2.0'}
                }
            }))
            result = scan(root, profile='basic')
            ids = {f.get('incident_id') for f in result['findings']}
            self.assertIn('CVE-2025-29927', ids)
            self.assertIn('CVE-2025-55182', ids)
            self.assertFalse(result['gate']['passed'])

    def test_patched_versions_not_flagged_by_seeded_incident_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'package-lock.json').write_text(json.dumps({
                'packages': {'node_modules/next': {'version': '15.2.3'},
                             'node_modules/react-server-dom-webpack': {'version': '19.2.1'}}
            }))
            result = scan(root, profile='basic')
            self.assertFalse(any(i['rule_id'].endswith('KNOWN-VERSION') for i in result['findings']))
            self.assertEqual(result['assurance'], 'limited')

    def test_missing_scanners_block_advanced_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch('defentail.core.shutil.which', return_value=None):
                result = scan(Path(folder), profile='quick')
            self.assertFalse(result['gate']['passed'])
            self.assertIn('semgrep', result['gate']['blocked_by']['incomplete_engines'])
            self.assertIn('osv-scanner', result['gate']['blocked_by']['incomplete_engines'])

    def test_comparison_not_claimed_fixed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            file = root / 'a.py'
            file.write_text('requests.get("a", verify=False)')
            before = scan(root, profile='basic')
            file.write_text('requests.get("a", verify=True)')
            after = scan(root, profile='basic')
            delta = compare(before, after)
            self.assertEqual(len(delta['removed_from_scan']), 1)
            self.assertIn('does not prove', delta['verification_note'])

    def test_osv_parser(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            obj = {'results': [{'source': {'path': str(root / 'package-lock.json')},
                                'packages': [{'package': {'name': 'next', 'version': '15.2.2'},
                                              'vulnerabilities': [{'id': 'GHSA-x', 'aliases': ['CVE-2025-29927']}]}]}]}
            entries = parse_osv(obj, root)
            self.assertEqual(entries[0]['rule_id'], 'CVE-2025-29927')
            self.assertEqual(entries[0]['package'], 'next')
            self.assertNotIn('secret', json.dumps(entries))

    def test_betterleaks_does_not_expose_raw_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            entries = parse_betterleaks([{'RuleID':'generic-api-key','File':'config.py',
                                         'StartLine': 1, 'Secret': 'VERY-SECRET-XYZ'}], Path(folder))
            self.assertEqual(len(entries), 1)
            self.assertNotIn('VERY-SECRET-XYZ', json.dumps(entries))

    def test_semgrep_default_severity_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            data = {'results': [{'check_id': 'my-risk', 'path': str(root/'x.py'), 'start': {'line': 4},
                                 'extra': {'message': 'TOKEN-EXAMPLE'}}]}
            item = parse_semgrep(data, root)[0]
            self.assertEqual(item['severity'], 'UNKNOWN')
            self.assertNotIn('TOKEN-EXAMPLE', json.dumps(item))

    def test_trivy_secrets_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            entries = parse_trivy({'Results': [{'Target': 'a.py', 'Secrets': [{'RuleID': 'secret',
                'Title': 'secret TOKEN-WOULD-BE-HERE', 'StartLine':2,'Severity': 'HIGH'}]}]}, Path(folder))
            self.assertEqual(len(entries), 1)
            self.assertNotIn('TOKEN-WOULD-BE-HERE', json.dumps(entries))

    def test_invalid_cisa_feed_rejected(self):
        with self.assertRaises(ValueError):
            _validate_kev({'vulnerabilities':[{'cveID':'bad'}]})

    def test_real_process_orchestration_with_hermetic_fake_tools(self):
        """Exercises subprocess invocations and JSON parsers without live third-party binaries."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            bindir = root / 'mock-bin'
            bindir.mkdir()
            # These mocks use documented JSON shapes; they are not a live scanner validation.
            tool_outputs = {
                'semgrep': {'results': []},
                'betterleaks': [],
                'osv-scanner': {'results': []},
                'trivy': {'Results': []},
            }
            for name, payload in tool_outputs.items():
                stub = bindir / name
                code = """#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
payload = PAYLOAD
if 'osv-scanner' in sys.argv[0]:
    print(json.dumps(payload))
else:
    flag = '--output' if '--output' in args else '--report-path'
    with open(args[args.index(flag) + 1], 'w', encoding='utf-8') as fh:
        json.dump(payload, fh)
""" .replace('PAYLOAD', repr(payload))
                stub.write_text(code, encoding='utf-8')
                stub.chmod(0o755)
            with patch.dict(os.environ, {'PATH': str(bindir) + os.pathsep + os.environ.get('PATH','')}):
                result = scan(root, profile='full')
            self.assertEqual(len(result['checks']), 5)
            self.assertTrue(all(c['status'] == 'complete' for c in result['checks']))
            self.assertTrue(result['gate']['passed'])

    def test_cisa_primary_bad_data_falls_back_to_official_mirror(self):
        class Response:
            def __init__(self, content, url):
                self.content, self.url = content, url
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self, _limit):
                return self.content
            def geturl(self):
                return self.url
        with tempfile.TemporaryDirectory() as folder:
            content = json.dumps({'vulnerabilities': [{'cveID': 'CVE-2025-1234'}]}).encode()
            with patch.dict(os.environ, {'DEFENTAIL_DATA_HOME': folder}):
                with patch('defentail.intelligence.urllib.request.urlopen', side_effect=[
                    Response(b'INVALID SOURCE', KEV_URL), Response(content, KEV_MIRROR)]):
                    result = update_kev()
                self.assertEqual(result['record_count'], 1)
                self.assertEqual(result['status'], 'fresh')

    def test_curated_data_and_beginner_html(self):
        self.assertTrue(bundled_data('incidents.json')['incidents'])
        self.assertTrue(bundled_data('policies.json')['policies'])
        page = render_page('fake-token', '/tmp/project', 'basic', None).decode()
        self.assertIn('Check my app', page)
        self.assertIn('Private on this computer', page)
        self.assertIn('Store rules and privacy checks', page)
        self.assertIn('Human review needed', page)
        self.assertIn('Advanced scanners run locally', page)


if __name__ == '__main__':
    unittest.main()
