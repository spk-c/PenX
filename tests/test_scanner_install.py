"""Offline installation/dispatcher tests; no winget, downloads or scans are run."""
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

import install_scanners_windows as installer
from penx_app.scanners import tools


def fake_archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return output.getvalue()


class InstallerTests(unittest.TestCase):
    def test_bounded_safe_unzip_and_root_stripping(self):
        zipped = fake_archive({'whatweb-v0.6.4/': '',
                               'whatweb-v0.6.4/whatweb': 'code',
                               'whatweb-v0.6.4/plugins/a.rb': 'plugin'})
        with tempfile.TemporaryDirectory() as dir_name:
            installer.safe_unzip(zipped, Path(dir_name))
            self.assertEqual((Path(dir_name) / 'whatweb').read_text(), 'code')
            self.assertEqual((Path(dir_name) / 'plugins' / 'a.rb').read_text(), 'plugin')

    def test_traversal_blocked(self):
        for name in ('repo/../../bad', 'repo/../escape', 'repo/C:/drive'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    installer.safe_unzip(fake_archive({name: 'bad'}), Path(tmp))

    def test_symlink_blocked(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            link = zipfile.ZipInfo('repo/evil')
            link.create_system = 3
            link.external_attr = (0o120777 << 16)
            archive.writestr(link, '../elsewhere')
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                installer.safe_unzip(output.getvalue(), Path(tmp))

    def test_source_download_from_mock_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            vendor = Path(tmp)
            marker = vendor / 'whatweb' / 'whatweb'
            zipped = fake_archive({'whatweb-v0.6.4/whatweb': '#!/usr/bin/env ruby'})
            with patch.object(installer, 'VENDOR', vendor), \
                 patch.object(installer, 'download_archive', return_value=zipped) as download:
                self.assertTrue(installer.ensure_source('WhatWeb', installer.WHATWEB_URL,
                                                        marker.parent, marker))
                self.assertTrue(marker.is_file())
                self.assertTrue(installer.ensure_source('WhatWeb', installer.WHATWEB_URL,
                                                        marker.parent, marker))
                self.assertEqual(download.call_count, 1)

    def test_no_winget_without_windows(self):
        with patch.object(installer, 'find_runtime', return_value=None):
            self.assertIsNone(installer.ensure_runtime('ruby', no_winget=True))

    def test_genuine_scanners_use_correct_interpreter_cwd_and_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            whatweb = Path(tmp) / 'whatweb' / 'whatweb'
            nikto = Path(tmp) / 'nikto' / 'program' / 'nikto.pl'
            for script in (whatweb, nikto):
                script.parent.mkdir(parents=True)
                script.write_text('fake')
            with patch.object(tools, 'WHATWEB_PATH', str(whatweb)), \
                 patch.object(tools, 'NIKTO_PATH', str(nikto)), \
                 patch.object(tools, 'find_runtime', side_effect=lambda n: '/opt/' + n), \
                 patch.object(tools, 'run_tool', return_value='ok') as run:
                self.assertEqual(tools.run_whatweb('https://example.org:8443/test'), 'ok')
                self.assertEqual(run.call_args.args[0][-1], 'https://example.org:8443/test')
                self.assertEqual(run.call_args.kwargs['cwd'], str(whatweb.parent))
                self.assertEqual(tools.run_nikto('https://example.org:8443/test'), 'ok')
                self.assertEqual(run.call_args.args[0][-2:], ['https://example.org:8443/test', '-nointeractive'])
                self.assertEqual(run.call_args.kwargs['cwd'], str(nikto.parent))

    def test_nikto_bare_domain_keeps_hostname_with_ssl_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            nikto = Path(tmp) / "nikto.pl"
            nikto.write_text("fixture")
            with patch.object(tools, "NIKTO_PATH", str(nikto)), \
                 patch.object(tools, "find_runtime", return_value="/opt/perl"), \
                 patch.object(tools, "run_tool", return_value="- Nikto v2.6.1") as run:
                tools.run_nikto("shirtgeklebt.net")
                args = run.call_args.args[0]
                self.assertEqual(args[-6:], ["-ssl", "-port", "443", "-h", "shirtgeklebt.net", "-nointeractive"])
                self.assertNotIn("https://shirtgeklebt.net", args)

    def test_all_menu_selection_keeps_nikto_optional(self):
        calls = []
        menu = {
            str(i): (f"tool{i}", lambda target, i=i: calls.append(i) or f"result{i}")
            for i in range(1, 10)
        }
        with patch.object(tools, "TOOLS_MENU", menu):
            with patch("builtins.input", return_value="a"):
                output = tools.interactive_tool_run("example.com")
            self.assertNotIn("TOOL6", output)
            self.assertEqual(calls, [1, 2, 3, 4, 5])
            calls.clear()
            with patch("builtins.input", return_value="n"):
                output = tools.interactive_tool_run("example.com")
            self.assertIn("TOOL6", output)
            self.assertEqual(calls, [1, 2, 3, 4, 5, 6])

    def test_nikto_module_present_skips_install(self):
        with patch.object(installer, 'nikto_module_available', return_value=True), \
             patch.object(installer, 'invoke') as invoke:
            self.assertTrue(installer.ensure_nikto_module('/opt/perl'))
            invoke.assert_not_called()

    def test_nikto_module_missing_installed_and_rechecked(self):
        with patch.object(installer, 'nikto_module_available', side_effect=[False, True]), \
             patch.object(installer, 'invoke', return_value=True) as invoke:
            self.assertTrue(installer.ensure_nikto_module('/opt/perl'))
            self.assertIn('XML::Writer', ' '.join(invoke.call_args.args[0]))
            self.assertEqual(invoke.call_args.kwargs['env']['PERL_MM_USE_DEFAULT'], '1')

    def test_nikto_module_install_failure_is_not_ready(self):
        with patch.object(installer, 'nikto_module_available', return_value=False), \
             patch.object(installer, 'invoke', return_value=False):
            self.assertFalse(installer.ensure_nikto_module('/opt/perl'))

    def test_nikto_startup_must_succeed_not_just_syntax(self):
        with patch.object(installer, 'ensure_source', return_value=True), \
             patch.object(installer, 'ensure_nikto_module', return_value=True), \
             patch.object(installer, 'invoke', side_effect=[True, False]) as invoke:
            self.assertFalse(installer.setup_nikto('/opt/perl'))
            self.assertEqual(invoke.call_count, 2)
            self.assertEqual(invoke.call_args.args[0][-1], '-Version')

    def test_official_nmap_download_url(self):
        page = '<a href="/dist/nmap-7.991-setup.exe">Nmap for Windows</a>'
        self.assertEqual(installer.official_nmap_installer_url(page),
                         'https://nmap.org/dist/nmap-7.991-setup.exe')
        with self.assertRaises(ValueError):
            installer.official_nmap_installer_url('No Windows setup links')

    def test_nmap_downloader_rejects_unofficial_domain(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                installer.fetch_official_exe('https://example.org/dist/nmap-7.991-setup.exe',
                                             Path(temp) / 'installer.exe')

    def test_official_sha256_verification(self):
        import hashlib
        import unittest.mock
        data = b'MZ' + b'example nmap installer fixture'
        sha = hashlib.sha256(data).hexdigest().upper()
        digest = 'nmap-7.991-setup.exe: SHA256 = ' + sha[:32] + '\n            ' + sha[32:] + '\nnmap-7.991-setup.exe: SHA384 = 00'
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n): return digest.encode()
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'installer.exe'
            file.write_bytes(data)
            with patch.object(installer, 'urlopen', return_value=Response()):
                self.assertTrue(installer.verify_nmap_sha256(file, 'https://nmap.org/dist/nmap-7.991-setup.exe'))
            file.write_bytes(data + b'tampered')
            with patch.object(installer, 'urlopen', return_value=Response()):
                self.assertFalse(installer.verify_nmap_sha256(file, 'https://nmap.org/dist/nmap-7.991-setup.exe'))

    def test_nmap_existing_install_does_not_download(self):
        with patch.object(installer, 'find_nmap', return_value='C:/Program Files/Nmap/nmap.exe'), \
             patch.object(installer, 'npcap_present', return_value=True), \
             patch.object(installer, 'fetch_nmap_installer_url') as download:
            self.assertTrue(installer.setup_nmap())
            download.assert_not_called()

    def test_web_url_validation(self):
        self.assertEqual(tools._web_target('https://example.org:8443/a'), 'https://example.org:8443/a')
        for target in ('http://example.org:99999/a', 'http://name:pwd@example.org/',
                       '192.0.2.0/24', '-sV'):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    tools._web_target(target)


    def test_native_setup_downloads_missing_but_keeps_installed(self):
        available = {"nuclei": "C:/tools/nuclei.exe"}
        def locate(name):
            return available.get(name)
        def download(name):
            available[name] = f"C:/PenX/vendor/bin/{name}.exe"
            return Path(available[name])
        with patch.object(installer, "find_native", side_effect=locate), \
             patch.object(installer, "download_verified_exe", side_effect=download) as fetch:
            result = installer.setup_native_scanners()
        self.assertEqual(result, {"nuclei": True, "httpx": True, "ffuf": True, "subfinder": True, "katana": True})
        self.assertEqual([call.args[0] for call in fetch.call_args_list], ["httpx", "ffuf", "subfinder", "katana"])

    def test_native_setup_refuses_failed_checksums_and_keeps_other_tools(self):
        available = {"httpx": "C:/tools/httpx.exe"}
        def locate(name):
            return available.get(name)
        def download(name):
            if name == "nuclei":
                raise ValueError("SHA256 verification failed")
            available[name] = f"C:/PenX/vendor/bin/{name}.exe"
            return Path(available[name])
        with patch.object(installer, "find_native", side_effect=locate), \
             patch.object(installer, "download_verified_exe", side_effect=download) as fetch:
            result = installer.setup_native_scanners()
        self.assertEqual(result, {"nuclei": False, "httpx": True, "ffuf": True, "subfinder": True, "katana": True})
        self.assertEqual([call.args[0] for call in fetch.call_args_list], ["nuclei", "ffuf", "subfinder", "katana"])

    def test_native_setup_does_not_redownload_present_scanners(self):
        with patch.object(installer, "find_native", side_effect=lambda name: f"C:/tools/{name}.exe"), \
             patch.object(installer, "download_verified_exe") as download:
            self.assertTrue(all(installer.setup_native_scanners().values()))
            download.assert_not_called()

    def test_bat_entry_installs_all_scanners_by_default_and_propagates_failures(self):
        with patch.object(installer, "setup_nmap", return_value=True), \
             patch.object(installer, "ensure_runtime", side_effect=["ruby", "perl"]), \
             patch.object(installer, "setup_whatweb", return_value=True), \
             patch.object(installer, "setup_nikto", return_value=True), \
             patch.object(installer, "nuclei_templates", return_value=Path("fixture/nuclei-templates")), \
             patch.object(installer, "setup_native_scanners", return_value={
                 "nuclei": True, "httpx": True, "ffuf": True, "subfinder": True, "katana": True,
             }) as native:
            self.assertEqual(installer.main([]), 0)
            native.assert_called_once_with()
        with patch.object(installer, "setup_nmap", return_value=True), \
             patch.object(installer, "ensure_runtime", side_effect=["ruby", "perl"]), \
             patch.object(installer, "setup_whatweb", return_value=True), \
             patch.object(installer, "setup_nikto", return_value=True), \
             patch.object(installer, "nuclei_templates", return_value=Path("fixture/nuclei-templates")), \
             patch.object(installer, "setup_native_scanners", return_value={
                 "nuclei": True, "httpx": False, "ffuf": True, "subfinder": True, "katana": True,
             }):
            self.assertEqual(installer.main([]), 1)

    def test_bat_reports_failed_template_install(self):
        with patch.object(installer, "setup_nmap", return_value=True), \
             patch.object(installer, "ensure_runtime", side_effect=["ruby", "perl"]), \
             patch.object(installer, "setup_whatweb", return_value=True), \
             patch.object(installer, "setup_nikto", return_value=True), \
             patch.object(installer, "setup_native_scanners", return_value={
                 "nuclei": True, "httpx": True, "ffuf": True, "subfinder": True, "katana": True,
             }), \
             patch.object(installer, "nuclei_templates", return_value=None), \
             patch.object(installer, "find_native", return_value="C:/PenX/nuclei.exe"), \
             patch.object(installer, "install_nuclei_templates", return_value=False) as update:
            self.assertEqual(installer.main([]), 1)
            update.assert_called_once()

    def test_skip_native_is_explicit_and_does_not_download(self):
        with patch.object(installer, "setup_nmap", return_value=True), \
             patch.object(installer, "ensure_runtime", side_effect=["ruby", "perl"]), \
             patch.object(installer, "setup_whatweb", return_value=True), \
             patch.object(installer, "setup_nikto", return_value=True), \
             patch.object(installer, "setup_native_scanners") as native:
            self.assertEqual(installer.main(["--skip-native"]), 0)
            native.assert_not_called()



if __name__ == '__main__':
    unittest.main(verbosity=2)
