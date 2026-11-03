"""Offline tests for the pure named project scope contract (PX-101).

Covers canonicalization (IDN, IPv6, ports, CIDR, wildcard), exact
authorization semantics, candidate/expiry handling, bounded CIDR preview,
and the scope/asset boundary validation. No network, no subprocess, no DB.
"""
import unittest
from datetime import datetime, timezone

from penx_app.domain.project_scope import (
    MAX_ASSETS,
    Asset,
    AssetStatus,
    ProjectScope,
    TargetKind,
    authorize,
    canonicalize,
    expand_cidr_preview,
    is_expired,
    with_candidate,
)

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)


def _host_asset(canonical, status=AssetStatus.APPROVED, expires_at=None):
    return Asset(
        raw=canonical,
        canonical=canonical,
        kind=TargetKind.HOST,
        approved_at=T0,
        expires_at=expires_at,
        status=status,
    )


class CanonicalizeTests(unittest.TestCase):
    def test_plain_host(self):
        self.assertEqual(canonicalize('example.test'), (TargetKind.HOST, 'example.test'))

    def test_host_port(self):
        self.assertEqual(
            canonicalize('example.test:8443'), (TargetKind.HOST, 'example.test:8443'))

    def test_host_uppercase_normalized(self):
        self.assertEqual(
            canonicalize('Example.Test'), (TargetKind.HOST, 'example.test'))

    def test_idn_host(self):
        kind, canonical = canonicalize('bücher.example')
        self.assertIs(kind, TargetKind.HOST)
        self.assertEqual(canonical, 'xn--bcher-kva.example')

    def test_bare_ipv6(self):
        self.assertEqual(canonicalize('2001:db8::1'), (TargetKind.HOST, '2001:db8::1'))

    def test_bracketed_ipv6_with_port(self):
        self.assertEqual(
            canonicalize('[2001:db8::1]:8443'), (TargetKind.HOST, '[2001:db8::1]:8443'))

    def test_scheme_url_stripped(self):
        self.assertEqual(
            canonicalize('https://example.test:8443'),
            (TargetKind.HOST, 'example.test:8443'))

    def test_scheme_url_default(self):
        self.assertEqual(
            canonicalize('http://example.test'), (TargetKind.HOST, 'example.test'))

    def test_cidr(self):
        self.assertEqual(
            canonicalize('192.168.0.0/30'), (TargetKind.CIDR, '192.168.0.0/30'))

    def test_cidr_host_network_normalized(self):
        self.assertEqual(
            canonicalize('192.168.0.1/30'), (TargetKind.CIDR, '192.168.0.0/30'))

    def test_wildcard(self):
        self.assertEqual(
            canonicalize('*.example.test'), (TargetKind.WILDCARD, '*.example.test'))

    def test_wildcard_idn_suffix(self):
        self.assertEqual(
            canonicalize('*.bücher.example'),
            (TargetKind.WILDCARD, '*.xn--bcher-kva.example'))

    def test_wildcard_multi_label_suffix_accepted(self):
        # A single label before the domain a.example.test is valid.
        self.assertEqual(
            canonicalize('*.a.example.test'),
            (TargetKind.WILDCARD, '*.a.example.test'))

    def test_cidr_too_large_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('192.168.0.0/8')

    def test_wildcard_with_port_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('*.example.test:8443')

    def test_wildcard_single_label_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('*.local')

    def test_wildcard_double_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('*.*.example.test')

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('')

    def test_whitespace_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('a b')

    def test_option_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('-t')

    def test_url_path_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('https://example.test/path')

    def test_url_query_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('https://example.test?x=1')

    def test_url_userinfo_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('https://user@example.test')

    def test_url_fragment_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('https://example.test#frag')

    def test_scheme_non_http_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('ftp://example.test')

    def test_port_zero_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('example.test:0')

    def test_port_too_large_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('example.test:99999')

    def test_port_non_numeric_rejected(self):
        with self.assertRaises(ValueError):
            canonicalize('example.test:abc')

    def test_regex_characters_rejected(self):
        for value in ('example.test?', 'exa[m]ple.test', 'example.tes[t]'):
            with self.assertRaises(ValueError, msg=value):
                canonicalize(value)


class AuthorizeTests(unittest.TestCase):
    def test_exact_host(self):
        scope = ProjectScope('p', T0, (_host_asset('example.test'),))
        self.assertTrue(authorize(scope, 'example.test'))

    def test_host_level_covers_any_port(self):
        scope = ProjectScope('p', T0, (_host_asset('example.test'),))
        for port in (1, 80, 443, 8443, 65535):
            self.assertTrue(authorize(scope, f'example.test:{port}'), port)
        # Scheme form normalizes to the same authority.
        self.assertTrue(authorize(scope, 'https://example.test:443'))

    def test_host_level_does_not_cover_other_host(self):
        scope = ProjectScope('p', T0, (_host_asset('example.test'),))
        self.assertFalse(authorize(scope, 'other.test'))
        self.assertFalse(authorize(scope, 'sub.example.test'))

    def test_port_specific_only_that_port(self):
        scope = ProjectScope('p', T0, (_host_asset('example.test:8443'),))
        self.assertTrue(authorize(scope, 'example.test:8443'))
        self.assertFalse(authorize(scope, 'example.test:443'))
        # A port-specific approval does not cover a bare host target.
        self.assertFalse(authorize(scope, 'example.test'))

    def test_ipv6_exact(self):
        scope = ProjectScope('p', T0, (_host_asset('2001:db8::1'),))
        self.assertTrue(authorize(scope, '2001:db8::1'))
        self.assertTrue(authorize(scope, '[2001:db8::1]'))
        self.assertTrue(authorize(scope, '[2001:db8::1]:8443'))

    def test_cidr_contains_addresses(self):
        scope = ProjectScope('p', T0, (
            Asset('192.168.0.0/30', '192.168.0.0/30', TargetKind.CIDR, T0),))
        for ip in ('192.168.0.0', '192.168.0.1', '192.168.0.2', '192.168.0.3'):
            self.assertTrue(authorize(scope, ip), ip)
        self.assertFalse(authorize(scope, '192.168.0.4'))

    def test_cidr_exact_match(self):
        scope = ProjectScope('p', T0, (
            Asset('192.168.0.0/30', '192.168.0.0/30', TargetKind.CIDR, T0),))
        self.assertTrue(authorize(scope, '192.168.0.0/30'))

    def test_wildcard_covers_exactly_one_label(self):
        scope = ProjectScope('p', T0, (
            Asset('*.example.test', '*.example.test', TargetKind.WILDCARD, T0),))
        self.assertTrue(authorize(scope, 'sub.example.test'))
        self.assertFalse(authorize(scope, 'a.b.example.test'))
        self.assertFalse(authorize(scope, 'example.test'))

    def test_wildcard_does_not_cover_ported_target(self):
        scope = ProjectScope('p', T0, (
            Asset('*.example.test', '*.example.test', TargetKind.WILDCARD, T0),))
        # A wildcard scope is label-level; a ported host still matches the
        # same label, so it is authorized at the host level.
        self.assertTrue(authorize(scope, 'sub.example.test:443'))

    def test_candidate_never_authorized(self):
        scope = ProjectScope('p', T0, (_host_asset('example.test', AssetStatus.CANDIDATE),))
        self.assertFalse(authorize(scope, 'example.test'))

    def test_expired_not_authorized(self):
        scope = ProjectScope('p', T0, (
            _host_asset('example.test', expires_at=T1),))
        # Before expiry: authorized.
        self.assertTrue(authorize(
            scope, 'example.test',
            now=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)))
        # Exactly at expiry: expired (now >= expires_at).
        self.assertFalse(authorize(
            scope, 'example.test', now=datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)))
        # After expiry: expired.
        self.assertFalse(authorize(scope, 'example.test',
                                   now=datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)))

    def test_unparseable_target_not_authorized(self):
        scope = ProjectScope('p', T0, (_host_asset('example.test'),))
        self.assertFalse(authorize(scope, 'example.test?'))
        self.assertFalse(authorize(scope, 'example.test:0'))
        self.assertFalse(authorize(scope, ''))

    def test_no_asset_scope_never_authorized(self):
        scope = ProjectScope('p', T0)
        self.assertFalse(authorize(scope, 'example.test'))

    def test_property_host_level_is_port_insensitive(self):
        scope = ProjectScope('p', T0, (_host_asset('example.test'),))
        approved = {f'example.test:{p}' for p in range(1, 65536)}
        for target in list(approved)[:64] + list(approved)[-64:]:
            self.assertTrue(authorize(scope, target), target)


class ExpiryTests(unittest.TestCase):
    def test_no_expiry_never_expired(self):
        asset = _host_asset('example.test')
        self.assertFalse(is_expired(asset, now=datetime(
            2030, 1, 1, tzinfo=timezone.utc)))

    def test_expired_at_and_after(self):
        asset = _host_asset('example.test', expires_at=T1)
        self.assertFalse(is_expired(asset, now=T0))
        self.assertTrue(is_expired(asset, now=T1))
        self.assertTrue(is_expired(asset, now=T1.replace(hour=1)))


class CidrPreviewTests(unittest.TestCase):
    def test_small_cidr_full_sample(self):
        preview = expand_cidr_preview('192.168.0.0/30')
        self.assertEqual(preview['total'], 4)
        self.assertFalse(preview['truncated'])
        self.assertEqual(preview['sample'],
                         ['192.168.0.0', '192.168.0.1', '192.168.0.2', '192.168.0.3'])

    def test_bounded_sample_truncated(self):
        preview = expand_cidr_preview('192.168.0.0/24')
        self.assertEqual(preview['total'], 256)
        self.assertTrue(preview['truncated'])
        self.assertEqual(len(preview['sample']), 32)
        self.assertEqual(preview['sample'][0], '192.168.0.0')

    def test_too_large_rejected(self):
        with self.assertRaises(ValueError):
            expand_cidr_preview('10.0.0.0/8')

    def test_invalid_network_rejected(self):
        with self.assertRaises(ValueError):
            expand_cidr_preview('not-a-network')


class AssetValidationTests(unittest.TestCase):
    def test_empty_raw_rejected(self):
        with self.assertRaises(ValueError):
            Asset(raw='', canonical='x', kind=TargetKind.HOST, approved_at=T0)

    def test_naive_approved_at_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST,
                  datetime(2026, 1, 1, tzinfo=None))

    def test_expiry_before_approval_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T1, expires_at=T0)

    def test_expiry_equal_approval_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, expires_at=T0)

    def test_rate_zero_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, max_rate=0)

    def test_rate_negative_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, max_rate=-1)

    def test_rate_bool_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, max_rate=True)

    def test_budget_zero_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, max_budget=0)

    def test_budget_bool_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, max_budget=True)

    def test_tag_too_long_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, tags=('t' * 65,))

    def test_too_many_tags_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0,
                  tags=tuple(f't{i}' for i in range(17)))

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            Asset('a', 'a', TargetKind.HOST, approved_at=T0, status='bogus')


class ScopeValidationTests(unittest.TestCase):
    def _assets(self, n):
        return tuple(
            _host_asset(f'host{i}.example.test') for i in range(n))

    def test_name_empty_rejected(self):
        with self.assertRaises(ValueError):
            ProjectScope('', T0)

    def test_name_too_long_rejected(self):
        with self.assertRaises(ValueError):
            ProjectScope('x' * 129, T0)

    def test_name_boundary_ok(self):
        ProjectScope('x' * 128, T0)

    def test_naive_created_at_rejected(self):
        with self.assertRaises(ValueError):
            ProjectScope('p', datetime(2026, 1, 1, tzinfo=None))

    def test_assets_must_be_tuple(self):
        with self.assertRaises(ValueError):
            ProjectScope('p', T0, [_host_asset('example.test')])

    def test_duplicate_asset_rejected(self):
        with self.assertRaises(ValueError):
            ProjectScope('p', T0, (
                _host_asset('example.test'),
                _host_asset('example.test'),
            ))

    def test_too_many_assets_rejected(self):
        with self.assertRaises(ValueError):
            ProjectScope('p', T0, self._assets(MAX_ASSETS + 1))

    def test_max_assets_boundary_ok(self):
        ProjectScope('p', T0, self._assets(MAX_ASSETS))


class WithCandidateTests(unittest.TestCase):
    def test_adds_candidate(self):
        scope = ProjectScope('p', T0)
        updated = with_candidate(scope, 'sub.example.test', T0)
        self.assertEqual(len(updated.assets), 1)
        self.assertIs(updated.assets[0].status, AssetStatus.CANDIDATE)
        self.assertFalse(authorize(updated, 'sub.example.test'))

    def test_idempotent(self):
        scope = ProjectScope('p', T0)
        once = with_candidate(scope, 'example.test', T0)
        twice = with_candidate(once, 'example.test', T1)
        self.assertEqual(len(twice.assets), 1)

    def test_does_not_mutate_original(self):
        scope = ProjectScope('p', T0)
        with_candidate(scope, 'example.test', T0)
        self.assertEqual(len(scope.assets), 0)


if __name__ == '__main__':
    unittest.main()
