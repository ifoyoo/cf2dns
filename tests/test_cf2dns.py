import ipaddress
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cf2dns


class TestRanges(unittest.TestCase):
    def test_parse_and_match(self):
        nets = cf2dns.parse_ranges("104.16.0.0/13\n")
        self.assertIsNotNone(nets)
        self.assertTrue(cf2dns.in_cloudflare("104.16.1.1", nets))
        self.assertFalse(cf2dns.in_cloudflare("8.8.8.8", nets))

    def test_invalid_ip(self):
        nets = cf2dns.parse_ranges("104.16.0.0/13\n")
        self.assertFalse(cf2dns.in_cloudflare("999.1.1.1", nets))


class TestDecision(unittest.TestCase):
    def setUp(self):
        self.config = {
            "probe": {"path": "/robots.txt", "timeout": 3, "attempts": 2},
            "fallback_ips": {"电信": "1.1.1.1"},
            "switch": {"rotate_after": 21600, "rotate_gain_ms": 25},
            "default_ip": "1.1.1.1",
        }
        self.nets = cf2dns.parse_ranges("104.16.0.0/13\n")
        self.spec = {"pool": "CT", "records": 1}

    def test_pool_order_is_used_for_fill(self):
        # Hostmonit 顺序是 slow 在前；即使本机探测 fast 更快，也按池内顺序补位。
        with patch.object(cf2dns, "probe_cached_many", side_effect=lambda ips, *_: {ip: (100 if ip == "104.16.0.1" else 1) for ip in ips}), patch.object(cf2dns, "probe_cached_one", return_value=(False, None)):
            targets, reason, mode, failed = cf2dns.decide_line(
                "电信", self.spec, self.config, {"CT": ["104.16.0.1", "104.16.0.2"]},
                self.nets, {}, "example.com", [], {}, allow_rotate=True, probe_cache={}
            )
        self.assertEqual(targets, ["104.16.0.1"])
        self.assertEqual(mode, "fill")

    def test_allow_rotate_false_keeps_healthy_current(self):
        with patch.object(cf2dns, "probe_cached_many", side_effect=lambda ips, *_: {ip: (100 if ip == "104.16.0.1" else 1) for ip in ips}), patch.object(cf2dns, "probe_cached_one", return_value=(False, None)):
            targets, reason, mode, failed = cf2dns.decide_line(
                "电信", self.spec, self.config, {"CT": ["104.16.0.2"]},
                self.nets, {}, "example.com", ["104.16.0.1"], {"last_change": 0},
                allow_rotate=False, probe_cache={}
            )
        self.assertEqual(targets, ["104.16.0.1"])
        self.assertEqual(mode, "keep")


class TestRecordOwnership(unittest.TestCase):
    def test_apply_line_skips_unmanaged_records(self):
        records = [{"Line": "电信", "Type": "A", "Value": "1.1.1.1", "RecordId": 1, "Remark": "manual"}]
        with patch.object(cf2dns, "call_dnspod_api") as api:
            changed, note = cf2dns.apply_line({"domain": "example.com", "subdomain": "@"}, records, "电信", ["104.16.0.1"], 600)
        self.assertFalse(changed)
        self.assertIn("未标记", note)
        api.assert_not_called()


class TestRunSyncHeartbeat(unittest.TestCase):
    def setUp(self):
        self.config = {
            "domain": "example.com",
            "ttl": 600,
            "lines": {"电信": {"pool": "CT", "records": 1}},
            "probe": {"path": "/robots.txt", "timeout": 3, "attempts": 2},
            "fallback_ips": {"电信": "1.1.1.1"},
            "switch": {"rotate_after": 21600, "rotate_gain_ms": 25},
            "blacklist_fail_threshold": 2,
            "blacklist_ttl": 21600,
            "heartbeat_url": "https://example.com/api/cf2dns",
            "heartbeat_token": "token",
        }

    def test_origin_down_still_reports_heartbeat(self):
        with patch.object(cf2dns, "load_json", side_effect=lambda *_: {}), \
             patch.object(cf2dns, "save_json"), \
             patch.object(cf2dns, "maybe_alert"), \
             patch.object(cf2dns, "fetch_heartbeat", return_value={}), \
             patch.object(cf2dns, "acquire_lease", return_value={"acquired": True, "generation": 1}), \
             patch.object(cf2dns, "cloudflare_networks", return_value=[]), \
             patch.object(cf2dns, "fetch_pool", return_value={}), \
             patch.object(cf2dns, "call_dnspod_api", return_value={"RecordList": []}), \
             patch.object(cf2dns, "decide_line", return_value=(None, "dead", "dead", [])), \
             patch.object(cf2dns, "report_heartbeat") as heartbeat:
            code = cf2dns.run_sync(self.config, node_id="vps")
        self.assertEqual(code, 0)
        heartbeat.assert_called_once()
        self.assertEqual(heartbeat.call_args.kwargs["status"], "origin-down")

    def test_no_lease_does_not_write_dns(self):
        with patch.object(cf2dns, "load_json", side_effect=lambda *_: {}), \
             patch.object(cf2dns, "save_json"), \
             patch.object(cf2dns, "maybe_alert"), \
             patch.object(cf2dns, "fetch_heartbeat", return_value={}), \
             patch.object(cf2dns, "acquire_lease", return_value={"ok": True, "acquired": False, "owner": "gha"}), \
             patch.object(cf2dns, "call_dnspod_api") as api, \
             patch.object(cf2dns, "report_heartbeat"):
            code = cf2dns.run_sync(self.config, node_id="vps")
        self.assertEqual(code, 0)
        api.assert_not_called()


class TestFailoverSafety(unittest.TestCase):
    def test_heartbeat_unreachable_does_not_take_over(self):
        with patch.object(cf2dns, "fetch_heartbeat", return_value=None):
            self.assertFalse(cf2dns.check_failover({}, "gha"))

    def test_active_vps_lease_blocks_gha_even_if_stale(self):
        data = {
            "ok": True,
            "is_stale": True,
            "owner": "vps",
            "lease_active": True,
            "node_id": "vps",
            "lease_until": 9_999_999_999_999,
        }
        with patch.object(cf2dns, "fetch_heartbeat", return_value=data):
            self.assertFalse(cf2dns.check_failover({}, "gha"))

    def test_no_lease_and_stale_allows_takeover(self):
        data = {
            "ok": True,
            "is_stale": True,
            "owner": None,
            "lease_active": False,
            "node_id": "vps",
        }
        with patch.object(cf2dns, "fetch_heartbeat", return_value=data):
            self.assertTrue(cf2dns.check_failover({}, "gha"))

    def test_vps_recovery_releases_gha_lease(self):
        data = {
            "ok": True,
            "is_stale": False,
            "owner": "gha",
            "lease_active": True,
            "node_id": "vps",
        }
        with patch.object(cf2dns, "fetch_heartbeat", return_value=data), patch.object(cf2dns, "release_lease") as release:
            self.assertFalse(cf2dns.check_failover({}, "gha"))
        release.assert_called_once()


if __name__ == "__main__":
    unittest.main()
