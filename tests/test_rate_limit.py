import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api.rate_limit as rate_limit
from api.rate_limit import (
    RateLimitExceeded,
    check_and_register_request,
    release_audit_slot,
    try_acquire_audit_slot,
)


class TestPerIPRateLimit(unittest.TestCase):
    def setUp(self):
        # Isole chaque test : état interne du module remis à zéro plutôt
        # que de dépendre de l'ordre d'exécution des tests.
        rate_limit._request_log.clear()

    def test_requests_within_limit_are_accepted(self):
        for i in range(rate_limit.MAX_REQUESTS_PER_WINDOW):
            check_and_register_request("1.2.3.4", now=float(i))  # ne doit pas lever

    def test_request_exceeding_limit_is_rejected(self):
        for i in range(rate_limit.MAX_REQUESTS_PER_WINDOW):
            check_and_register_request("1.2.3.4", now=float(i))
        with self.assertRaises(RateLimitExceeded):
            check_and_register_request("1.2.3.4", now=float(rate_limit.MAX_REQUESTS_PER_WINDOW))

    def test_different_ips_are_independent(self):
        for i in range(rate_limit.MAX_REQUESTS_PER_WINDOW):
            check_and_register_request("1.2.3.4", now=float(i))
        # Une autre IP ne doit pas être affectée par la limite de la première.
        check_and_register_request("5.6.7.8", now=0.0)  # ne doit pas lever

    def test_old_requests_expire_out_of_the_sliding_window(self):
        for i in range(rate_limit.MAX_REQUESTS_PER_WINDOW):
            check_and_register_request("1.2.3.4", now=float(i))
        # Suffisamment de temps s'est écoulé : la fenêtre glissante doit
        # avoir purgé les anciennes requêtes, celle-ci doit passer.
        far_future = rate_limit.WINDOW_SECONDS + 100.0
        check_and_register_request("1.2.3.4", now=far_future)  # ne doit pas lever


class TestConcurrencyLimit(unittest.TestCase):
    def setUp(self):
        # Vide le sémaphore au cas où un test précédent aurait laissé des
        # slots non relâchés (robustesse de l'isolation des tests).
        while rate_limit.try_acquire_audit_slot():
            pass
        for _ in range(rate_limit.MAX_CONCURRENT_AUDITS):
            release_audit_slot()

    def test_acquires_up_to_max_concurrent(self):
        acquired = [try_acquire_audit_slot() for _ in range(rate_limit.MAX_CONCURRENT_AUDITS)]
        self.assertTrue(all(acquired))
        for _ in range(rate_limit.MAX_CONCURRENT_AUDITS):
            release_audit_slot()

    def test_exceeding_max_concurrent_returns_false_immediately(self):
        for _ in range(rate_limit.MAX_CONCURRENT_AUDITS):
            self.assertTrue(try_acquire_audit_slot())
        self.assertFalse(try_acquire_audit_slot())
        for _ in range(rate_limit.MAX_CONCURRENT_AUDITS):
            release_audit_slot()

    def test_release_frees_a_slot_for_reuse(self):
        for _ in range(rate_limit.MAX_CONCURRENT_AUDITS):
            self.assertTrue(try_acquire_audit_slot())
        self.assertFalse(try_acquire_audit_slot())
        release_audit_slot()
        self.assertTrue(try_acquire_audit_slot())  # le slot libéré redevient disponible
        # nettoyage
        for _ in range(rate_limit.MAX_CONCURRENT_AUDITS):
            release_audit_slot()


if __name__ == "__main__":
    unittest.main()
