from unittest import TestCase
from unittest.mock import patch

from octodns.zone import Zone

from octodns_fastly import FastlyAcmeSource


class TestFastlyAcmeSource(TestCase):
    def test_init(self):
        source = FastlyAcmeSource("test")
        self.assertEqual(source.id, "test")
