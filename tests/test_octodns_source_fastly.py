from unittest import TestCase
from unittest.mock import patch

from octodns_fastly import FastlyAcmeSource
from octodns.zone import Zone


class TestFastlyAcmeSource(TestCase):
    def test_init(self):
        source = FastlyAcmeSource("test")
        self.assertEqual(source.id, "test")
