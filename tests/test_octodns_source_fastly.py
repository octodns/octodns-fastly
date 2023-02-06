from unittest import TestCase

from octodns_fastly import FastlyAcmeSource


class TestFastlyAcmeSource(TestCase):
    def test_init(self):
        source = FastlyAcmeSource("test")
        self.assertEqual(source.id, "test")
