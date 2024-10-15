import unittest
import os

class Testsuite(unittest.TestCase):
    def test_database_exists(client):
        client.assertTrue(os.path.isfile('totally_not_my_privateKeys.db'))