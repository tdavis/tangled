"""
Tests for L{twisty.web.client.http}.


import os

from urlparse import urlparse

from twisted.web import server, static, client, error, util, resource
from twisted.internet import reactor, defer, interfaces
from twisted.python.filepath import FilePath
from twisted.protocols.policies import WrappingFactory
from twisted.test.proto_helpers import StringTransport

try:
    from twisted.internet import ssl
except:
    ssl = None
"""

from twisted.trial import unittest
from twisty.web.client.http import Uri



class UriTestCase(unittest.TestCase):
    """docstring for UriTestCase"""
    def test_setUri(self):
        """docstring for test_setUri"""
        uri = Uri('http://test.com')
        self.assertEquals(uri.url, 'http://test.com')
        self.assertEquals(uri.path, '/')
        self.assertEquals(uri.scheme, 'http')
        self.assertEquals(uri.port, 80)
        self.assertEquals(uri.netloc, 'test.com')
        self.assertEquals(uri.query, '')
        self.assertEquals(uri.fragment, '')
        uri.setUrl('http://test.com:88/path?arg=1')
        self.assertEquals(uri.url, 'http://test.com:88/path/')
    
