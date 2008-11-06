import urlparse, logging, os

from tangled.web.client.util import WWWInsensitiveDefaultDict
from tangled.web.client.protocol import SimpleStringReader, SimpleStringWriter

from twisted.python.failure import Failure

from twisted.internet import reactor
from twisted.internet.main import CONNECTION_DONE, CONNECTION_LOST
from twisted.internet.protocol import ClientCreator
from twisted.internet.defer import Deferred, DeferredQueue

from twisted.protocols.policies import TimeoutMixin

from twisted.web.http import MOVED_PERMANENTLY, FOUND

from twisted.web2.responsecode import BAD_REQUEST, HTTP_VERSION_NOT_SUPPORTED, OK
from twisted.web2.http import parseVersion
from twisted.web2.http_headers import Headers
from twisted.web2.channel.http import HTTPParser, PERSIST_NO_PIPELINE, PERSIST_PIPELINE
from twisted.web2.client.http import EmptyHTTPClientManager, HTTPClientProtocol as HTTPClientProtocol_web2

class ProtocolError(Exception):
    """
    Exception raised when a HTTP error happened.
    """


class RedirectLimitExceededError(Exception):
    """
    Exception raised when there have been too many redirects for a 
    specific request.
    """
    def __init__(self, url):
        """docstring for __init__"""
        message = "Too many redirects for the URL starting at '%s'" % url
        super(RedirectLimitExceededError, self).__init__(message)


class PendingChannel(object):
    """
    A dummy `Pending Channel` which are used to make sure queuing is
    done accurately.
    """
    host = None
    readPersistent = PERSIST_NO_PIPELINE


class Uri(object):
    def __init__(self, url):
        """
        Sets the url and url parts for this L{Uri}
        
        @param url: The URL
        @type url: C{str}
        """
        self.setUrl(url)
    
    def setUrl(self, url):
        """
        Sets the full URL to the provided string after defragging
        
        @param url: The URL
        @type url: C{str}
        """
        self.url = urlparse.urldefrag(url.strip())[0]
        self.__setParts()
    
    def __setParts(self):
        """
        Sets all URL parts, providing sensible defaults.
        
        Not a user function.
        """
        parts = self.getRawParts()
        self.scheme = parts.scheme or 'http'
        self.path = parts.path or '/'
        self.port = parts.port or 80
        self.netloc, self.query, self.fragment = parts.netloc, parts.query, parts.fragment
        self.hostname = self.netloc
    
    def getDomainUrl(self):
        """
        Returns the URL to the domain of this Uri
        """
        return self.scheme + '://' + self.netloc + '/'
    
    def getRobotsUrl(self):
        """
        Returns the I{robots.txt} URL for this Uri
        """
        return self.getDomainUrl() + 'robots.txt'
    
    def getHash(self):
        """
        Returns a hash of our URL, adding some normalization
        """
        url = self.url
        if url[-1] == '/':
            url = url[0:-1]
        # technically, www/non-www can be different, but this is never the 
        # case
        shash = hash(url.replace('www.', ''))
        return shash
        
    def getHost(self):
        return self.netloc.lower().replace('www.','')
    
    def getRawParts(self):
        """
        Returns the raw `parts` of our URL
        """
        return urlparse.urlsplit(self.url)
        
    def getRequestLocation(self):
        loc = '?'.join((self.path,self.query))
        if loc.endswith('?'):
            loc = loc[:-1]
        return loc.replace(' ', '%20')
    
    def join(self, uri):
        """
        Returns supplied url joined with ours
        
        @param url: the URL to join
        @type url: L{Uri}
        
        @returns resulting L{Uri}
        """
        newUrl = urlparse.urljoin(self.url, uri.url)
        return Uri(newUrl)
    
    def isSameDomain(self, uri):
        """
        Checks if the supplied URI has the same domain as ours
        
        @param uri: the URI to join
        @type uri: L{Uri}
        
        @returns C{bool}
        """
        result = False
        if uri != None:
            # Match base urls, most of the time we should get if they are from same domain here
            result = (self.domainUrl.lower() == uri.domainUrl.lower())                
        return result
    
    def isHostScope(self, uri):
        """
        Checks if the supplied URI is within the same host. Keep in mind
        that the result of a I{join} on the URIs is also checked, under
        the possibility that it's a relative URL on the same domain.
        
        @param uri: the URI to check
        @type uri: L{Uri}
        
        @returns C{bool}
        """
        if self.isSameDomain(uri) or self.join(uri).isSameDomain(self):
            return True
        return False
    
    def isDomainScope(self, uri):
        """
        Checks if the supplied URI has the same domain scope as ours
        
        @param uri: the URI to check
        @type uri: L{Uri}
        
        @returns C{bool}
        """
        result = False
        if uri:
            # media.archive.org should give archive.org
            d1 = self.hostname.replace('www', '')
            d2 = d1.split('.')
            # Base domain is entire domain without www.
            baseDomain = d1
            # audio.archive.org
            # NOTE: hostname can be None http://docs.python.org/lib/module-urlparse.html
            otherDomain = uri.hostname and uri.hostname or ''
            # audio.archive.org is a sub-domain of archive.org?
            result = otherDomain.endswith(baseDomain)
        return result
    
    def isPathScope(self, uri):
        """
        Checks if the supplied URI has the same path scope as ours
        
        @param uri: the URI to check
        @type uri: L{Uri}
        
        @returns C{bool}
        """
        result = False
        if uri:
            # http://members.aol.com/~bigbird/ should give members.aol.com/~bigbird
            basePath = self.netloc + os.path.split(self.path)[0]
            # http://members.aol.com/~bigbird/profile should give members.aol.com/~bigbird/profile
            otherPath = uri.netloc + uri.path
            # members.aol.com/~bigbird/profile comes from same folder as members.aol.com/~bigbird ?
            result = otherPath.startswith(basePath)
        return result
    
    def __str__(self):
        return self.url
    
    def __hash__(self):
        return self.getHash()
    
    domainUrl = property(fget=getDomainUrl)
    robotsUrl = property(fget=getRobotsUrl)
    urlHash = property(fget=getHash)


class Response(object):
    """
    An object representing an HTTP Response to be sent to the client.
    """
    
    code = OK
    headers = None
    protocol = None
    request = None
    
    def __init__(self, code=None, headers=None, data=None):
        """
        @param code: The HTTP status code for this Response
        @type code: C{int}
        
        @param headers: Headers to be sent to the client.
        @type headers: C{dict}, L{twisted.web2.http_headers.Headers}, or 
            C{None}
        
        @param data: Content body received
        @type data: C{str} or similar
        """
        
        if code is not None:
            self.code = int(code)
            
        if headers is not None:
            if isinstance(headers, dict):
                headers = Headers(headers)
            self.headers=headers
        else:
            self.headers = Headers()
            
        self.data = data
        
    def __repr__(self):
        datalen = len(self.data)
        
        return "<%s.%s code=%d, datalen=%s>" % (self.__module__, self.__class__.__name__, self.code, datalen)
    


class ClientRequest(object):
    """
    A class for describing an HTTP request to be sent to the server.
    """
    numRedirects = 0
    redirects = []
    retries = 0
    
    def __init__(self, method, uri, protocol, headers=None, closeAfter=True):
        """
        @param method: The HTTP method to for this request, ex: 'GET', 'HEAD',
            'POST', etc.
        @type method: C{str}
        
        @param uri: The URI of the resource to request, this may be absolute or
            relative, however the interpretation of this URI is left up to the
            remote server.
        @type uri: C{str}
        
        @param headers: Headers to be sent to the server.  It is important to
            note that this object does not create any implicit headers.  So it
            is up to the HTTP Client to add required headers such as 'Host'.
        @type headers: C{dict}, L{twisted.web2.http_headers.Headers}, or
            C{None}
            
        @param protocol: Protocol to manage writing request data and reading
            response data
        @type protocol: L{twisted.internet.protocol.Protocol} derivative
        
        @param protocol: Indicates that we would like the connection to be
            closed following this request.
        @type protocol: C{bool}
        """
        
        self.method = method
        self.uri = uri
        self.closeAfter = closeAfter
        if isinstance(headers, Headers):
            self.headers = headers
        else:
            self.headers = Headers(headers or {})
            
        if protocol is not None:
            self.protocol = protocol
        else:
            raise RuntimeError("You must provide a protocol for the request!")
            
    def redirect(self, location):
        """docstring for redirect"""
        curHost = self.uri.getHost()
        self.redirects.append(self.uri)
        self.uri.setUrl(location)
        if not self.uri.netloc:
            self.uri.netloc, self.uri.hostname = (curHost, curHost)
        self.numRedirects += 1
    


class HTTPClientChannelRequest(HTTPParser):
    parseCloseAsEnd = True
    outgoing_version = "HTTP/1.1"
    chunkedOut = False
    finished = False
    autoRedirect = True
    closeAfter = False
    userAgent = 'TwistedClient'
    code = 0
    
    def __init__(self, channel, request, closeAfter):
        HTTPParser.__init__(self, channel)
        self.request = request
        self.closeAfter = closeAfter
        self.transport = self.channel.transport
        self.outHeaders = Headers({})
    
    def submit(self):
        request = self.request
        if request.method == "HEAD":
            # No incoming data will arrive.
            self.length = 0
        path = request.uri.getRequestLocation()
        l = '%s %s %s\r\n' % (request.method, path,
                                   self.outgoing_version)
        self.transport.write(l)
        
        self.sendHeader('Host', request.uri.netloc)
        self.sendHeader('User-Agent', self.userAgent)
        
        if request.headers is not None:
            for name, valuelist in request.headers.getAllRawHeaders():
                for value in valuelist:
                    self.sendHeader(name, value)
                    
        if hasattr(request, 'contentLength'):
            if request.protocol.contentLength() is not None:
                self.sendHeader('Content-Length', request.protocol.contentLength())
                # l.append("%s: %s\r\n" % ('Content-Length', request.protocol.contentLength()))
            else:
                # Got a stream with no length. Send as chunked and hope, against
                # the odds, that the server actually supports chunked uploads.
                self.sendHeader('Transfer-Encoding', 'chunked')
                # l.append("%s: %s\r\n" % ('Transfer-Encoding', 'chunked'))
                self.chunkedOut = True
                
        if self.closeAfter:
            self.sendHeader('Connection', 'close')
            # l.append("%s: %s\r\n" % ('Connection', 'close'))
        else:            
            self.sendHeader('Connection', 'Keep-Alive')
            # l.append("%s: %s\r\n" % ('Connection', 'Keep-Alive'))
        
        self.sendHeader('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        self.sendHeader('Accept-charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
        self.sendHeader('Cache-Control', 'max-age=0')
        
        self.transport.write("\r\n")
        request.protocol.makeConnection(self)
    
    def sendHeader(self, name, value):
        self.outHeaders.addRawHeader(name, value)
        self.transport.write('%s: %s\r\n' % (name, value))
    
    def registerProducer(self, producer, streaming):
        """
        Register a producer.
        """
        self.transport.registerProducer(producer, streaming)
    
    def unregisterProducer(self):
        self.transport.unregisterProducer()
    
    def write(self, data):
        if not data:
            return
        elif self.chunkedOut:
            self.transport.writeSequence(("%X\r\n" % len(data), data, "\r\n"))
        else:
            self.transport.write(data)
    
    def loseConnection(self):
        """
        We are finished writing data.
        """
        if self.chunkedOut:
            # write last chunk and closing CRLF
            self.transport.write("0\r\n\r\n")
            
        self.finished = True
        self.channel.requestWriteFinished(self)
        del self.transport
    
    def _error(self, err):
        """
        Abort parsing, and depending of the status of the request, either fire
        the C{responseDefer} if no response has been sent yet, or close the
        stream.
        """
        self.abortParse()
        if hasattr(self, 'request') and self.request.protocol is not None:
            self.request.protocol.connectionLost(Failure(CONNECTION_LOST))
        else:
            self.responseDefer.errback(err)
    
    def _abortWithError(self, errcode, text):
        """
        Abort parsing by forwarding a C{ProtocolError} to C{_error}.
        """
        self._error(ProtocolError(text))
    
    def connectionLost(self, reason):
        self._error(reason)
    
    def gotInitialLine(self, initialLine):
        parts = initialLine.split(' ', 2)
        # Parse the initial request line
        if len(parts) != 3:
            self._abortWithError(BAD_REQUEST,
                                 "Bad response line: %s" % (initialLine,))
            return
            
        strversion, self.code, message = parts
        
        try:
            protovers = parseVersion(strversion)
            if protovers[0] != 'http':
                raise ValueError()
        except ValueError:
            self._abortWithError(BAD_REQUEST,
                                 "Unknown protocol: %s" % (strversion,))
            return
            
        self.version = protovers[1:3]
        
        # Ensure HTTP 0 or HTTP 1.
        if self.version[0] != 1:
            self._abortWithError(HTTP_VERSION_NOT_SUPPORTED,
                                 'Only HTTP 1.x is supported.')
            return
    
    ## FIXME: Actually creates Response, function is badly named!
    def createRequest(self):
        pass
    
    def createResponse(self, data):
        r = Response(code=self.code, headers=self.getHeaders(), data=data)
        r.request = self.request
        return r
    
    ## FIXME: Actually processes Response, function is badly named!
    def processRequest(self):
        pass
    
    def handleContentChunk(self, data):
        self.request.protocol.dataReceived(data)
    
    def handleContentComplete(self):
        self.request.protocol.connectionLost(Failure(CONNECTION_DONE))
    
    def getHeaders(self):
        return self.inHeaders
    


class HTTPClientProtocol(HTTPClientProtocol_web2):
    
    host = ''
    
    def submitRequest(self, request, closeAfter=True):
        """
        @param request: The request to send to a remote server.
        @type request: L{ClientRequest}
        
        @param closeAfter: If True the 'Connection: close' header will be sent,
            otherwise 'Connection: keep-alive'
        @type closeAfter: C{bool}
        
        @rtype: L{twisted.internet.defer.Deferred}
        @return: A Deferred which will be called back with the
            L{twisted.web2.http.Response} from the server.
        """
        
        # Assert we're in a valid state to submit more
        assert self.outRequest is None
        assert ((self.readPersistent is PERSIST_NO_PIPELINE
                 and not self.inRequests)
                or self.readPersistent is PERSIST_PIPELINE), (self, request.uri.url, closeAfter, request.closeAfter)
                
        self.manager.clientBusy(self)
        if closeAfter:
            self.readPersistent = False
            
        self.outRequest = chanRequest = HTTPClientChannelRequest(self,
                                            request, closeAfter)
        self.inRequests.append(chanRequest)
        
        chanRequest.submit()
    


class HTTPClientChannelManager(EmptyHTTPClientManager):
    """
    TODO
    """
    queue = None
    openChannels = set()
    pendingChannels = set()
    persistQueueThreshold = 5
    clientIdleTimeout = 25
    agent = None
    maxRedirects = 5
    stopping = False
    
    clientChannel = HTTPClientProtocol
    clientChannelRequest = HTTPClientChannelRequest
    
    def __init__(self, maxQueued=None, maxBacklog=None, maxConcurrent=15):
        """docstring for __init__"""
        self.maxQueued = maxQueued
        self.maxBacklog = maxBacklog
        self.maxConcurrent = maxConcurrent
        self.resetQueue()
    
    def runCount(self):
        """
        Gets the number of 'running' requests which pending requests are
        considered to be as well.
        """
        return len(self.openChannels.union(self.pendingChannels))
    
    def queueCount(self, host=None):
        """
        Get the number of queued requests for a host.
        
        @type host: C{str}
        @param host: An HTTP Host, i.e. I{example.com}
        
        @return: Number of queued requests as an C{int}
        """
        if host:
            return len(self.queue[host].pending)
        else:
            return reduce(lambda cum,q: cum+len(q.pending), self.queue.values(), 0)
    
    def shouldQueue(self, request):
        """
        Determines if a request should be queued or made immediately.
        
        A Request should be queued for the following reasons:
        
            1.  If PERSISTENT and no channel accepting requests
            2.  If C{maxConcurrent} reached
            
        C{persistQueueThreshold}
        
        @type request: C{str}
        @param request: L{ClientRequest}
        """
        allChannels = self.openChannels.union(self.pendingChannels)
        if self.runCount() >= self.maxConcurrent:
            return True
        # Connection will persist
        if not request.closeAfter:
            pCount = 0
            for chan in allChannels:
                if chan.host == request.uri.getHost() and chan.readPersistent:
                    pCount += 1
            # Max concurrent persistent connections for host met
            if pCount >= 2:
                # Set to non-persist if threshold met
                if (self.persistQueueThreshold != 0 and
                self.queueCount(request.uri.getHost()) >=
                self.persistQueueThreshold):
                    request.closeAfter = True
                    return False
                else:
                    return True
        return False
    
    def resetQueue(self, host=None):
        """
        Resets a queue of requests.
        
        @type host: c{str}
        @param host: An option host queue to reset. If no host is provided
            the entire queue is reset.
        """
        def dq(): return DeferredQueue(self.maxQueued, self.maxBacklog)
        if not host:
            self.queue = WWWInsensitiveDefaultDict(dq)
        else:
            self.queue[host] = dq()
    
    def rotateQueue(self, host=None):
        """
        Queued requests can be 'forgotten' if requests for a host do not
        finish properly. When this happens the queues need to be rotated
        such that requests are forced into 'open' mode.
        
        @type host: c{str}
        @param host: An optional host queue to rotate. If no host is
            provided all queues are rotated.
        
        """
        def rotateThese(hosts):
            maxRunnable = self.maxConcurrent - self.runCount()
            if maxRunnable <= 0: return False
            rotated = False            
            for host in hosts:
                host = host.replace('www.','').strip()
                for x in xrange(0, len(self.queue[host].pending)):
                    if maxRunnable > 0:
                        d = self.queue[host].get()
                        d.addCallback(self.createClientChannel)
                        d.addErrback(self.__handleConnErrback)
                        maxRunnable -= 1
                    rotated = True
            return rotated
        
        if host:
            return rotateThese([host])
        else:
            return rotateThese(self.queue.keys())
    
    def submitRequest(self, request, _deferFromRedirect=None, now=False):
        """
        Submits a request which may be run immediately or queued.
        
        @param request: The request
        @type request: L{ClientRequest}
        @param _deferFromRedirect: If this is supplied it means that a
            redirect occurred and that deferred should be used for the
            subsequent re-request.
        @type _deferFromRedirect: C{Deferred}
        @param now: Force the request to run NOW
        @type now: C{bool}
        """
        d = None
        if self.maxRedirects == 0:
            d = request.protocol.deferred
        elif not _deferFromRedirect:
            d = Deferred()
            request.protocol.deferred.addCallback(self.__handlePossibleRedirect, d)
            request.protocol.deferred.addErrback(self.__handleErrback, d)
        else:
            request.protocol.deferred.addCallback(self.__handlePossibleRedirect, 
                                                _deferFromRedirect)
            request.protocol.deferred.addErrback(self.__handleErrback, 
                                                _deferFromRedirect)
        
        if not now and self.shouldQueue(request):
            #self.agent.logger.debug('Queued %s' % request.uri)
            self.queue[request.uri.getHost()].put(request)
        else:
            #self.agent.logger.debug('Submitted %s' % request.uri)
            self.createClientChannel(request)
        return d
    
    def createClientChannel(self, request):
        """
        Creates the actual channel for the request.
        
        @param request: The request
        @type request: L{ClientRequest}
        """
        c = ClientCreator(reactor, self.clientChannel, self)
        d = c.connectTCP(host=request.uri.netloc, port=request.uri.port)
        pending = PendingChannel()
        pending.host = request.uri.getHost()
        if request.closeAfter:
            pending.readPersistent = False
        self.pendingChannels.add(pending)
        d.addCallback(self.__request, request, pending)
        d.addErrback(self.__handleConnErrback, request, pending)
        
    def __handleConnErrback(self, e, request, pending=None):
        """
        Handles any timeout or unexpected error during a request.
        """
        if pending:
            self.pendingChannels.discard(pending)
        return self.agent.handleError(e, request, retry=True)
    
    def __handleErrback(self, e, d):
        """
        Handles all other errbacks.
        """
        if d:
            d.errback(e)
        else:
            return self.agent.handleError(e)
    
    def __handlePossibleRedirect(self, response, d):
        """
        The wonderful handling of possible redirects is done here, for lack
        of a place that makes more sense to me.
        """
        request = response.request
            
        if response.code in (MOVED_PERMANENTLY,FOUND):
            # Only auto-handle redirect for GET and POST, per RFC 2616
            if (request.method in ('GET','POST') and 
                response.headers.hasHeader('Location')):
                if request.numRedirects < self.maxRedirects:
                    loc = response.headers.getRawHeaders('Location')[0]
                    request.redirect(loc)
                    request.protocol.deferred = Deferred()
                    self.submitRequest(request, d)
                else:
                    d.errback(RedirectLimitExceededError(request.redirects[-1]))
            else:
                d.callback(response)
        else:
            d.callback(response)
    
    def __request(self, channel, request, pending=None):
        if pending:
            channel.host = request.uri.netloc
            self.openChannels.add(channel)
            self.pendingChannels.discard(pending)
            del pending
        channel.submitRequest(request, request.closeAfter)
    
    def __requestFromQueue(self, request, channel):
        self.__request(channel, request)
    
    def clientBusy(self, channel):
        self.agent.connManagerBusy()
    
    def clientIdle(self, channel):
        channel.setTimeout(self.clientIdleTimeout)
        # something messed below here...
        
        #d = self.queue[channel.host].get()
        #d.addCallback(self.__requestFromQueue, channel)
        #d.addErrback(self.__handleErrback, None)
    
    def clientPipelining(self, channel):
        # Not implemented due to bug in twisted.web2 (I think!)
        pass
    
    def clientGone(self, channel):
        self.openChannels.remove(channel)
        # There may not be another channel waiting for requests from this
        # host, so rotate the queue to possibily initialize a new one
        if not self.stopping: self.rotateQueue(channel.host)
        if self.runCount() <= 0:
            # rotate all queues to check for any dangling requests
            self.agent.connManagerIdle()
        del channel
    
    def loseClient(self, channel, reason):
        channel.connectionLost(reason)
    
    def loseEverything(self, reason):
        self.stopping = True
        self.resetQueue()
        for chan in self.openChannels:
            chan.connectionLost(reason)
        self.pendingChannels = set()
        self.openChannels = set()
    


class AgentTimeout(object): pass

class Agent(object, TimeoutMixin):
    
    connManager = HTTPClientChannelManager
    clientRequest = ClientRequest
    
    closeAfter = False
    timeOut = 60 * 2
    defaultReadProto = SimpleStringReader
    defaultWriteProto = SimpleStringWriter
    done = None
    maxRetries = 3
    
    def __init__(self, maxConnections=15, userAgent='TwistedClient',
                connTimeout=20, followRedirects=True, redirectLimit=10,
                logger='CrawlLogger'):
        """docstring for __init__"""
        self.manager = self.connManager(maxConcurrent=maxConnections)
        self.manager.maxRedirects = followRedirects and redirectLimit or 0
        self.manager.clientChannel.inputTimeOut = connTimeout
        self.manager.clientChannelRequest.userAgent = userAgent
        self.manager.agent = self
        self.done = Deferred()
        self.logger = logging.getLogger(logger)
        self.setTimeout(connTimeout*5)
    
    def requestString(self, uri, method='GET', headers=None, closeAfter=None, data=None, now=False):
        try:
            uri.url
        except AttributeError:
            uri = Uri(uri)
        if closeAfter == None:
            closeAfter = self.closeAfter
        if not data:
            protocol = self.defaultReadProto(Deferred())
        else:
            protocol = self.defaultWriteProto(Deferred(), data)
        request = self.clientRequest(method, uri, protocol, headers, closeAfter=closeAfter)
        return self.request(request, now=now)
            
    def request(self, request, now=False):
        return self.manager.submitRequest(request, now=now)
    
    def timeoutConnection(self):
        """
        From: C{TimeoutMixin}
        """
        self.logger.info("Agent timed out.")
        self.manager.loseEverything(AgentTimeout())
        self.done.callback(None)
    
    def stop(self):
        self.setTimeout(0)
    
    def connManagerIdle(self):
        self.manager.rotateQueue()
    
    def connManagerBusy(self):
        self.resetTimeout()
    
    def handleError(self, error, request=None, retry=True):
        s = []
        s.append("Error: %s" % error.getErrorMessage())
        if request: 
            s.append("From:  %s" % request.uri)
            if retry: 
                self.retryLater.add(request.uri)
        s.append(error.getBriefTraceback())
        self.logger.error('\n'.join(s))
        self.resetTimeout()
        self.manager.rotateQueue()
        return error
        
    def retry(self, request):
        if request.retries < self.maxRetries:
            request.retries += 1
            request.protocol.deferred = Deferred()
            self.logger.debug("Retrying `%s`" % request.uri)
            self.request(request)
        else:
            self.logger.debug("Max retries reached for `%s`" % request.uri)
        


