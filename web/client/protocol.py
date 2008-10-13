from twisted.internet.protocol import Protocol
from twisted.internet.error import ConnectionDone

class PartialDownload(Exception):
    "Only part of the data was downloaded."
    def __init__(self, uri, data):
        msg = "Lost connection during request to `%s`" % uri
        self.data = data
        self.uri = uri
        super(PartialDownload, self).__init__(msg)

class SimpleStringReader(Protocol):
    """
    A simple string reader that appends data to a result string.
    """
    def __init__(self, deferred):
        self.deferred = deferred
        self.result = ''

    def connectionMade(self):
        # I don't write anything!
        self.transport.loseConnection()

    def dataReceived(self, data):
        self.result += data

    def connectionLost(self, reason):
        # It's important to know if we received the whole content body
        response = self.transport.createResponse(self.result)
        if reason.check(ConnectionDone) and response:
            # Clean connection close!  We got all the data!
            self.deferred.callback(response)
        else:                
            # Didn't get all the data for some reason; any other error is bad
            # for now.
            self.deferred.errback(PartialDownload(response.request.uri, self.result))
            del response
            
class SimpleStringWriter(Protocol):
    """
    A simple string writer/reader. It will send a string as part of the
    request and will read the resulting response to a string.
    """
    def __init__(self, deferred, data):
        self.deferred = deferred
        self.data = data
        self.result = ''

    def connectionMade(self):
        self.transport.write(self.data)
        self.transport.loseConnection()

    def dataReceived(self, data):
        self.result += data

    def connectionLost(self, reason):
        # It's important to know if we received the whole content body
        if reason.check(ConnectionDone):
            # Clean connection close!  We got all the data!
            response = self.transport.createResponse(self.result)
            self.deferred.callback(response)
        else:                
            # Didn't get all the data for some reason; any other error is bad
            # for now.
            self.deferred.errback(PartialDownload(self.result))
            
    def contentLength(self):
        return len(self.data)