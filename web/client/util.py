from collections import defaultdict

class WWWInsensitiveDefaultDict(defaultdict):
    """
    A C{defaultdict} that is insensitive to both case and the
    existence of 'www.' in the key.
    """
    def __normalize(self, key):
        return key.lower().replace('www.','',1)
    
    def __getitem__(self, key):
        """Retrieve the value associated with 'key' (in any case)."""
        key = self.__normalize(key)
        return super(WWWInsensitiveDefaultDict, self).__getitem__(key)

    def __setitem__(self, key, value):
        """Associate 'value' with 'key'. If 'key' already exists, but
        in different case, it will be replaced."""
        key = self.__normalize(key)
        return super(WWWInsensitiveDefaultDict, self).__setitem__(key, value)