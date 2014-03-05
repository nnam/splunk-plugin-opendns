from requests.auth import AuthBase

#add your custom auth handler class to this module

class MyCustomAuth(AuthBase):
    def __init__(self,**args):
        # setup any auth-related data here
        #self.username = args['username']
        #self.password = args['password']
        pass
        
    def __call__(self, r):
        # modify and return the request
        #r.headers['foouser'] = self.username
        #r.headers['foopass'] = self.password
        return r