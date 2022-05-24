class authResponse(dict):
    
    def __init__(self, token, expiresin, isAdmin, user_id):
        self.token = token
        self.user_id = user_id
        self.expiresin = expiresin
        self.isAdmin = isAdmin