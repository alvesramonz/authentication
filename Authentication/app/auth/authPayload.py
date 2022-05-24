from datetime import datetime  
from datetime import timedelta  

class authPayload(dict):

    def __init__(self, id, clientId, isAdmin):
        self.id = id
        self.clientId = clientId
        self.isAdmin = isAdmin
        self.exp = datetime.utcnow() + timedelta(seconds=3000)