# yourapp/token_utils.py
import jwt
from datetime import datetime, timedelta, timezone
from django.conf import settings

SECRET_KEY = settings.JWT_SECRET_KEY
ALGORITHM = 'HS256'

expiration_time = datetime.now(timezone.utc) + timedelta(minutes=30)

def create_token(org_id):
    payload = {
        'org_id': org_id,
        # 'exp':  expiration_time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

