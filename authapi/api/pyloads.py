from datetime import datetime

def custom_payload_handler(user):
    return {
        'user_id': user.id,
        'email': user.email,
        # 'roles': user.roles,  If you have a 'roles' attribute in your user model
        'issued_at': datetime.utcnow(),
    }
