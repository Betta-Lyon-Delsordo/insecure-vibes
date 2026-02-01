from db import add_user as db_add_user, get_user_by_username

def add_user(username, password):
    db_add_user(username, password)

def check_login(username, password):
    user = get_user_by_username(username)
    if not user:
        return False
    stored_password = user[2]
    return stored_password == password