from auth import Auth

email = 'bob@bob.com'
password = 'mySuperPwd'
auth = Auth()

auth.register_user(email, password)

session_id = auth.create_session(email)
print(session_id)
print(auth.get_user_from_session_id(session_id))
print(auth.get_user_from_session_id(session_id).id)
print(auth.get_user_from_session_id(session_id).email)
