from tornado.gen import coroutine
from tornado.web import authenticated

from .auth import AuthHandler

class LogoutHandler(AuthHandler):

    @authenticated
    @coroutine
    def post(self):
        self.response = {}

        yield self.db.users.update_one({
            'email': self.current_user['email'],
        }, {
            '$set': {
                'token': None
            }
        })

        print(f"User {self.current_user['email']} logged out.")  ### Logout statement.

        self.current_user = None

        self.set_status(200)
        self.response['message'] = "Successfully logged out."
        self.write_json()
