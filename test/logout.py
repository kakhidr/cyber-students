from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.logout import LogoutHandler

from .base import BaseTest

import urllib.parse

class LogoutHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/logout', LogoutHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        from api.utils import hash_password, hash_email, encrypt_field

        email = self.email.lower().strip()
        credentials = hash_password(self.password)
        yield self.get_app().db.users.insert_one({
            'email_hash': hash_email(email),
            'email': encrypt_field(email),
            'password_hash': credentials['hash'],
            'password_salt': credentials['salt'],
            'display_name': encrypt_field("testDisplayName"),
            'tag_name': "testDisplayName",
            'dob': encrypt_field("2000-01-01"),
            'address': encrypt_field("Dublin"),
            'phone': encrypt_field("+353123456789"),
            'disabilities': encrypt_field("sight")
        })

    @coroutine
    def login(self):
        from api.utils import hash_email
        yield self.get_app().db.users.update_one({
            'email_hash': hash_email(self.email)
        }, {
            '$set': { 'token': self.token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

    def test_logout_without_token(self):
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_twice(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response_2.code)