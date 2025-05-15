from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest

from api.handlers.login import LoginHandler

import urllib.parse

class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/login', LoginHandler)])
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

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
          'email': self.email,
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_case_insensitive(self):
        body = {
          'email': self.email.swapcase(),
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
          'email': 'wrongUsername',
          'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
          'email': self.email,
          'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)