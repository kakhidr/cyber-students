from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.registration import RegistrationHandler

from .base import BaseTest

import urllib.parse

class RegistrationHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/registration', RegistrationHandler)])
        super().setUpClass()

    def test_registration(self):
        email = 'test@test.com'
        display_name = 'testDisplayName'
        body = {
            'email': email,
            'password': 'testPassword',
            'displayName': display_name,
            'dob': '2000-01-01',
            'address': 'Dublin',
            'phone': '+353123456789',
            'disabilities': ['sight']
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(body_2['message'], "User registered successfully.")

    def test_registration_without_display_name(self):
        email = 'test@test.com'
        body = {
            'email': email,
            'password': 'testPassword',
            'dob': '2000-01-01',
            'address': 'Dublin',
            'phone': '+353123456789',
            'disabilities': ['sight']
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(body_2['message'], "User registered successfully.")

    def test_registration_twice(self):
        body = {
            'email': 'test@test.com',
            'password': 'testPassword',
            'displayName': 'testDisplayName',
            'dob': '2000-01-01',
            'address': 'Dublin',
            'phone': '+353123456789',
            'disabilities': ['sight']
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(409, response_2.code)