import os
import time
import unittest
from unittest.mock import patch
from urllib.parse import quote

os.environ.setdefault('vulnerable', '1')

import jwt  # noqa: E402

from config import vuln_app  # noqa: E402


class VampiTestCase(unittest.TestCase):
    def setUp(self):
        self.client = vuln_app.app.test_client()
        self.assertEqual(self.client.get('/createdb').status_code, 200)

    def login(self, username, password):
        res = self.client.post('/users/v1/login', json={'username': username, 'password': password})
        return res.get_json()

    def token(self, username, password):
        return self.login(username, password)['auth_token']

    def auth(self, username, password):
        return {'Authorization': 'Bearer ' + self.token(username, password)}


class CreateDbTest(VampiTestCase):
    def test_createdb_assigns_unique_book_titles_when_random_values_repeat(self):
        with patch('models.user_model.randrange', side_effect=[42, 42, 43, 42, 43, 44]):
            res = self.client.get('/createdb')
        self.assertEqual(res.status_code, 200)
        titles = [book['book_title'] for book in self.client.get('/books/v1').get_json()['Books']]
        self.assertEqual(sorted(titles), ['bookTitle42', 'bookTitle43', 'bookTitle44'])


class SqlInjectionTest(VampiTestCase):
    def test_get_user_by_username(self):
        res = self.client.get('/users/v1/name1')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json(), {'username': 'name1', 'email': 'mail1@mail.com'})

    def test_union_select_does_not_leak_passwords(self):
        payload = "x' UNION SELECT 1, password, 3, password, 5 FROM users WHERE username = 'admin'--"
        res = self.client.get('/users/v1/' + quote(payload))
        self.assertEqual(res.status_code, 404)
        self.assertNotIn('pass1', res.get_data(as_text=True))


class UnauthorizedPasswordChangeTest(VampiTestCase):
    def test_user_can_change_own_password(self):
        res = self.client.put('/users/v1/name1/password', json={'password': 'newpass1'}, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 204)
        self.assertIn('auth_token', self.login('name1', 'newpass1'))

    def test_user_cannot_change_password_of_another_user(self):
        res = self.client.put('/users/v1/name2/password', json={'password': 'hacked'}, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 403)
        self.assertNotIn('auth_token', self.login('name2', 'hacked'))
        self.assertIn('auth_token', self.login('name2', 'pass2'))


class BookAuthorizationTest(VampiTestCase):
    def book_of(self, username):
        books = self.client.get('/books/v1').get_json()['Books']
        return next(book['book_title'] for book in books if book['user'] == username)

    def test_owner_can_read_own_book_secret(self):
        title = self.book_of('name1')
        res = self.client.get('/books/v1/' + title, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()['owner'], 'name1')

    def test_user_cannot_read_book_secret_of_another_user(self):
        title = self.book_of('name2')
        res = self.client.get('/books/v1/' + title, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 404)
        self.assertNotIn('secret', res.get_json())


class MassAssignmentTest(VampiTestCase):
    def test_registration_cannot_grant_admin(self):
        res = self.client.post('/users/v1/register', json={
            'username': 'mallory', 'password': 'pw', 'email': 'mallory@mail.com', 'admin': True
        })
        self.assertEqual(res.status_code, 200)
        me = self.client.get('/me', headers=self.auth('mallory', 'pw')).get_json()
        self.assertFalse(me['data']['admin'])


class DebugEndpointExposureTest(VampiTestCase):
    def test_debug_requires_authentication(self):
        res = self.client.get('/users/v1/_debug')
        self.assertEqual(res.status_code, 401)
        self.assertNotIn('pass1', res.get_data(as_text=True))

    def test_debug_requires_admin(self):
        res = self.client.get('/users/v1/_debug', headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 403)
        self.assertNotIn('pass1', res.get_data(as_text=True))

    def test_debug_for_admin_does_not_expose_passwords(self):
        res = self.client.get('/users/v1/_debug', headers=self.auth('admin', 'pass1'))
        self.assertEqual(res.status_code, 200)
        users = res.get_json()['users']
        self.assertTrue(any(user['username'] == 'admin' and user['admin'] for user in users))
        self.assertTrue(all('password' not in user for user in users))


class UserEnumerationTest(VampiTestCase):
    def test_login_does_not_reveal_whether_user_exists(self):
        wrong_password = self.client.post('/users/v1/login', json={'username': 'name1', 'password': 'wrong'})
        unknown_user = self.client.post('/users/v1/login', json={'username': 'nobody', 'password': 'wrong'})
        self.assertEqual(wrong_password.status_code, unknown_user.status_code)
        self.assertEqual(wrong_password.get_json(), unknown_user.get_json())
        self.assertNotIn('auth_token', wrong_password.get_json())


class EmailRegexDosTest(VampiTestCase):
    def test_valid_email_can_be_updated(self):
        res = self.client.put('/users/v1/name1/email', json={'email': 'new.mail-1@example.org'}, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 204)
        self.assertEqual(self.client.get('/users/v1/name1').get_json()['email'], 'new.mail-1@example.org')

    def test_invalid_email_is_rejected(self):
        res = self.client.put('/users/v1/name1/email', json={'email': 'not-an-email'}, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 400)

    def test_malicious_email_is_rejected_quickly(self):
        headers = self.auth('name1', 'pass1')
        start = time.monotonic()
        res = self.client.put('/users/v1/name1/email', json={'email': 'a' * 26 + '!'}, headers=headers)
        self.assertEqual(res.status_code, 400)
        self.assertLess(time.monotonic() - start, 0.5)


class JwtSigningKeyTest(VampiTestCase):
    def test_token_signed_with_guessable_key_is_rejected(self):
        forged = jwt.encode({'sub': 'admin', 'exp': int(time.time()) + 600, 'iat': int(time.time())}, 'random', algorithm='HS256')
        res = self.client.get('/me', headers={'Authorization': 'Bearer ' + forged})
        self.assertEqual(res.status_code, 401)

    def test_issued_token_is_accepted(self):
        res = self.client.get('/me', headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()['data']['username'], 'name1')


if __name__ == '__main__':
    unittest.main()
