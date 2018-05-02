import base64
import json
import os
import passwort
import tempfile
import unittest
from Cryptodome import Random


class TestPasswort(unittest.TestCase):

    def setUp(self):
        tf = tempfile.NamedTemporaryFile(delete=False, dir=os.getcwd())
        self.temp_filename = os.path.join(os.getcwd(), tf.name)
        tf.close()
        os.unlink(self.temp_filename)

    def tearDown(self):
        if os.path.exists(self.temp_filename):
            os.unlink(self.temp_filename)

    def test_basic_features(self):
        username = 'foo'
        key = passwort.generate_key()
        k1 = passwort.Keychain()
        k1.use_key(key)
        k1.set('example.com', passwort.Keychain.USERNAME_FIELD, username)
        k1.save(self.temp_filename)

        v1 = k1.get('example.com', passwort.Keychain.USERNAME_FIELD)
        self.assertEqual(v1, username)

        k2 = passwort.Keychain()
        k2.use_key(key)
        k2.load(self.temp_filename)

        v2 = k2.get('example.com', passwort.Keychain.USERNAME_FIELD)
        self.assertEqual(v2, v1)

    def test_tampering(self):
        password = '1' * 100
        key = passwort.generate_key()
        k1 = passwort.Keychain()
        k1.use_key(key)
        k1.set('example.com', passwort.Keychain.PASSWORD_FIELD, password)
        k1.save(self.temp_filename)

        v1 = k1.get('example.com', passwort.Keychain.PASSWORD_FIELD)
        self.assertEqual(v1, password)

        k2 = passwort.Keychain()
        k2.use_key(key)
        k2.load(self.temp_filename)

        v2 = k2.get('example.com', passwort.Keychain.PASSWORD_FIELD)
        self.assertEqual(v2, v1)

        tmp = open(self.temp_filename)
        data = json.load(tmp)
        tmp.close()
        enc_password_value = base64.b64decode(data['example.com']['password']['text'])
        tampered_value = Random.new().read(16) + enc_password_value[16:]
        data['example.com']['password']['text'] = base64.b64encode(tampered_value).decode()
        f = open(self.temp_filename, "w")
        f.write(json.dumps(data))
        f.close()

        k3 = passwort.Keychain()
        k3.use_key(key)
        k3.load(self.temp_filename)

        with self.assertRaises(NameError):
            k3.get('example.com', passwort.Keychain.PASSWORD_FIELD)


if __name__ == '__main__':
    unittest.main()
