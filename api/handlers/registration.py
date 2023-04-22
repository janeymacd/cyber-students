from abc import ABC
import bcrypt
from tornado.escape import json_decode
from tornado.gen import coroutine
from .base import BaseHandler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import json


# encryption method for user profile data
def encrypt_value(value):
    # generate a 32 byte key using secrets module and converts to bytes
    key = secrets.token_bytes(32)
    key_bytes = bytes(key)
    # generates 16 bytes nonce using secrets module
    nonce_bytes = secrets.token_bytes(16)
    # initialises new cipher object using aes in ctr mode with the nonce_bytes
    aes_ctr_cipher = Cipher(algorithms.AES(key_bytes), mode=modes.CTR(nonce_bytes))
    # initialises new encryptor object from the cipher object
    aes_ctr_encryptor = aes_ctr_cipher.encryptor()
    # encodes using utf-8 encoding
    plaintext_bytes = bytes(value, "utf-8")
    # converts ciphertext_bytes to hex string
    ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)
    ciphertext = ciphertext_bytes.hex()
    # returns a tuple containing ciphertext, key_bytes and nonce_bytes
    return ciphertext, key_bytes, nonce_bytes


class RegistrationHandler(BaseHandler, ABC):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            # added to get full_name
            full_name = body.get('fullName')
            if not isinstance(full_name, str):
                raise Exception()
            # added to get address
            address = body.get('address')
            if not isinstance(address, str):
                raise Exception()
            # added to get phone
            phone = body.get('phone')
            if not isinstance(phone, str):
                raise Exception()
            # added to get disabilities
            disabilities = body.get('disabilities')
            if not isinstance(disabilities, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        if not full_name:
            self.send_error(400, message='Please enter a full name!')
            return

        if not address:
            self.send_error(400, message='Please enter an address!')
            return

        if not phone:
            self.send_error(400, message='Please enter a phone number!')
            return

        if not disabilities:
            self.send_error(400, message='If this field does not apply please enter NONE!')
            return

        user = yield self.db.users.find_one({
            'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # function to hash user password
        def hash_password(password):
            # generate a salt for the password hash
            salt = bcrypt.gensalt()
            # hash the password using bcrypt with the salt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            # return the hashed password and salt as bytes
            return hashed_password, salt

        # hash the password
        hashed_password, salt = hash_password(password)
        # encrypt_value method is used to encrypt user data and store in variables, along with key and nonce
        encrypted_full_name, key_full_name, nonce_full_name = encrypt_value(full_name)
        encrypted_address, key_address, nonce_address = encrypt_value(address)
        encrypted_phone, key_phone, nonce_phone = encrypt_value(phone)
        encrypted_disabilities, key_disabilities, nonce_disabilities = encrypt_value(disabilities)

        # store the encrypted values in the users collection of the db
        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'displayName': display_name,
            'salt': salt,
            'full_name': encrypted_full_name,
            'address': encrypted_address,
            'phone': encrypted_phone,
            'disabilities': encrypted_disabilities
        })

        # store the keys and nonces in a file named keyfile
        with open('keyfile', 'w') as f:
            json.dump([
                {'name': 'full_name', 'key': key_full_name.hex(), 'nonce': nonce_full_name.hex()},
                {'name': 'address', 'key': key_address.hex(), 'nonce': nonce_address.hex()},
                {'name': 'phone', 'key': key_phone.hex(), 'nonce': nonce_phone.hex()},
                {'name': 'disabilities', 'key': key_disabilities.hex(), 'nonce': nonce_disabilities.hex()}
            ], f)

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
