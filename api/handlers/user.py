import json
from abc import ABC
from typing import List
from tornado.web import authenticated

from .auth import AuthHandler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class UserHandler(AuthHandler, ABC):

    # function to decrypt a value using a specific key and nonce
    def decrypt_value(self, value, key, nonce):
        if not key or not nonce:
            return None

        aes_ctr_cipher = Cipher(algorithms.AES(key), mode=modes.CTR(nonce))
        aes_ctr_decryptor = aes_ctr_cipher.decryptor()

        ciphertext_bytes = bytes.fromhex(value)
        plaintext_bytes = aes_ctr_decryptor.update(ciphertext_bytes)
        plaintext = plaintext_bytes.decode("utf-8")

        return plaintext

    async def get_user_data(self, email):
        if not self.db:
            return None

        user_data = await self.db.users.find_one({'email': email})
        return user_data

    async def generate_user_data(self, email):
        # load the keys and nonces from the keyfile
        with open('keyfile', 'r') as f:
            key_data = json.load(f)

        # function to retrieve a specific key and nonce
        def get_key_and_nonce(name):
            for item in key_data:
                if item.get('name') == name:
                    return bytes.fromhex(item.get('key')), bytes.fromhex(item.get('nonce'))
            return None, None

        # retrieve user's encrypted details from the database
        if not self.db:
            return None

        user_data = await self.get_user_data(email)
        encrypted_full_name = user_data['full_name']
        encrypted_address = user_data['address']
        encrypted_phone = user_data['phone']
        encrypted_disabilities = user_data['disabilities']

        # retrieve keys and nonces for the encrypted details
        key_full_name, nonce_full_name = get_key_and_nonce('full_name')
        key_address, nonce_address = get_key_and_nonce('address')
        key_phone, nonce_phone = get_key_and_nonce('phone')
        key_disabilities, nonce_disabilities = get_key_and_nonce('disabilities')

        # decrypt encrypted details using the keys and nonces
        full_name = self.decrypt_value(encrypted_full_name, key_full_name, nonce_full_name)
        address = self.decrypt_value(encrypted_address, key_address, nonce_address)
        phone = self.decrypt_value(encrypted_phone, key_phone, nonce_phone)
        disabilities = self.decrypt_value(encrypted_disabilities, key_disabilities, nonce_disabilities)

        # return decrypted user data
        return {
            'full_name': full_name,
            'address': address,
            'phone': phone,
            'disabilities': disabilities
        }

    @authenticated
    async def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']
        # decrypt user data using the generate_user_data function
        decrypted_data = await self.generate_user_data(self.current_user['email'])
        if decrypted_data:
            self.response['full_name'] = decrypted_data['full_name']
            self.response['address'] = decrypted_data['address']
            self.response['phone'] = decrypted_data['phone']
            self.response['disabilities'] = decrypted_data['disabilities']
        self.write_json()
