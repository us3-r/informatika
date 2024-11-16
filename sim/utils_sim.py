import hashlib
import errors
import errno
import secrets
import os
import ast
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from datetime import datetime
import logger


class FileHandler:
    """
    A class to handle file operations
    """

    @staticmethod
    def read_file(file_path: str, mode: str = 'r'):
        """
        Read a file and return the content

            :param file_path: The path to the file
            :param mode: The mode to open the file in
        """
        try:
            with open(file_path, mode=mode) as file:
                return file.read()
        except FileNotFoundError as e:
            raise errors.FileError(f'File not found: {e}')
        except IOError as e:
            if e.errno == errno.EACCES:
                raise errors.FileError(f'Permission denied: {e}')
            else:
                raise errors.UnableToReadFile(f'Unable to read file: {e}')
        except Exception as e:
            raise errors.FileErrorUndefined(f'Undefined file error: {e}')

    @staticmethod
    def write_file(file_path: str, content, mode: str = 'w') -> None:
        """
        Write content to a file

            :param file_path: The path to the file
            :param content: The content to write
            :param mode: The mode to open the file in

        """
        try:
            with open(file_path, mode=mode) as file:
                file.write(content)
        except FileNotFoundError as e:
            raise errors.FileError(f'File not found: {e}')
        except IOError as e:
            if e.errno == errno.EACCES:
                raise errors.FileError(f'Permission denied: {e}')
            else:
                raise errors.FileError(f'Unable to write file: {e}')
        except Exception as e:
            raise errors.FileErrorUndefined(f'Undefined file error: {e}')

    @staticmethod
    def hash_file(file_path: str = None, _type: str = 'md5') -> str:
        """
        Hash the given file
        (source: https://stackoverflow.com/questions/22058048/hashing-a-file-in-python)

            :param file_path: The path to the file
            :param _type: The type of hash to use
            :return: The hash of the file
        """
        if not file_path:
            raise errors.FileError('File path not provided')
        if _type not in ['md5', 'sha1']:
            raise errors.UnsupportedOperationError(f'Unsupported hash type: {_type}')

        BUFFER_SIZE = 65536  # 64kb -> so we don't use too much ram

        with open(file_path, 'rb') as file:
            while True:
                data = file.read(BUFFER_SIZE)
                if not data:
                    break

        if _type == 'md5':
            return hashlib.md5(data).hexdigest()
        elif _type == 'sha1':
            return hashlib.sha1(data).hexdigest()


class CHelper:
    """
    Class to host common functions to be used wile encrypting/decrypting etc
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def make_bytes(self, data: str) -> bytes:
        """
        Convert a string to bytes
        """
        logger.log_to_stderr(f'Converting {data} to bytes') if self.verbose else None
        return data.encode('utf-8')

    def get_mac(self, secret: bytes, data: bytes) -> bytes:
        """
        Generate a MAC for the given data

            :param secret: The secret key to use
            :param data: The data to generate the MAC for
            :return: The MAC for the given data
        """
        logger.log_to_stderr(f'[ENC] Generating MAC for <data> using secret {secret}') if self.verbose else None
        try:
            h = hmac.HMAC(secret, hashes.SHA256())
            h.update(data)
            logger.log_to_stderr(f'[ENC] MAC generated', level='SUCCESS') if self.verbose else None
            return h.finalize()
        except Exception as e:
            logger.log_to_stderr(f'[ENC] Unable to generate MAC: {e}', level='ERROR') if self.verbose else None
            raise errors.MACGenerationError(f'Unable to generate MAC: {e}')

    def compare_mac(self, secret: bytes, data: bytes, mac: bytes) -> bool:
        """
        Compare the MAC of the data with the given MAC

            :param secret: The secret key to use
            :param data: The data to compare the MAC with
            :param mac: The MAC to compare with
            :return: True if the MACs match else
        """
        logger.log_to_stderr(f'Comparing MAC for <data> using secret {secret}') if self.verbose else None
        h = hmac.HMAC(secret, hashes.SHA256())
        h.update(data)
        try:
            h.verify(mac)
        except InvalidSignature:
            logger.log_to_stderr(f'Invalid MAC', level='ERROR') if self.verbose else None
            return False
        return True

    def generate_rsa_key_pair(self, size: int, file_name: str = None, test: bool = False) -> bool:
        """
        Generate RSA key pair

            :param size: The size of the key pair
            :param file_name: The name of the file to save the key pair
            :param test: If this is a test
            :return: True if the key pair was generated successfully else raises an error
        """
        # set file name to 'file_name' if not none else to current time
        logger.log_to_stderr(
            f'Generating RSA key pair with size {size} and file name {file_name}') if self.verbose else None

        current_time = datetime.now().strftime('%H_%M_%S')
        if test:
            file_name = f'test_{file_name}_' if file_name else 'test_'
        else:
            file_name = file_name + "_" if file_name else f'{current_time}_'
        if os.path.exists(f"keys\\{file_name}private.pem") or os.path.exists(f"keys\\{file_name}public.pem"):
            logger.log_to_stderr(f'Key pair with name "{file_name}" already exists',
                                 level='ERROR') if self.verbose else None
            raise errors.KeyGenerationError(f'Key pair with name "{file_name}" already exists')

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size
        )
        public_key = private_key.public_key()
        try:
            FileHandler.write_file(f'keys\\{file_name}private.pem', private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'))

            FileHandler.write_file(f'keys\\{file_name}public.pem', public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'))
            logger.log_to_stderr(f'Key pair generated successfully', level='SUCC') if self.verbose else None
        except Exception as e:
            logger.log_to_stderr(f'Unable to generate key pair: {e}', level='ERROR') if self.verbose else None
            raise errors.KeyGenerationError(f'Unable to generate key pair: {e}')
        return True

    def generate_aes_key(self, size: int = 32, file_name: str = None, test: bool = False) -> bytes:
        """
        Generate an AES key

            :param size: The size of the key
            :return: The generated AES key
        """
        if size > 32:  # if size is in bits
            size = size // 8
        if size not in [16, 24, 32]:
            logger.log_to_stderr(f'Invalid AES key size: {size}', level='ERROR') if self.verbose else None
            raise errors.AESKeySizeError(f'Invalid AES key size: {size}')

        logger.log_to_stderr(f'Generating AES key with size {size}') if self.verbose else None

        current_time = datetime.now().strftime('%H_%M_%S')
        if test:
            file_name = f'test_{file_name}_' if file_name else 'test_'
        else:
            file_name = file_name + "_" if file_name else f'{current_time}_'
        if os.path.exists(f"keys\\{file_name}.txt"):
            logger.log_to_stderr(f'Key with name "{file_name}aes_key.txt" already exists',
                                 level='ERROR') if self.verbose else None
            raise errors.KeyGenerationError(f'Key with name "{file_name}aes_key.txt" already exists')

        _key = secrets.token_bytes(size)
        FileHandler.write_file(f'keys\\{file_name}aes_key.txt', str(_key))
        logger.log_to_stderr(f'AES key generated successfully', level='SUCC') if self.verbose else None
        return _key

    def generate_twofish_key(self, size: int = 32, file_name: str = None, test: bool = False) -> bytes:
        """
        Generate a Twofish key

            :param size: The size of the key
            :param file_name: The name of the file to save the key
            :param test: If this is a test
            :return: The generated Twofish key
        """
        if size > 32:  # if size is in bits
            size = size // 8
        if not (16 <= size <= 32):
            logger.log_to_stderr(f'Invalid Twofish key size: {size}', level='ERROR') if self.verbose else None
            raise errors.TWOFISHKeySizeError(f'Invalid Twofish key size: {size}')

        logger.log_to_stderr(f'Generating TWOFISH key with size {size}') if self.verbose else None

        current_time = datetime.now().strftime('%H_%M_%S')
        if test:
            file_name = f'test_{file_name}_' if file_name else 'test_'
        else:
            file_name = file_name + "_" if file_name else f'{current_time}_'
        if os.path.exists(f"keys\\{file_name}.txt"):
            logger.log_to_stderr(f'Key with name "{file_name}twofish_key.txt" already exists',
                                 level='ERROR') if self.verbose else None
            raise errors.KeyGenerationError(f'Key with name "{file_name}twofish_key.txt" already exists')

        _key = secrets.token_bytes(size)
        FileHandler.write_file(f'keys\\{file_name}twofish_key.txt', str(_key))
        return _key

    def get_key(self, key_path: str) -> bytes:
        """
        Get the key from the given path

            :param key_path: The path to key
            :return bytes: key
        """
        logger.log_to_stderr(f'Getting key from {key_path}') if self.verbose else None
        if key_path.endswith('.txt'):
            logger.log_to_stderr(f'Reading key [AES] from {key_path}') if self.verbose else None
            return ast.literal_eval(FileHandler.read_file(key_path))
        elif key_path.endswith('.pem'):
            logger.log_to_stderr(f'Reading key [RSA] from {key_path}') if self.verbose else None
            return FileHandler.read_file(key_path).encode('utf-8')


class EncryptionHandler:
    """
    Class to handle encryption, should work like so:
    - Initialize the class with a path to key, and context
    - Encrypt, generate MAC, and write to file
    """

    def __init__(self, key_path: str, secret: str = None, verbose: bool = False):
        self.key_path = key_path
        self.key = CHelper(verbose).get_key(key_path)
        self.secret = secret  # for MAC
        self.verbose = verbose
        self.chelper = CHelper(verbose)

    def encrypt_text(self, text: str, _is_file: bool = False, _type: str = None) -> bytes:
        """
        Encrypts the given text or gets the text from the file and encrypts it

            :param text: The text to encrypt or the path to the file
            :param _is_file: If the text is a file
            :param _type: The type of encryption to use
            :return bytes: The encrypted text

        """
        logger.log_to_stderr(f'[ENC] Encrypting input') if self.verbose else None
        encrypted_text = None

        if _type is None or _type not in ['AES', 'TWOFISH', 'RSA']:
            raise errors.InvalidEncryptionType(f'Invalid encryption type: {_type}')

        if _is_file:
            text = FileHandler.read_file(text)

        if _type == 'AES':
            iv, enc_context = self._encrypt_aes(text)
            encrypted_text = iv + enc_context

        elif _type == 'TWOFISH':
            logger.log_to_stderr(f'[ENC] Twofish encryption not supported yet', level='ERROR') if self.verbose else None
            pass

        elif _type == 'RSA':
            logger.log_to_stderr(f'[ENC] Encrypting with ) RSA (') if self.verbose else None
            pb_key = serialization.load_pem_public_key(self.key)
            encrypted_text = pb_key.encrypt(
                self.chelper.make_bytes(text),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        if self.secret:
            logger.log_to_stderr(f'[ENC] Adding MAC to the encrypted text') if self.verbose else None
            mac = self.chelper.get_mac(self.chelper.make_bytes(self.secret), encrypted_text)
            logger.log_to_stderr(f'[GEN] MAC - {mac}', level="DEBUG") if self.verbose else None
            encrypted_text += mac

        if not encrypted_text:
            raise errors.EncryptionFailOrReturnsNone(f'Encryption failed or returned None')
        logger.log_to_stderr(f'[ENC] Encryption ) DONE (') if self.verbose else None
        return encrypted_text

    def _encrypt_aes(self, context: str) -> tuple:
        """
        Encrypt the given context using AES in CTR mode

            :param context: The context to encrypt
            :return tuple: The encrypted context and the IV
        """
        logger.log_to_stderr(f'[ENC] Encrypting with ) AES (') if self.verbose else None
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        enc = cipher.encryptor()
        enc_context = enc.update(self.chelper.make_bytes(context)) + enc.finalize()
        return iv, enc_context


class DecryptionHandler:
    def __init__(self, key_path: str, secret: str = None, verbose: bool = False):
        self.key_path = key_path
        self.key = CHelper(verbose).get_key(key_path)
        self.secret = secret
        self.verbose = verbose
        self.chelper = CHelper(verbose)

    def decrypt_text(self, text: bytes | str, _is_file: bool = False, _type: str = None) -> str:
        """
            Decrypts the given text or gets the text from the file and decrypts it
                :param text:
                :param _is_file:
                :param _type:
                :return: decrypted text
        """
        logger.log_to_stderr(f'[DEC] Decrypting input') if self.verbose else None

        decrypted_text = None

        _ = text if not _is_file else FileHandler.read_file(text, 'rb')
        logger.log_to_stderr(f'[DEC] Text to decrypt: {_}', level='DEBUG') if self.verbose else None
        logger.log_to_stderr(f'[DEC] Type : {type(_)}', level='DEBUG') if self.verbose else None
        text = _.encode('utf-8') if type(_) is str else _

        if self.secret:
            logger.log_to_stderr(f'[DEC] Verifying MAC') if self.verbose else None
            mac = text[-32:]
            logger.log_to_stderr(f'[GEN] MAC - {mac}', level="DEBUG") if self.verbose else None
            text = text[:-32]
            if not self.chelper.compare_mac(self.chelper.make_bytes(self.secret), text, mac):
                raise errors.InvalidMAC(f'Invalid MAC')

        if _type is None or _type not in ['AES', 'RSA']:
            raise errors.InvalidEncryptionType(f'Invalid encryption type: {_type}')

        if _type == 'AES':
            logger.log_to_stderr(f'[DEC] splitting IV and context') if self.verbose else None
            iv = text[:16]
            enc_context = text[16:]
            decrypted_text = self._decrypt_aes(iv, enc_context)

        elif _type == 'TWOFISH':
            pass

        elif _type == 'RSA':
            logger.log_to_stderr(f'[DEC] Decrypting with ) RSA (') if self.verbose else None
            pr_key = serialization.load_pem_private_key(self.key, None)
            decrypted_text = pr_key.decrypt(
                text,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')

        if not decrypted_text:
            raise errors.DecryptionFailOrReturnsNone(f'[DEC] Decryption failed or returned None')
        logger.log_to_stderr(f'[DEC] Decryption ) DONE (') if self.verbose else None
        # return as string
        return decrypted_text.decode('utf-8') if type(decrypted_text) is bytes else decrypted_text

    def _decrypt_aes(self, iv, enc_context):
        """
        Decrypt the given context using AES in CTR mode

            :param iv: The IV
            :param enc_context: The encrypted context
            :return: The decrypted context
        """
        logger.log_to_stderr(f'[DEC] Decrypting with ) AES (') if self.verbose else None
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        dec = cipher.decryptor()
        dec_context = dec.update(enc_context) + dec.finalize()
        return dec_context
