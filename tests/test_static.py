import pytest
import os
from utils import CHelper, FileHandler, EncryptionHandler, DecryptionHandler
import errors

_chelper = CHelper(
    verbose=False
)


def test_rsa_key_gen():
    assert _chelper.generate_rsa_key_pair(2048, None, True) is True
    keys = ['keys\\test_public.pem', 'keys\\test_private.pem']
    for key_file in keys:
        assert os.path.exists(key_file)

    # Cleanup
    for key_file in keys:
        if os.path.exists(key_file):
            os.remove(key_file)


def test_mac():
    secret = "Testings"
    data = "This is a test sample data"
    mac = _chelper.get_mac(secret.encode(), data.encode())
    assert mac is not None and type(mac) is bytes  # check if mac is generated
    assert _chelper.compare_mac(secret.encode(), data.encode(), mac) is True


def test_mac_fail():
    secret = "0195some"
    wrong_secret = "NotRight"
    data = "This is a test sample data"
    mac = _chelper.get_mac(secret.encode(), data.encode())
    assert mac is not None and type(mac) is bytes  # check if mac is generated
    assert _chelper.compare_mac(wrong_secret.encode(), data.encode(), mac) is False


def test_generate_aes_key_valid_sizes():
    valid_sizes = [16, 24, 32]
    for size in valid_sizes:
        if os.path.exists('keys\\test_aes_key.txt'):
            os.remove('keys\\test_aes_key.txt')

        key = _chelper.generate_aes_key(size, None, True)
        assert isinstance(key, bytes), "Key should be of type bytes"
        assert len(key) == size, f"Key length should be {size} bytes"
        assert os.path.exists('keys\\test_aes_key.txt'), "Key file should exist"

        # Read the key from the file and compare (Note: Keys will differ due to double generation)
        file_content = FileHandler().read_file('keys\\test_aes_key.txt')
        file_key = eval(file_content)  # Convert string representation back to bytes
        assert isinstance(file_key, bytes), "File key should be of type bytes"
        assert len(file_key) == size, f"File key length should be {size} bytes"


def test_generate_aes_key_invalid_size():
    invalid_sizes = [15, 20, 33]
    for size in invalid_sizes:
        with pytest.raises(errors.AESKeySizeError):
            _chelper.generate_aes_key(size)


def test_generate_twofish_key_valid_sizes():
    valid_sizes = range(16, 33)  # Sizes from 16 to 32 inclusive
    for size in valid_sizes:
        if os.path.exists('keys\\test_twofish_key.txt'):
            os.remove('keys\\test_twofish_key.txt')

        key = _chelper.generate_twofish_key(size, None, True)
        assert isinstance(key, bytes), "Key should be of type bytes"
        assert len(key) == size, f"Key length should be {size} bytes"
        assert os.path.exists('keys\\test_twofish_key.txt'), "Key file should exist"

        # Read the key from the file and compare
        file_content = FileHandler().read_file('keys\\test_twofish_key.txt')
        file_key = eval(file_content)
        assert isinstance(file_key, bytes), "File key should be of type bytes"
        assert len(file_key) == size, f"File key length should be {size} bytes"


def test_generate_twofish_key_invalid_size():
    invalid_sizes = [15, 33]
    for size in invalid_sizes:
        with pytest.raises(errors.TWOFISHKeySizeError):
            _chelper.generate_twofish_key(size)


def test_enc_dec_ok():
    _k = ['keys\\test_A_public.pem', 'keys\\test_A_private.pem', 'keys\\test_B_public.pem', 'keys\\test_B_private.pem']
    for key_file in _k:
        if os.path.exists(key_file):
            os.remove(key_file)

    _chelper.generate_rsa_key_pair(2048, 'A', True)
    _chelper.generate_rsa_key_pair(2048, 'B', True)
    _secret = "11/22/1250"
    text_to_encrypt = [
        "Hello world",
        "This is a test",
        "Some random text",
        "1234567890",
        "12@34#56$78%90"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAaaaaaaaa"
    ]
    c_B = EncryptionHandler(
        key_path='keys\\test_B_public.pem',
        secret=_secret
    )
    d_B = DecryptionHandler(
        key_path='keys\\test_B_private.pem',
        secret=_secret
    )
    for ctx in text_to_encrypt:
        enc_text = c_B.encrypt_text(ctx, _is_file=False, _type='RSA')
        dec_text = d_B.decrypt_text(enc_text, _is_file=False, _type='RSA')
        assert ctx == dec_text, f"[B] Decrypted text should be {ctx}"

    c_A = EncryptionHandler(
        key_path='keys\\test_A_public.pem',
        secret=_secret
    )
    d_A = DecryptionHandler(
        key_path='keys\\test_A_private.pem',
        secret=_secret
    )
    for ctx in text_to_encrypt:
        enc_text = c_A.encrypt_text(ctx, _is_file=False, _type='RSA')
        dec_text = d_A.decrypt_text(enc_text, _is_file=False, _type='RSA')
        assert ctx == dec_text, f"[A] Decrypted text should be {ctx}"
