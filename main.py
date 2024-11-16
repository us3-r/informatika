import os
from utils import CHelper, EncryptionHandler, DecryptionHandler, FileHandler
import argparse
import logger

arg_parser = argparse.ArgumentParser(description='Encrypt and Decrypt files',
                                     formatter_class=argparse.RawTextHelpFormatter)

arg_parser.add_argument('-e', '--encrypt', type=str, metavar='str,str',
                        help=('[*] Encrypt context' +
                              '\n-> Chose type ["RSA","AES"]' +
                              '\n-> MAC [secret] ? empty'))
# py main.py -e RSA -f test.txt | -t "Hello World"
arg_parser.add_argument('-d', '--decrypt', type=str, metavar='str,str',
                        help=('[*] Decrypt context' +
                              '\n-> Chose type ["RSA","AES"]' +
                              '\n-> MAC [secret] ? empty'))
# py main.py -d RSA -f test.txt | -t "Hello World"
arg_parser.add_argument('-f', '--file', type=str, metavar='path/to/file',
                        help='[*] File path to encrypt/decrypt')
arg_parser.add_argument('-t', '--text', type=str,
                        help='[*] Text to encrypt/decrypt')
arg_parser.add_argument('-gk', '--generate-key', type=str,
                        help=('[*] Generate a key for encryption/decryption' +
                              '\n-> Chose type ["RSA","AES"]' +
                              '\n-> Chose size [128, 192, 256 or 16, 24, 32]' +
                              '\n-> Chose output name (default is: <project_dir>\\keys\\<current_time>_?.?'))
arg_parser.add_argument('-k', '--key', type=str, metavar='path/to/key',
                        help=('[*] set key path to encrypt/decrypt' +
                              '\n-> keys used for encryption or decryption if type is AES' +
                              '\n !!! use -pk or --private-key to set RSA private key !!!'))
arg_parser.add_argument('-pk', '--private-key', type=str, metavar='path/to/private-key',
                        help='[*] Set RSA private key path')
arg_parser.add_argument('-v', '--verbose', action='store_true',
                        help='[*] Print verbose output')
arg_parser.add_argument('-o', '--output', type=str, metavar='path/to/output',
                        help='[*] Set output path for encrypted/decrypted file')

_arg = arg_parser.parse_args()

_enc = _arg.encrypt
_dec = _arg.decrypt
_file = _arg.file
_text = _arg.text
_gen_key = _arg.generate_key
_key = _arg.key
_private_key_path = _arg.private_key
_output_file = _arg.output

_chelper = CHelper(
    verbose=_arg.verbose
)

if _gen_key:
    key_type = _gen_key.split(',')[0]
    key_size = int(_gen_key.split(',')[1])
    key_path = _gen_key.split(',')[2] if len(_gen_key.split(',')) == 3 else None
    if key_type.upper() == 'RSA':
        _chelper.generate_rsa_key_pair(key_size, key_path, test=False)
    elif key_type.uper() == 'AES':
        _chelper.generate_aes_key(key_size, key_path, test=False)
if _enc:
    e = EncryptionHandler(
        key_path=_key,
        secret=_enc.split(',')[1] if len(_enc.split(',')) == 2 else None,
        verbose=_arg.verbose
    )
    if _file:
        pass  # TODO: implement file encryption
    elif _text:
        enc_data = e.encrypt_text(_text, False, _enc.split(',')[0].upper())
        print((
                "[ENCRYPTED TEXT]\n" +
                "+---------------\n" +
                f"{enc_data}" +
                "\n+---------------"
        )) if not _output_file else FileHandler.write_file(_output_file, enc_data, 'wb')

if _dec:
    d = DecryptionHandler(
        key_path=_private_key_path,
        secret=_dec.split(',')[1] if len(_dec.split(',')) == 2 else None,
        verbose=_arg.verbose
    )
    if _file:
        dec_data = d.decrypt_text(_file, True, _dec.split(',')[0].upper())
        print((
                "[DECRYPTED TEXT]\n" +
                "+---------------\n" +
                f"{dec_data}" +
                "\n+---------------"
        )) if not _output_file else FileHandler.write_file(_output_file, enc_data, 'wb')

    elif _text:
        dec_data = d.decrypt_text(_text, False, _dec.split(',')[0].upper())
        print((
                "[DECRYPTED TEXT]\n" +
                "+---------------\n" +
                f"{dec_data}" +
                "\n+---------------"
        )) if not _output_file else FileHandler.write_file(_output_file, str(dec_data))
