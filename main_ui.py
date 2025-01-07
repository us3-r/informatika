import os
from utils import CHelper, EncryptionHandler, DecryptionHandler, FileHandler
from logger import display_to_stdout

err = 0
display_to_stdout("[NOTE] Program is not case sensitive [----]", level="WARNING")
verb_in = input(display_to_stdout("Before we proceed, would you like to enable verbose mode? [y|n]", level="VERBOSE",
                                  return_msg=True))
verbose = True if verb_in.lower() == 'y' else False

while True:
    display_to_stdout("\n[------------------------------]", level="INFO")
    display_to_stdout("Choose an option to proceed...", level="INFO")
    display_to_stdout("[1] Generate RSA key pair", level="INFO")
    display_to_stdout("[2] Generate AES key", level="INFO")
    display_to_stdout("[3] Encrypt text", level="INFO")
    display_to_stdout("[4] Decrypt text", level="INFO")
    display_to_stdout("[5] Hash file", level="INFO")
    display_to_stdout("[0] Exit", level="INFO")
    choice = input(display_to_stdout("Enter your choice: ", level="WARNING", return_msg=True))

    _chelper = CHelper(
        verbose=verbose
    )
    _filehandler = FileHandler(
        verbose=verbose
    )

    match choice:
        case '1':
            key_size = int(
                input(
                    display_to_stdout("Enter the key size (default 2048): ", level="WARNING", return_msg=True)) or 2048)
            print(key_size)
            file_name = input(display_to_stdout("Enter file name (default hh_mm_ss_priv/pub.pem): ", level="WARNING",
                                                return_msg=True) or None)
            display_to_stdout("Generating RSA key pair...", level="INFO")
            _chelper.generate_rsa_key_pair(key_size, file_name, test=False)
        case '2':
            key_size = int(
                input(
                    display_to_stdout("Enter the key size (default 256): ", level="WARNING", return_msg=True)) or 256)
            file_name = input(display_to_stdout("Enter file name (default hh_mm_ss_aes_key.txt): ", level="WARNING",
                                                return_msg=True) or None)
            display_to_stdout("Generating AES key...", level="INFO")
            _chelper.generate_aes_key(key_size, file_name, test=False)
        case '3':
            key_path = input(display_to_stdout("Enter the key path: ", level="WARNING", return_msg=True))
            display_to_stdout("If you want to add a secret (MAC) enter it below, otherwise press enter...",
                              level="INFO")
            secret = input(display_to_stdout("Enter the secret: ", level="WARNING", return_msg=True) or None)
            _type = input(
                display_to_stdout("Enter the type of encryption (RSA|AES): ", level="WARNING", return_msg=True))
            e = EncryptionHandler(
                key_path=key_path,
                secret=secret,
                verbose=verbose
            )

            file_path = input(display_to_stdout("Enter the file path: ", level="WARNING", return_msg=True)) or None
            if file_path is None:
                text = input(display_to_stdout("Enter the text to encrypt: ", level="WARNING", return_msg=True))
                display_to_stdout("Encrypting text...", level="INFO")
                enc_data = e.encrypt_text(text, False, _type)
            else:
                display_to_stdout("Encrypting file...", level="INFO")
                enc_data = e.encrypt_text(file_path, True, _type)

            what = input(display_to_stdout("Would you like to save the enc data to file ('f') or just display it ('d')?", level="INFO", return_msg=True))

            if what == 'f':
                file_name = input(display_to_stdout("Enter the file name (default hh_mm_ss_): ", level="WARNING",
                                                    return_msg=True) or None)
                display_to_stdout("Saving encrypted data to file...", level="INFO")
                _filehandler.write_file(file_name, enc_data, "wb")
            else:
                print((
                        "[ENCRYPTED DATA]\n" +
                        "+---------------\n" +
                        f"{enc_data}" +
                        "\n+---------------"
                ))
        case '4':
            key_path = input(display_to_stdout("Enter the key path: ", level="WARNING", return_msg=True))
            display_to_stdout("If you want to add a secret (MAC) enter it below, otherwise press enter...",
                              level="INFO")
            secret = input(display_to_stdout("Enter the secret: ", level="WARNING", return_msg=True) or None)
            display_to_stdout("If you want to decrypt a file, enter the file path below, otherwise press enter...",
                              level="INFO")
            _type = input(
                display_to_stdout("Enter the type of encryption (RSA|AES): ", level="WARNING", return_msg=True)
                )
            d = DecryptionHandler(
                key_path=key_path,
                secret=secret,
                verbose=verbose
            )

            file_path = input(display_to_stdout("Enter the file path: ", level="WARNING", return_msg=True) or None)
            if file_path is None:
                text = input(display_to_stdout("Enter the text to decrypt: ", level="WARNING", return_msg=True))
                display_to_stdout("Decrypting text...", level="INFO")
                dec_data = d.decrypt_text(text, False, key_path)
            else:
                display_to_stdout("Decrypting file...", level="INFO")
                dec_data = d.decrypt_text(file_path, True, key_path)

            what = input(display_to_stdout("Would you like to save the dec data to file ('f') or just display it ('d')?", level="INFO", return_msg=True))

            if what == 'f':
                file_name = input(display_to_stdout("Enter the file name (default hh_mm_ss_): ", level="WARNING",
                                                    return_msg=True) or None)
                display_to_stdout("Saving decrypted data to file...", level="INFO")
                _filehandler.write_file(file_name, dec_data, "wb")
            else:
                print((
                        "[DECRYPTED DATA]\n" +
                        "+---------------\n" +
                        f"{dec_data}" +
                        "\n+---------------"
                ))

        case '5':
            file_path = input(display_to_stdout("Enter the file path: ", level="WARNING", return_msg=True))
            display_to_stdout("Hashing file...", level="INFO")
            file_hash = _filehandler.hash_file(file_path)
            print((
                    "[FILE HASH]\n" +
                    "+---------------\n" +
                    f"{file_hash}" +
                    "\n+---------------"
            ))
        case '0':
            display_to_stdout("Exiting the program...", level="INFO")
            exit()
        case _:
            display_to_stdout("Invalid choice, next will lead to exiting program", level="ERROR")
            err += 1
            if err > 1:
                display_to_stdout("Exiting the program...", level="INFO")
                exit()
