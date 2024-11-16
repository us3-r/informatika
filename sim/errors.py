class InvalidInputError(Exception):
    """
    This error is raised when the input provided by the user is invalid.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class InvalidOutputError(Exception):
    """
    This error is raised when the output provided by the user is invalid.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class EmptyInputError(Exception):
    """
    This error is raised when the input provided by the user is empty.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class UnsupportedOperationError(Exception):
    """
    This error is raised when the operation requested by the user is not supported.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class FileError(Exception):
    """
    This error is raised when there is an issue with the file.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class FileErrorUndefined(Exception):
    """
    This error is raised when there is an undefined issue with the file.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class UnableToReadFile(Exception):
    """
    This error is raised when the file cannot be read.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class UnableToWriteFile(Exception):
    """
    This error is raised when the file cannot be written to.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class KeyGenerationError(Exception):
    """
    This error is raised when there is an issue with key generation.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class AESKeySizeError(Exception):
    """
    This error is raised when the AES key size is invalid.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class TWOFISHKeySizeError(Exception):
    """
    This error is raised when the TWOFISH key size is invalid.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class InvalidEncryptionType(Exception):
    """
    This error is raised when the encryption type is invalid.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class EncryptionFailOrReturnsNone(Exception):
    """
    This error is raised when the encryption returns None.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class InvalidMAC(Exception):
    """
    This error is raised when the MAC is invalid or does not match.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class DecryptionFailOrReturnsNone(Exception):
    """
    This error is raised when the decryption returns None.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class MACGenerationError(Exception):
    """
    This error is raised when there is an issue with MAC generation.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
