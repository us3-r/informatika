Outline for the kryptograpy project in python

## Components
- [ ] Command Line Interface (falgs for common things, plus flag for simulation of chat)
- [ ] Encryption and Decryption
- [ ] Key Generation
- [ ] Signature Generation and Verification
- [ ] Unit Tests
- [ ] Simulation of P2P enc chat (very basic, just for PoC)

## CLI Flags
- [ ] `--encrypt | -e` Encrypt a message
- [ ] `--decrypt | -d` Decrypt a message
- [ ] `--generate-key | -gk` Generate a key
- [ ] `--generate-signature | -gs` Generate a signature
- [ ] `--verify-signature | -vs` Verify a signature
- [ ] `--help | -h` Show help message
- [ ] `--verbose | -v` Show verbose output

## Encryption and Decryption
- [ ] Use different encryption algorithms (AES,RSA, Twofish)
  - Adjust chosen algorithem based on message size (prioritize speed for small messages, security for large messages)
  - Use a hybrid approach for encryption (AES for large messages, RSA for small messages, Twofish for chat messages)
    - (Generate a random key for AES and Twofish, encrypt the key with RSA)
  - Same for decryption
- [ ] Implement padding for input text (ANSI X.923 for AES and Twofish, OAEP for RSA)
- [ ] Diffie-Hellman key exchange for chat messages/communication/othr

## Key Generation
- [ ] Generate a key for AES and Twofish
- [ ] Generate a key pair for RSA
- [ ] Output keys to a file / read keys from a file
- [ ] Use a secure random number generator (mby costume made?)

## Signature Generation and Verification (RSA-PSS)
- [ ] Generate a signature for a message
- [ ] Verify a signature for a message
- [ ] Use a secure hash function (SHA-256, SHA-3)

## Unit Tests
- [ ] Test all components (encryption, decryption, key generation, signature generation, signature verification)
- [ ] Test edge cases (empty message, empty key, empty signature)
- [ ] Test performance (time to encrypt, time to decrypt, time to generate key, time to generate signature, time to verify signature)
- [ ] Test security (test if the encryption is secure, test if the signature is secure)
- [ ] Test possible brute force attacks (try to decrypt a message without the key, try to verify a signature without the public key)




#### TODO
- [ ] Create Errors.py (for custom errors)
- [ ] Create Utils.py (for helper functions)
        Functions for:
        - [ ]  key generation
        - [ ] encryption
        - [ ] decryption
        - [ ] signature generation
        - [ ] signature verification
        - [ ] file handling
        - [ ] random number generation
        - [ ] hash functions
        - [ ] padding
        - [ ] message integrity
        - [ ] signature integrity
- [ ] Create Tests.py (for unit tests)
- [ ] Create sim.py (for chat simulation/live message exchange simulation)