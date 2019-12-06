# Encryption, Decryption, and CSR using AES and RSA

This is an example project demonstrating the encryption and decryption process using AES and generating CSR with RSA.

## Installation

1. Git clone the project and open in Eclipse or your preferred IDE
2. Run the project as a Java Application

## Watch the files

The original file: payments.xls is located inside the folder tmp on the project root. After running the application, the encrypted and decrypted files will appear in the same folder.

## Generating CSR

In order to generate a Certificate Signing Request (CSR), run the method mainForCSV as follows:

`
CSRGenerator generator = new CSRGenerator();`
`generator.generate();`

The generated CSR will be found at tmp/keys/csr.pem
