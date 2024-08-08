![Sourceduty Encryption Exchange V1 0](https://github.com/user-attachments/assets/5df93b44-4e1c-4051-8b4f-cedc6809504e)

> Text sender-receiver encryption system using AES.

#

Sourceduty Encryption Exchange is a simple implementation of a encryption system using the Advanced Encryption Standard (AES). It provides a graphical user interface (GUI) that allows users to encrypt and decrypt files using a single key, which must be securely shared between the sender and receiver. The program eliminates the need for public-key cryptography, focusing solely on symmetric key management, making it straightforward and efficient for use cases where both parties can securely exchange the key.

The core of the program revolves around the cryptography library, which is used to handle encryption and decryption operations. The sender generates a 256-bit AES key and saves it to a file. This key is then used to encrypt a selected text file. The resulting encrypted file is saved with a .enc extension. This encrypted file and the key file can then be shared with the intended recipient securely.

When the recipient receives the encrypted file, they load the file along with the corresponding key file using the program. The program then decrypts the encrypted file using the AES key and saves the decrypted content as a new file with a _decrypted.txt suffix. This process ensures that only someone with access to the correct key can decrypt and read the file's contents.

The program's simplicity and ease of use make it suitable for scenarios where secure file transfer is needed, but public key infrastructure (PKI) is not available or necessary. However, the security of the system relies heavily on the safe distribution and storage of the symmetric key. If the key is exposed or intercepted, the security of the encrypted data is compromised.

#
### User Instructions

```
Using the Program as a Sender:

Select the "Sender" role in the program.

Follow these steps:

Click "Step 1: Select File" to choose the .txt file you want to encrypt.
Click "Step 2: Generate and Save Key" to create a symmetric key and save it to a .key file.
Click "Step 3: Encrypt File" to encrypt the selected file using the generated key. The encrypted file will be saved with a .enc extension.
```
```
Using the Program as a Receiver:

Select the "Receiver" role in the program.

Follow these steps:

Click "Step 1: Select Encrypted File" to choose the .enc file you want to decrypt.
Click "Step 2: Select Key File" to load the corresponding .key file that was used for encryption.
Click "Step 3: Decrypt File" to decrypt the selected file using the key. The decrypted file will be saved with a _decrypted.txt suffix.
```

#
### Program Topological Diagram

```
SymmetricEncryptionApp Class
|
|-- __init__()
|   |-- Initialize variables
|   |-- Create GUI widgets
|
|-- create_widgets()
|   |-- Define GUI layout
|   |-- Create buttons, labels, and progress indicator
|
|-- update_role()
|   |-- Reset variables
|   |-- Update GUI based on role
|
|-- select_file()
|   |-- Open file dialog
|   |-- Select file based on role
|
|-- step2_action()
|   |-- Perform action based on role
|   |-- Sender: Generate key
|   |-- Receiver: Load key
|
|-- step3_action()
|   |-- Perform final action based on role
|   |-- Sender: Encrypt file
|   |-- Receiver: Decrypt file
|
|-- generate_key()
|   |-- Generate AES key
|   |-- Save key to file
|
|-- load_key()
|   |-- Load AES key from file
|
|-- encrypt_file()
|   |-- Encrypt selected file using AES key
|   |-- Save encrypted file
|
|-- decrypt_file()
|   |-- Decrypt selected file using AES key
|   |-- Save decrypted file
```

#
### User Process Topological Diagram

```
Start Program
|
|-- Select Role
|   |-- Sender
|   |   |-- Step 1: Select File
|   |   |-- Step 2: Generate and Save Key
|   |   |-- Step 3: Encrypt File
|   |-- Receiver
|       |-- Step 1: Select Encrypted File
|       |-- Step 2: Select Key File
|       |-- Step 3: Decrypt File
|
|-- End Program
```

#
### Related Links

[Format Developer](https://github.com/sourceduty/Format_Developer)
<br>
[Format Analyzer](https://github.com/sourceduty/Format_Analyzer)
<br>
[Encryption](https://github.com/sourceduty/Encryption)
<br>
[Encryption Specialist](https://github.com/sourceduty/Encryption_Specialist)

***
Copyright (C) 2024, Sourceduty - All Rights Reserved.
