UTPB-COSC-4380-Project3-4
This repository contains the code and documentation for Projects 3 and 4 of the Cryptography class, completed by Group 7: Alejandro Sotelo, Bryan Lim, and Roman Huerta. These projects focus on enhancing understanding and implementation skills in cryptography using Java, particularly around the Diffie-Hellman Key Exchange (DHE), RSA algorithms, and the Advanced Encryption Standard (AES).

Project 3: DHE and RSA Algorithms
Project Goals
Enhance proficiency in Java/Python coding to solve cryptographic problems.
Deepen understanding of the Diffie-Hellman Key Exchange (DHE) and RSA algorithms.
Provide useful implementations of key exchange and encryption algorithms.
Description
For Project 3, we implemented a library based on the provided Java/Python skeleton to achieve Diffie-Hellman key exchange and RSA encryption/decryption along with digital signatures. The Java code includes JavaDoc comments that outline the expected methods, their parameters, and return values. We addressed the unimplemented methods marked with TODO comments and validated the implementation using provided tests.

Key Features
Diffie-Hellman Key Exchange (DHE): Implementation supports two-party and three-party exchanges, computing shared secrets accurately.
RSA Encryption and Signing: Capable of encrypting and decrypting messages and generating/verifying digital signatures.
Grading Compliance
Fully functional, implementing all required interfaces.
Handles foreseeable exceptions gracefully to avoid crashes.
Methods are straightforward and easy to use.
Deliverables
The deliverables for Project 3 include a fully functional Java/Python application implementing the DHE and RSA algorithms, with pertinent documentation detailing the development process and resources consulted.

Project 4: AES Algorithm Implementation
Project Goals
Enhance coding skills in Java/Python for implementing block cipher algorithms.
Deepen understanding of the AES encryption algorithm and its modes.
Provide a usable AES encryption and decryption implementation.
Description
In Project 4, we implemented the AES algorithm in both ECB and CBC modes, as specified. Our implementation exposes an 
encrypt()
 method that accepts plaintext, a key, and a mode indicator, returning the corresponding ciphertext. Similarly, the 
decrypt()
 method reverses this process. We included a debug flag for detailed output at each encryption/decryption step, aiding the validation process against provided sample debug outputs.

Key Features
AES in ECB and CBC Modes: Implementation supports both operation modes for AES, with detailed state output for debugging.
Encryption and Decryption: Methods for both operations are exposed, providing flexible usage for various cryptographic needs.
Grading Compliance
The code compiles successfully and handles all specified inputs without crashes.
It follows the outlined algorithmic steps accurately, producing expected results.
Interfaces are user-friendly and not overly complicated.
Deliverables
For Project 4, we provide a Java/Python program that implements the AES algorithm as required. This includes documentation on the coding process and resources used to aid our understanding and implementation.

Tools and Resources
This project was aided by the use of Claude 3.7 via Macro for development and problem-solving support.
