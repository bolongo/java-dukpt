# Java Triple DES DUKPT Library

Implementation of the ANSI 3DES DUKPT standard: specified within Retail Financial Services Symmetric Key Management Part 1: Using Symmetric Techniques (ANSI X9.24-1:2009).

## v. 1.3.0
The Dukpt class is expanded with methods for the encryption and decryption using __AES 128__, __AES 192__ and __AES 256__,
padding the key if necessary

## v. 1.2.0
The method _computeKeyFromIpek_ is added to both _Dukpt_ and _DukptVariant_ classes for use when an _IPEK_ is provided
to the device instead of a _BDK_ 

