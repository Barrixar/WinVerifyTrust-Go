## WinVerifyTrust-Go project ##

Hardened and reliable utility for verifying digital signatures in executable files (e.g .EXE, .SYS, .DLL).
Implements advanced WinVerifyTrust API features as well as cryptographic ones.

Features real, native certificate extraction and validation (not superficial using only high-level Windows API calls) 

Features include:
  * **Dual signature support (Windows 8+)**
  * **RFC3161 timestamp verification**
  * **Extensive security validation**
  * **Certificate chain verification**
  * **Multiple file processing**

Options:
  -revocation    Check certificate revocation status
  -verbose       Show detailed certificate and timestamp information
  -help          Show this help message


WinVerifyTrust-Go is not susceptible to the recently published CVE-2013-3900 while checking a file (As you can't expect all systems to have migitated it using registry). The CVE from 2013 was REpublished more than 10 years later, so you read that "Recently published" part right.

Due to the short nanture of this README (subject to change, if I have more time soon) it is advised to comb through the code before use, to understand its extensive set of features and security implementations.
The only way to do this is by reading the source code at:
https://github.com/Barrixar/WinVerifyTrust-Go/blob/main/WinVerifyTrust.go

I'm also happy to accept contributions to the README, I am looking for a good writer to accurately summarize the project.
