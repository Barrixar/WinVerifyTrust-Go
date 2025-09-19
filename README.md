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


WinVerifyTrust-Go is not susceptible to the recently published CVE-2013-3900 while checking a file (As you can't expect all systems to have migitated it using registry).

I wrote it leveraging my extensive security engineering knownledge, using:
https://gist.github.com/heaths/ebbca7d956f0b42bbb33193f0837e272?permalink_comment_id=5766639#gistcomment-5766639 (Gist from a Microsoft engineer) as a template, and it turned out exactly as what i commented there on their Gist. It is a mature, pentested implementation as-is, even though i seek contributors, reviews, and will strive to actively maintain this repository depending on community interest.

Due to the short nanture of this README (subject to change, if I have more time soon) it is advised to comb through the code before use, to understand its extensive set of featurues and security implementations.
The only way to do this is by reading the source code at:
https://github.com/Barrixar/WinVerifyTrust-Go/blob/main/WinVerifyTrust.go

I'm also happy to accept contributions to the README, I am looking for a good writer to accurately summarize the project.
