## WinVerifyTrust-Go project ##

Hardened and reliable utility for verifying digital signatures in executable files (e.g .EXE, .SYS, .DLL).
Implements advanced WinVerifyTrust API features as well as cryptographic ones.

Features real, native certificate extraction and validation (not superficial using only high-level Windows API calls) 

Features include:
  * Dual signature support (Windows 8+)
  * RFC3161 timestamp verification
  * Extensive security validation
  * Certificate chain verification
  * Multiple file processing

Options:
  -revocation    Check certificate revocation status
  -verbose       Show detailed certificate and timestamp information
  -help          Show this help message
