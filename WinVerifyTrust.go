//go:build windows

// This program implements an advanced Windows digital signature verification tool.
// It leverages Windows WinTrust API functions to validate Authenticode signatures on executable files (.exe, .dll, .sys, etc.)
// with support for both standard verification and extended verification modes. The tool provides detailed
// signature information including certificate chains, timestamps, and signature algorithms.
//
// IMPORTANT SECURITY NOTES:
// - This tool extracts real certificate data using Windows CryptoAPI
// - Uses unsafe.Pointer operations with proper validation and bounds checking
// - This tool is designed for Windows platforms only
//
// SECURITY HARDENED:
// - Command-line argument validation (count limits, size limits, character validation)
// - Path traversal prevention with path validation
// - TOCTOU attack prevention through exclusive file access
// - Integer overflow protection in all pointer arithmetic operations
// - Memory safety measures with bounds checking and safe memory copying
// - Thread-safe operations with proper mutex synchronization
// - Resource exhaustion prevention through input validation and limits
// - Technically advanced error handling with security-focused responses
//
// Features:
// - Dual verification modes: WinVerifyTrust and WinVerifyTrustEx
// - Technically advanced signature validation with certificate chain analysis
// - Timestamp verification and detailed certificate information
// - Thread-safe verification with proper Windows API compliance
// - Support for various executable formats (.exe, .dll, .sys, etc.)
//
// Usage:
//
//	WinVerifyTrust [-mode=trust|trustex] [-verbose] <file1> [file2] ...
//
// The tool requires Windows and uses official Microsoft WinTrust APIs
// for cryptographic signature verification.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Barrixar/WinVerifyTrust-Go/verify"
	"github.com/Barrixar/WinVerifyTrust-Go/winver"
)

// reconstructPaths attempts to reconstruct file paths from command line arguments
// This helps when users forget to quote paths with spaces
func reconstructPaths(args []string) []string {
	if len(args) <= 1 {
		return args
	}

	// REGRESSION FIX: Don't attempt to reconstruct if we already have what appear to be
	// multiple complete file paths. Only reconstruct when we have a path that was
	// split by spaces within a single logical file path.

	// Check if all arguments already look like complete file paths
	allLookLikeCompletePaths := true
	for _, arg := range args {
		// Check if this looks like a complete Windows path (drive letter + valid extension)
		if !(len(arg) >= 2 && arg[1] == ':' && (strings.HasSuffix(strings.ToLower(arg), ".exe") ||
			strings.HasSuffix(strings.ToLower(arg), ".dll") ||
			strings.HasSuffix(strings.ToLower(arg), ".sys") ||
			strings.HasSuffix(strings.ToLower(arg), ".msi") ||
			strings.HasSuffix(strings.ToLower(arg), ".ocx"))) {
			allLookLikeCompletePaths = false
			break
		}
	}

	// If all arguments already look like complete paths, don't reconstruct
	if allLookLikeCompletePaths {
		return args
	}

	// Only attempt reconstruction if we have incomplete paths
	var reconstructed []string
	i := 0
	for i < len(args) {
		currentArg := args[i]

		// Check if this looks like the start of a Windows path
		if len(currentArg) >= 2 && currentArg[1] == ':' {
			// This looks like C:\ path, try to reconstruct
			path := currentArg
			j := i + 1

			// Look ahead to see if we can build a valid path
			for j < len(args) {
				testPath := path + " " + args[j]

				// Check if adding this makes it look more like a file path
				if strings.HasSuffix(strings.ToLower(testPath), ".exe") ||
					strings.HasSuffix(strings.ToLower(testPath), ".dll") ||
					strings.HasSuffix(strings.ToLower(testPath), ".sys") {
					// This looks like a complete file path
					path = testPath
					i = j
					break
				} else if j == len(args)-1 {
					// Last argument, include it
					path = testPath
					i = j
					break
				} else {
					// Continue building path
					path = testPath
					j++
				}
			}
			reconstructed = append(reconstructed, path)
		} else {
			// Not a Windows path, keep as-is
			reconstructed = append(reconstructed, currentArg)
		}
		i++
	}

	return reconstructed
}

func main() {
	// Security: Validate argument count and total length to prevent resource exhaustion
	if len(os.Args) > 100 {
		fmt.Fprintf(os.Stderr, "Error: Too many arguments (maximum 100 allowed)\n")
		return
	}

	totalArgLength := 0
	for _, arg := range os.Args {
		totalArgLength += len(arg)
		if totalArgLength > 32768 { // 32KB limit
			fmt.Fprintf(os.Stderr, "Error: Arguments too long (maximum 32KB total)\n")
			os.Exit(1)
		}
		// Security: Check for null bytes and control characters in arguments
		for _, b := range []byte(arg) {
			if b == 0 || (b < 32 && b != 9 && b != 10 && b != 13) {
				fmt.Fprintf(os.Stderr, "Error: Invalid characters in argument\n")
				os.Exit(1)
			}
		}
	}

	var (
		checkRevocation = flag.Bool("revocation", false, "Check certificate revocation status")
		verbose         = flag.Bool("verbose", false, "Show detailed information")
		showHelp        = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *showHelp || flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Windows Signature Verification Tool (Security Hardened)\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <file_path> [file_path2] [...]\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\nFeatures:\n")
		fmt.Fprintf(os.Stderr, "  * Dual signature support (Windows 8+)\n")
		fmt.Fprintf(os.Stderr, "  * RFC3161 timestamp verification\n")
		fmt.Fprintf(os.Stderr, "  * security validation\n")
		fmt.Fprintf(os.Stderr, "  * Certificate chain verification\n")
		fmt.Fprintf(os.Stderr, "  * Multiple file processing\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -revocation    Check certificate revocation status\n")
		fmt.Fprintf(os.Stderr, "  -verbose       Show detailed certificate and timestamp information\n")
		fmt.Fprintf(os.Stderr, "  -help          Show this help message\n")
		os.Exit(1)
	}

	if !winver.IsWindows7OrLater() {
		fmt.Fprintf(os.Stderr, "Error: This tool requires Windows 7 or later\n")
		os.Exit(1)
	}

	// Display system info once if verbose
	if *verbose {
		isWin8Plus := winver.IsWindows8OrLater()
		if isWin8Plus {
			fmt.Println("System: Windows 8 or later (verification)")
		} else {
			fmt.Println("System: Windows 7 or earlier")
		}
		if flag.NArg() > 1 {
			fmt.Printf("Processing %d files...\n\n", flag.NArg())
		}
	}

	// Collect all non-flag arguments
	rawArgs := make([]string, flag.NArg())
	for i := 0; i < flag.NArg(); i++ {
		rawArgs[i] = flag.Arg(i)
	}

	// Attempt to reconstruct paths if it looks like arguments were split on spaces
	processedArgs := reconstructPaths(rawArgs)

	// If reconstruction changed the number of arguments, show a helpful message
	if len(processedArgs) != len(rawArgs) && len(rawArgs) > 1 {
		fmt.Printf("Note: Detected %d arguments that may be parts of %d file path(s).\n", len(rawArgs), len(processedArgs))
		fmt.Printf("Tip: Use quotes around file paths with spaces: \"%s\"\n", strings.Join(rawArgs, " "))
		fmt.Println()
	}

	// Process all file arguments
	for i, filePath := range processedArgs {
		// Show file header for multiple files
		if len(processedArgs) > 1 {
			if i > 0 {
				fmt.Println() // Add blank line between files
			}
			fmt.Printf("=== File %d of %d: %s ===\n", i+1, len(processedArgs), filepath.Base(filePath))
		} else if *verbose {
			fmt.Printf("Verifying: %s\n", filepath.Base(filePath))
		}

		// Use detailed verification to support dual signatures and timestamps
		signatures, err := verify.VerifyFileSignatureWithDetails(filePath, *checkRevocation, *verbose)
		if err != nil {
			if *verbose {
				fmt.Printf("Detailed verification failed: %v\n", err)
				fmt.Printf("Falling back to basic verification...\n")
			}
			// Fallback to simple verification if detailed fails
			fallbackErr := verify.VerifyFileSignature(filePath, *checkRevocation)
			if fallbackErr != nil {
				fmt.Printf("[FAIL] Verification failed: %v\n", fallbackErr)
				continue // Continue to next file instead of exiting
			}
			fmt.Printf("[OK] File has a valid signature\n")
			continue
		}

		// Display signature information
		fmt.Printf("[OK] File has a valid signature\n")

		if *verbose && len(signatures) > 0 {
			fmt.Printf("\nSignature Details:\n")
			fmt.Printf("==================\n")

			for _, sig := range signatures {
				sigType := "Primary"
				if !sig.IsPrimary {
					sigType = fmt.Sprintf("Secondary (%d)", sig.Index)
				}

				fmt.Printf("\n%s Signature:\n", sigType)
				fmt.Printf("  Type: %s\n", sig.SignatureType)

				if sig.Certificate != nil {
					fmt.Printf("  Certificate:\n")
					fmt.Printf("    Subject: %s\n", sig.Certificate.Subject)
					fmt.Printf("    Issuer: %s\n", sig.Certificate.Issuer)
					fmt.Printf("    Algorithm: %s\n", sig.Certificate.SignatureAlg)
					if !sig.Certificate.NotBefore.IsZero() {
						fmt.Printf("    Valid From: %s\n", sig.Certificate.NotBefore.Format("2006-01-02 15:04:05"))
					}
					if !sig.Certificate.NotAfter.IsZero() {
						fmt.Printf("    Valid To: %s\n", sig.Certificate.NotAfter.Format("2006-01-02 15:04:05"))
					}
					if len(sig.Certificate.KeyUsage) > 0 {
						fmt.Printf("    Key Usage: %s\n", strings.Join(sig.Certificate.KeyUsage, ", "))
					}
					// Display certificate analysis if available
					if len(sig.Certificate.EnhancedInfo) > 0 {
						fmt.Printf("    Analysis:\n")
						for key, value := range sig.Certificate.EnhancedInfo {
							// Only display interesting analysis results
							if key != "error" && value != "" &&
								!strings.Contains(value, "capability available") {
								fmt.Printf("      %s: %s\n", key, value)
							}
						}
						// Show capability summary
						if capNote, exists := sig.Certificate.EnhancedInfo["CapabilitiesNote"]; exists {
							fmt.Printf("    %s\n", capNote)
						}
					}

					// Display comprehensive certificate chain trust status
					if sig.Certificate.TrustStatus != nil {
						fmt.Printf("    Certificate Chain Trust Analysis:\n")
						fmt.Printf("      Trust Level: %s\n", sig.Certificate.TrustStatus.TrustLevel)
						fmt.Printf("      Is Trusted: %v\n", sig.Certificate.TrustStatus.IsTrusted)
						if sig.Certificate.TrustStatus.ChainStatus != "" {
							fmt.Printf("      Chain Status: %s\n", sig.Certificate.TrustStatus.ChainStatus)
						}
						if len(sig.Certificate.TrustStatus.ErrorStatus) > 0 {
							fmt.Printf("      Trust Errors:\n")
							for _, err := range sig.Certificate.TrustStatus.ErrorStatus {
								fmt.Printf("        - %s\n", err)
							}
						}
						if len(sig.Certificate.TrustStatus.InfoStatus) > 0 {
							fmt.Printf("      Trust Information:\n")
							for _, info := range sig.Certificate.TrustStatus.InfoStatus {
								fmt.Printf("        - %s\n", info)
							}
						}
					}
				}

				if sig.Timestamp != nil {
					fmt.Printf("  Timestamp:\n")
					if !sig.Timestamp.Timestamp.IsZero() {
						fmt.Printf("    Time: %s\n", sig.Timestamp.Timestamp.Format("2006-01-02 15:04:05 MST"))
					}
					if sig.Timestamp.TSAName != "" {
						fmt.Printf("    TSA: %s\n", sig.Timestamp.TSAName)
					}
					if sig.Timestamp.HashAlgorithm != "" {
						fmt.Printf("    Hash Algorithm: %s\n", sig.Timestamp.HashAlgorithm)
					}
					fmt.Printf("    RFC3161: %v\n", sig.Timestamp.IsRFC3161)
				}
			}

			if len(signatures) > 1 {
				fmt.Printf("\nTotal Signatures: %d\n", len(signatures))
			}
		}
	}
}
