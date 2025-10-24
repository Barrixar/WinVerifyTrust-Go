package winver

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Version checking mutex for thread-safe version detection
var versionCheckMutex sync.Mutex

// IsWindows7OrLater checks if we're running on Windows 7 or later with security
func IsWindows7OrLater() bool {
	// Thread safety for version detection
	versionCheckMutex.Lock()
	defer versionCheckMutex.Unlock()

	// Use RtlGetVersion to check for minimum Windows 7 (6.1)
	// This is more reliable than GetVersionEx and harder to hook
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	// Validate ntdll loaded successfully
	if err := ntdll.Load(); err != nil {
		// If we can't load ntdll, assume compromised system
		return false
	}

	proc := ntdll.NewProc("RtlGetVersion")
	if proc.Find() != nil {
		// Can't find RtlGetVersion, assume not supported or tampered
		return false
	}

	// Validate proc address is legitimate
	if proc.Addr() == 0 {
		return false
	}

	type rtlOSVersionInfo struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformID        uint32
	}

	var info rtlOSVersionInfo
	info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))

	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 { // Not STATUS_SUCCESS
		return false
	}

	// Windows 7 is 6.1, we support 6.1 and later
	if info.dwMajorVersion > 6 {
		return true
	}
	if info.dwMajorVersion == 6 && info.dwMinorVersion >= 1 {
		return true
	}

	return false
}

// IsWindows8OrLater uses multiple secure methods to detect Windows version with thread safety
func IsWindows8OrLater() bool {
	// Thread safety for version checks
	versionCheckMutex.Lock()
	defer versionCheckMutex.Unlock()

	// Method 1: Check for Windows 8+ specific API existence
	// This is harder to spoof than version numbers
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	// Validate DLL loaded successfully before checking exports
	if err := kernel32.Load(); err != nil {
		// If we can't load kernel32, something is very wrong
		return false
	}

	// GetSystemTimePreciseAsFileTime only exists on Windows 8+
	if proc := kernel32.NewProc("GetSystemTimePreciseAsFileTime"); proc.Find() == nil {
		// Validate the proc address is actually valid
		if proc.Addr() != 0 {
			return true
		}
	}

	// Method 2: Check ntdll exports that exist only on Windows 8+
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	// RtlCheckTokenCapability added in Windows 8
	if proc := ntdll.NewProc("RtlCheckTokenCapability"); proc.Find() == nil {
		return true
	}

	// Method 3: Use RtlGetVersion as fallback (harder to hook than GetVersionEx)
	// RtlGetVersion is not subject to compatibility shims
	type rtlOSVersionInfoEx struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformID        uint32
		szCSDVersion        [128]uint16
		wServicePackMajor   uint16
		wServicePackMinor   uint16
		wSuiteMask          uint16
		wProductType        byte
		wReserved           byte
	}

	if proc := ntdll.NewProc("RtlGetVersion"); proc.Find() == nil {
		var info rtlOSVersionInfoEx
		info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))

		ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&info)))
		if ret == 0 { // STATUS_SUCCESS
			// Windows 8 is 6.2, Windows 10 is 10.0
			if info.dwMajorVersion > 6 {
				return true
			}
			if info.dwMajorVersion == 6 && info.dwMinorVersion >= 2 {
				return true
			}
		}
	}

	// Method 4: Check for Windows 8+ specific DLLs
	// These DLLs don't exist on Windows 7
	windows8DLLs := []string{
		"api-ms-win-core-winrt-l1-1-0.dll",        // WinRT support
		"api-ms-win-core-winrt-string-l1-1-0.dll", // WinRT strings
	}

	for _, dllName := range windows8DLLs {
		if dll := windows.NewLazySystemDLL(dllName); dll.Load() == nil {
			return true
		}
	}

	// If none of the Windows 8+ indicators are found, assume Windows 7
	return false
}
