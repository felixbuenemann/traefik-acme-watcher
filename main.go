package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"unsafe"

	"golang.org/x/sys/unix"
)

type AcmeJSON struct {
	Letsencrypt struct {
		Account struct {
			Email      string `json:"Email"`
			PrivateKey string `json:"PrivateKey"`
			KeyType    string `json:"KeyType"`
		} `json:"Account"`
		Certificates []struct {
			Domain struct {
				Main string `json:"main"`
			} `json:"domain"`
			Certificate string `json:"certificate"`
			Key         string `json:"key"`
			Store       string `json:"Store"`
		} `json:"Certificates"`
	} `json:"letsencrypt"`
}

type Config struct {
	acmePath string
	domain   string
	certPath string
	keyPath  string
	pid      int
	execCmd  string
	userName string
	signal   string
	wait     bool
}

var (
	// Store the certificate in memory for comparison
	currentCertBase64 string
	certMutex         sync.RWMutex

	// Track if we sent a signal to the child process
	sentSignalToChild bool
	childProcess      *exec.Cmd
	childMutex        sync.Mutex
)

func main() {
	config := parseFlags()

	// Initial certificate extraction
	if err := extractAndWriteCertificates(config, true); err != nil {
		if config.wait && (strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no such file")) {
			if strings.Contains(err.Error(), "no such file") {
				log.Printf("acme.json not found, waiting for it to appear...")
			} else {
				log.Printf("Domain %s not found in acme.json, waiting for it to appear...", config.domain)
			}
		} else {
			log.Fatalf("Failed to extract certificates on startup: %v", err)
		}
	} else {
		// Only start child process if we successfully extracted certificates
		if config.execCmd != "" {
			go runChildProcess(config)
		}
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Set up file watching
	watchChan := make(chan struct{}, 1)
	go watchAcmeFile(config.acmePath, watchChan)

	// Track if child process has been started
	childStarted := config.execCmd == "" || currentCertBase64 != ""

	// Main event loop
	for {
		select {
		case <-watchChan:
			log.Println("Detected change in acme.json")
			if err := extractAndWriteCertificates(config, false); err != nil {
				log.Printf("Error processing certificate change: %v", err)
			} else if !childStarted && config.execCmd != "" && currentCertBase64 != "" {
				// Domain appeared for the first time in wait mode
				log.Printf("Domain %s appeared, starting child process", config.domain)
				go runChildProcess(config)
				childStarted = true
			}
		case sig := <-sigChan:
			log.Printf("Received signal %v, shutting down", sig)
			cleanup()
			os.Exit(0)
		}
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.acmePath, "acme-path", "", "Path to acme.json file")
	flag.StringVar(&config.domain, "domain", "", "Domain name to extract certificate for")
	flag.StringVar(&config.certPath, "cert", "", "Output path for certificate PEM file")
	flag.StringVar(&config.keyPath, "key", "", "Output path for private key PEM file")
	flag.IntVar(&config.pid, "pid", 0, "Process ID to signal on certificate changes")
	flag.StringVar(&config.execCmd, "exec", "", "Command to execute and manage")
	flag.StringVar(&config.userName, "user", "", "User to switch to when using --exec")
	flag.StringVar(&config.signal, "signal", "HUP", "Signal to send (default: HUP)")
	flag.BoolVar(&config.wait, "wait", false, "Wait for domain to appear in acme.json instead of failing")

	flag.Parse()

	// Validate required flags
	if config.acmePath == "" || config.domain == "" || config.certPath == "" || config.keyPath == "" {
		flag.Usage()
		log.Fatal("Required flags: --acme-path, --domain, --cert, --key")
	}

	// Validate mutually exclusive flags
	if config.pid != 0 && config.execCmd != "" {
		log.Fatal("Cannot use both --pid and --exec")
	}

	return config
}

func extractAndWriteCertificates(config *Config, isStartup bool) error {
	// Read and parse acme.json
	data, err := os.ReadFile(config.acmePath)
	if err != nil {
		return fmt.Errorf("failed to read acme.json: %w", err)
	}

	var acme AcmeJSON
	if err := json.Unmarshal(data, &acme); err != nil {
		return fmt.Errorf("failed to parse acme.json: %w", err)
	}

	// Find certificate for domain
	var certData, keyData string
	found := false
	for _, cert := range acme.Letsencrypt.Certificates {
		if cert.Domain.Main == config.domain {
			certData = cert.Certificate
			keyData = cert.Key
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("certificate for domain %s not found", config.domain)
	}

	// Check if certificate changed
	certMutex.Lock()
	defer certMutex.Unlock()

	if !isStartup && certData == currentCertBase64 {
		log.Println("Certificate unchanged, skipping update")
		return nil
	}

	// Decode base64 to PEM
	certPEM, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	// Write certificate and key files atomically
	if err := writeFileAtomic(config.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	if err := writeFileAtomic(config.keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	// Update stored certificate
	currentCertBase64 = certData

	log.Printf("Successfully wrote certificate and key for domain %s", config.domain)

	// Send signal if configured (but not on startup, unless in wait mode and domain just appeared)
	shouldSignal := !isStartup || (config.wait && isStartup && config.pid != 0)
	if shouldSignal {
		if config.pid != 0 {
			if err := sendSignal(config.pid, config.signal); err != nil {
				log.Printf("Failed to send signal to PID %d: %v", config.pid, err)
			}
		} else if config.execCmd != "" && childProcess != nil {
			sendSignalToChild(config.signal)
		}
	}

	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()

	// Clean up temp file on any error
	defer func() {
		if tempFile != nil {
			tempFile.Close()
			os.Remove(tempPath)
		}
	}()

	if _, err := tempFile.Write(data); err != nil {
		return err
	}

	if err := tempFile.Close(); err != nil {
		return err
	}
	tempFile = nil // Prevent defer cleanup

	// Set permissions before rename
	if err := os.Chmod(tempPath, perm); err != nil {
		return err
	}

	// Atomic rename
	return os.Rename(tempPath, path)
}

func watchAcmeFile(path string, notify chan<- struct{}) {
	// Initialize inotify
	fd, err := unix.InotifyInit1(0)
	if err != nil {
		log.Fatalf("Failed to initialize inotify: %v", err)
	}
	defer unix.Close(fd)

	// Watch the directory for atomic writes and file creation
	dir := filepath.Dir(path)
	watchDesc, err := unix.InotifyAddWatch(fd, dir, unix.IN_MOVED_TO|unix.IN_CREATE)
	if err != nil {
		log.Fatalf("Failed to add inotify watch: %v", err)
	}
	defer unix.InotifyRmWatch(fd, uint32(watchDesc))

	// Also watch the file directly for in-place modifications (only after close)
	fileWatchDesc, err := unix.InotifyAddWatch(fd, path, unix.IN_CLOSE_WRITE)
	if err != nil {
		// This is expected if file doesn't exist yet
		fileWatchDesc = -1
	} else {
		defer unix.InotifyRmWatch(fd, uint32(fileWatchDesc))
	}

	filename := filepath.Base(path)
	buf := make([]byte, 4096)

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			log.Printf("Error reading inotify events: %v", err)
			time.Sleep(time.Second)
			continue
		}

		// Parse inotify events
		offset := 0
		for offset < n {
			if n-offset < unix.SizeofInotifyEvent {
				break
			}

			event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]
			name := string(nameBytes[:clen(nameBytes)])

			// Check if event is for our file or from direct file watch
			if name == filename || name == "" {
				// Debounce multiple events
				select {
				case notify <- struct{}{}:
				default:
				}
			}

			offset += unix.SizeofInotifyEvent + int(event.Len)
		}
	}
}

// clen returns the length of a null-terminated C string
func clen(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return len(b)
}

func sendSignal(pid int, sigName string) error {
	sig := parseSignal(sigName)
	return syscall.Kill(pid, sig)
}

func parseSignal(sigName string) syscall.Signal {
	sigName = strings.ToUpper(sigName)
	switch sigName {
	case "HUP", "SIGHUP":
		return syscall.SIGHUP
	case "INT", "SIGINT":
		return syscall.SIGINT
	case "QUIT", "SIGQUIT":
		return syscall.SIGQUIT
	case "KILL", "SIGKILL":
		return syscall.SIGKILL
	case "TERM", "SIGTERM":
		return syscall.SIGTERM
	case "USR1", "SIGUSR1":
		return syscall.SIGUSR1
	case "USR2", "SIGUSR2":
		return syscall.SIGUSR2
	default:
		log.Printf("Unknown signal %s, using SIGHUP", sigName)
		return syscall.SIGHUP
	}
}

func runChildProcess(config *Config) {
	// Switch user if specified
	if config.userName != "" {
		if err := switchUser(config.userName); err != nil {
			log.Fatalf("Failed to switch user: %v", err)
		}
	}

	// Parse command with proper quote handling
	args, err := parseCommand(config.execCmd)
	if err != nil {
		log.Fatalf("Failed to parse exec command: %v", err)
	}
	if len(args) == 0 {
		log.Fatal("Empty exec command")
	}

	for {
		childMutex.Lock()
		sentSignalToChild = false
		childProcess = exec.Command(args[0], args[1:]...)
		childProcess.Stdout = os.Stdout
		childProcess.Stderr = os.Stderr
		childProcess.Stdin = os.Stdin
		childMutex.Unlock()

		// Set up signal forwarding
		go forwardSignals()

		log.Printf("Starting child process: %s", config.execCmd)
		err := childProcess.Run()

		childMutex.Lock()
		wasSignaled := sentSignalToChild
		childProcess = nil
		childMutex.Unlock()

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				log.Printf("Child process exited with error: %v", exitErr)
			} else {
				log.Printf("Failed to run child process: %v", err)
			}
			// Don't restart on error
			os.Exit(1)
		}

		// Clean exit
		if wasSignaled {
			log.Println("Child process exited cleanly after signal, restarting...")
			time.Sleep(time.Second) // Brief pause before restart
		} else {
			log.Println("Child process exited cleanly without signal, not restarting")
			os.Exit(0)
		}
	}
}

func switchUser(userName string) error {
	u, err := user.Lookup(userName)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}

	// Set GID first, then UID
	if err := syscall.Setgid(gid); err != nil {
		return err
	}

	if err := syscall.Setuid(uid); err != nil {
		return err
	}

	return nil
}

func forwardSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan)

	for sig := range sigChan {
		// Don't forward SIGCHLD
		if sig == syscall.SIGCHLD {
			continue
		}

		childMutex.Lock()
		if childProcess != nil && childProcess.Process != nil {
			childProcess.Process.Signal(sig)
		}
		childMutex.Unlock()
	}
}

func sendSignalToChild(sigName string) {
	childMutex.Lock()
	defer childMutex.Unlock()

	if childProcess != nil && childProcess.Process != nil {
		sentSignalToChild = true
		sig := parseSignal(sigName)
		if err := childProcess.Process.Signal(sig); err != nil {
			log.Printf("Failed to send signal to child process: %v", err)
		} else {
			log.Printf("Sent signal %s to child process", sigName)
		}
	}
}

func cleanup() {
	childMutex.Lock()
	defer childMutex.Unlock()

	if childProcess != nil && childProcess.Process != nil {
		childProcess.Process.Signal(syscall.SIGTERM)
		// Give it time to exit cleanly
		done := make(chan struct{})
		go func() {
			childProcess.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(5 * time.Second):
			// Force kill after timeout
			childProcess.Process.Kill()
		}
	}
}

// parseCommand parses a command string respecting quotes
func parseCommand(cmd string) ([]string, error) {
	var args []string
	var current []rune
	var inQuote rune
	var escaped bool

	for _, r := range cmd {
		if escaped {
			current = append(current, r)
			escaped = false
			continue
		}

		switch r {
		case '\\':
			if inQuote != 0 {
				escaped = true
			} else {
				current = append(current, r)
			}
		case '"', '\'':
			if inQuote == 0 {
				inQuote = r
			} else if inQuote == r {
				inQuote = 0
			} else {
				current = append(current, r)
			}
		case ' ', '\t':
			if inQuote != 0 {
				current = append(current, r)
			} else if len(current) > 0 {
				args = append(args, string(current))
				current = nil
			}
		default:
			current = append(current, r)
		}
	}

	if len(current) > 0 {
		args = append(args, string(current))
	}

	if inQuote != 0 {
		return nil, fmt.Errorf("unclosed quote in command")
	}

	return args, nil
}
