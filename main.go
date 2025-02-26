package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/docker/docker/pkg/namesgenerator" // Docker's name generator package
	"github.com/joho/godotenv"                    // For .env support
	"github.com/russross/blackfriday/v2"
)

var (
	hashPassword      string // Global variable for the hash password
	fqdn              string // Global variable for the FQDN
	port              string // Global variable for the port
	sessionsDir       string // Global variable for the sessions directory
	logger            = log.New(os.Stdout, "shellHandler: ", log.LstdFlags)
	lastCommandOutput = &CommandOutput{} // Global variable to store last command output
)

type CommandOutput struct {
	Output string
	Error  string
	mu     sync.Mutex // Ensures thread-safe access to the output
}
type Resp struct {
	Ticket  int    `json:"ticket"`
	Session string `json:"session"`
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		logger.Fatalf("Error loading .env file: %v", err)
	}

	hashPassword = os.Getenv("HASH")
	fqdn = os.Getenv("FQDN")
	port = os.Getenv("PORT")
	sessionsDir = os.Getenv("SESSIONS_DIR")

	// Validate environment variables
	if len(hashPassword) < 32 {
		logger.Fatalf("HASH must be >= 32 characters: %d", len(hashPassword))
	}

	if fqdn == "" {
		logger.Fatalf("FQDN must be set in .env file")
	}

	if port == "" {
		logger.Fatalf("PORT must be set in .env file")
	}

	if sessionsDir == "" {
		sessionsDir = "sessions" // Default value if not set
		logger.Printf("SESSIONS_DIR not set, using default: %s", sessionsDir)
	}

	// Initialize sessions directory
	log.Println(sessionsDir)
	if err := os.MkdirAll(sessionsDir, 0755); err != nil {
		logger.Fatalf("Failed to initialize sessions directory: %v", err)
	}

}
func getNextTicket(sessionFolder string) (int, error) {
	// Create the full path to the session folder
	log.Println(sessionFolder)

	// Create the session folder if it doesn't exist
	err := os.MkdirAll(sessionFolder, 0755)
	if err != nil {
		return 0, fmt.Errorf("failed to create session folder: %v", err)
	}

	// Read all files in the session folder
	files, err := os.ReadDir(sessionFolder)
	if err != nil {
		return 0, fmt.Errorf("failed to read session folder: %v", err)
	}

	// Find the highest ticket number
	maxTicket := 0
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".ticket" {
			numStr := strings.TrimSuffix(file.Name(), ".ticket")
			num, err := strconv.Atoi(numStr)
			if err == nil && num > maxTicket {
				maxTicket = num
			}
		}
	}

	// Return next ticket number
	return maxTicket + 1, nil
}
func statusHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request is a GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the hash parameter
	ticket, err := strconv.Atoi(r.URL.Query().Get("ticket"))
	if err != nil {
		http.Error(w, "Invalid or missing 'ticket' parameter", http.StatusBadRequest)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		http.Error(w, "Invalid or missing 'hash' parameter", http.StatusUnauthorized)
		return
	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		// Generate a dynamic session name using Docker's namesgenerator if not provided
		session = namesgenerator.GetRandomName(0)
	}

	// If session is provided, create the session directory if it doesn't exist
	sessionFolder := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionFolder); os.IsNotExist(err) {
		if err := os.MkdirAll(sessionFolder, 0755); err != nil {
			logger.Printf("Failed to create session directory %s: %v", sessionFolder, err)
			http.Error(w, fmt.Sprintf("Failed to create session directory: %v", err), http.StatusInternalServerError)
			return
		}
		logger.Printf("Created new session directory: %s", sessionFolder)
	}

	// Read all ticket files in the session
	file, err := os.ReadFile(filepath.Join(sessionsDir, session, fmt.Sprintf("%d.ticket", ticket)))
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s\n", "No ticket found")
		return
	}

	// Set content type to plain text
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s\n", file)
	return
}
func shellHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request is a GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		http.Error(w, "Invalid or missing 'hash' parameter", http.StatusUnauthorized)
		return
	}

	// Get query parameters
	cmdParam := r.URL.Query().Get("cmd")

	// Determine the command to execute
	var finalCmd string
	if cmdParam != "" {
		var erru error
		finalCmd, erru = url.QueryUnescape(cmdParam)
		if erru != nil {
			logger.Printf("Failed to unescape command: %v", erru)
			http.Error(w, fmt.Sprintf("Failed to unescape command: %v", erru), http.StatusBadRequest)
			return
		}

	}

	// Check if session is provided in query parameters
	session := r.URL.Query().Get("session")
	if session == "" {
		// Generate a dynamic session name using Docker's namesgenerator if not provided
		session = namesgenerator.GetRandomName(0)
	}

	// Log the command being executed
	logger.Printf("Executing command for session %s: %s", session, finalCmd)

	// If session is provided, create the session directory if it doesn't exist
	sessionFolder := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionFolder); os.IsNotExist(err) {
		if err := os.MkdirAll(sessionFolder, 0755); err != nil {
			logger.Printf("Failed to create session directory %s: %v", sessionFolder, err)
			http.Error(w, fmt.Sprintf("Failed to create session directory: %v", err), http.StatusInternalServerError)
			return
		}
		logger.Printf("Created new session directory: %s", sessionFolder)
	}

	// Get the next ticket number
	ticket, err := getNextTicket(sessionFolder)
	if err != nil {
		logger.Printf("Failed to generate ticket for session %s: %v", session, err)
		http.Error(w, fmt.Sprintf("Failed to generate ticket: %v", err), http.StatusInternalServerError)
		return
	}

	// Execute the command using a shell to preserve quotes and complex syntax
	cmd := exec.Command("sh", "-c", finalCmd) // Use "cmd" /C on Windows if needed
	output, err := cmd.CombinedOutput()

	// Lock to safely update the global output
	lastCommandOutput.mu.Lock()
	defer lastCommandOutput.mu.Unlock()

	// Store the output or error in lastCommandOutput
	if err != nil {
		lastCommandOutput.Output = ""
		lastCommandOutput.Error = fmt.Sprintf("Error executing command: %v\n%s", err, string(output))
	} else {
		lastCommandOutput.Output = string(output)
		lastCommandOutput.Error = ""
	}

	// Define output filename based on session and ticket
	outputFile := filepath.Join(sessionFolder, fmt.Sprintf("%d.ticket", ticket))

	// Open the output file for writing
	file, fileErr := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if fileErr != nil {
		logger.Printf("Failed to open output file %s: %v", outputFile, fileErr)
		http.Error(w, fmt.Sprintf("Failed to open output file: %v", fileErr), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Write the output or error to the file
	if err != nil {
		_, writeErr := file.WriteString(lastCommandOutput.Error)
		if writeErr != nil {
			logger.Printf("Failed to write error to file %s: %v", outputFile, writeErr)
			http.Error(w, fmt.Sprintf("Failed to write error to file: %v", writeErr), http.StatusInternalServerError)
			return
		}
		logger.Printf("Command %s failed for session %s, ticket %d: %s", finalCmd, session, ticket, lastCommandOutput.Error)
	} else {
		out := fmt.Sprintf("$ %s\n%s", finalCmd, strings.TrimSpace(lastCommandOutput.Output))
		_, writeErr := file.WriteString(out)
		if writeErr != nil {
			logger.Printf("Failed to write output to file %s: %v", outputFile, writeErr)
			http.Error(w, fmt.Sprintf("Failed to write output to file: %v", writeErr), http.StatusInternalServerError)
			return
		}
		logger.Printf("Command %s succeeded for session %s, ticket %d", finalCmd, session, ticket)
	}

	resp := &Resp{
		Ticket:  ticket,
		Session: session,
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		logger.Printf("Failed to marshal JSON response: %v", err)
		http.Error(w, fmt.Sprintf("Failed to marshal JSON response: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, string(jsonResp))
	return
}
func histoyHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request is a GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		http.Error(w, "Invalid or missing 'hash' parameter", http.StatusUnauthorized)
		return
	}

	// Get the session parameter
	session := r.URL.Query().Get("session")
	if session == "" {
		// If no session is specified, fall back to the last command output
		lastCommandOutput.mu.Lock()
		defer lastCommandOutput.mu.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		if lastCommandOutput.Output != "" {
			fmt.Fprintf(w, "%s", lastCommandOutput.Output)
		} else if lastCommandOutput.Error != "" {
			fmt.Fprintf(w, "%s", lastCommandOutput.Error)
		} else {
			fmt.Fprintf(w, "No command has been executed yet")
		}
		return
	}

	// Check if session exists
	sessionPath := filepath.Join(sessionsDir, session)
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		http.Error(w, fmt.Sprintf("Group %s does not exist", session), http.StatusBadRequest)
		return
	}

	// Read all ticket files in the session
	files, err := os.ReadDir(sessionPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read session directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Set content type to plain text
	w.Header().Set("Content-Type", "text/plain")

	// Sort files by ticket number
	tickets := make([]string, 0)
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".ticket" {
			tickets = append(tickets, file.Name())
		}
	}

	if len(tickets) == 0 {
		fmt.Fprintf(w, "No tickets found for session %s", session)
		return
	}

	// Display content of all tickets
	for _, ticket := range tickets {
		content, err := os.ReadFile(filepath.Join(sessionPath, ticket))
		if err != nil {
			logger.Printf("Failed to read ticket %s: %v", ticket, err)
			continue
		}
		fmt.Fprintf(w, "%s\n", content)
	}
	return
}
func readmeHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle the root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Ensure the request is a GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the README.md file
	content, err := os.ReadFile("README.md")
	if err != nil {
		logger.Printf("Failed to read README.md: %v", err)
		http.Error(w, "Failed to read documentation", http.StatusInternalServerError)
		return
	}

	contentStr := strings.ReplaceAll(string(content), "{FQDN}", fqdn)

	// Convert markdown to HTML
	html := blackfriday.Run([]byte(contentStr))
	printHTML(w, string(html))
}

func contextHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle the root path
	if r.URL.Path != "/context" {
		http.NotFound(w, r)
		return
	}

	// Ensure the request is a GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the hash parameter
	hashParam := r.URL.Query().Get("hash")
	if subtle.ConstantTimeCompare([]byte(hashParam), []byte(hashPassword)) != 1 {
		http.Error(w, "Invalid or missing 'hash' parameter", http.StatusUnauthorized)
		return
	}

	// Read the README.md file
	content, err := os.ReadFile("CONTEXT.md")
	if err != nil {
		logger.Printf("Failed to read CONTEXT.md: %v", err)
		http.Error(w, "Failed to read documentation", http.StatusInternalServerError)
		return
	}

	contentStr := strings.ReplaceAll(string(content), "{FQDN}", fqdn)

	// Convert markdown to HTML
	html := blackfriday.Run([]byte(contentStr))
	printHTML(w, string(html))
}

func printHTML(w http.ResponseWriter, html string) {
	// Set content type to HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Write a basic HTML wrapper around the converted markdown
	fmt.Fprintf(w, `<!DOCTYPE html>
	<html>
	<head>
		<title>LLMASS - LLM Asynchronous Shell Scheduler</title>
		<link rel="stylesheet" href="/assets/style.css">
	</head>
	<body>
		<div class="main">
			<div class="header">
				<a class="header-link" href="/">
					<img src="/assets/logo.png" alt="LLMAS Logo" width="200" height="200">
				</a>
			</div>
			<div class="content">
			%s
			</div>
		</div>
	</body>
	</html>`, html)
}

func main() {
	// Load environment variables
	loadEnv()

	// Register handlers for the endpoints
	http.HandleFunc("/", readmeHandler)
	http.HandleFunc("/shell", shellHandler)
	http.HandleFunc("/history", histoyHandler)
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/context", contextHandler)
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
	// Start the server using the PORT from .env
	listenAddr := fmt.Sprintf(":%s", port)
	logger.Printf("Starting server with FQDN: %s on port %s", fqdn, port)
	err := http.ListenAndServe(listenAddr, nil)
	if err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
