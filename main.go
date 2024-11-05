package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Alert represents a connection attempt alert.
type Alert struct {
	Port      int       `json:"port"`
	RemoteIP  string    `json:"remote_ip"`
	Timestamp time.Time `json:"timestamp"`
}

// AlertConfig holds the configuration for alerts and logging.
type AlertConfig struct {
	LogToFile      bool   `json:"LogToFile"`      // Whether to log to a file
	PostToServer   bool   `json:"PostToServer"`   // Whether to send HTTP POST requests
	ServerURL      string `json:"ServerURL"`      // URL to send POST requests to
	BanIP          bool   `json:"BanIP"`          // Whether to ban the IP
	BanDuration    int    `json:"BanDuration"`    // Duration to ban IP (minutes), 0 for permanent
	PortsToMonitor []int  `json:"PortsToMonitor"` // List of ports to monitor
	LogFile        string `json:"LogFile"`        // Path to the log file
}

// Default configuration values.
var defaultConfig = AlertConfig{
	LogToFile:    true,
	PostToServer: true,
	ServerURL:    "https://yourserver.com/alert",
	BanIP:        true,
	BanDuration:  10, // Default ban duration: 10 minutes
	PortsToMonitor: []int{
		445,  // SMB
		135,  // RPC
		139,  // NetBIOS
		5985, // WinRM
		3389, // RDP
		22,   // SSH
		1433, // Microsoft SQL Server
		3306, // MySQL
		5900, // VNC
		1723, // PPTP VPN
		8000, // HTTP Alternate
		8080, // HTTP Alternate
		3268, // Global Catalog (Active Directory)
		389,  // LDAP
		636,  // LDAPS
		21,   // FTP
	},
	LogFile: "./LogFile.txt",
}

// loadConfig reads the configuration from a JSON file.
func loadConfig(filename string) (AlertConfig, error) {
	var config AlertConfig

	file, err := os.Open(filename)
	if err != nil {
		return config, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %v", err)
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		return config, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Populate default values if not set
	if config.PortsToMonitor == nil || len(config.PortsToMonitor) == 0 {
		config.PortsToMonitor = defaultConfig.PortsToMonitor
	}
	if config.LogFile == "" {
		config.LogFile = defaultConfig.LogFile
	}

	return config, nil
}

// banIP bans the specified IP using iptables for the given duration.
func banIP(ip string, duration int) {
	if duration == 0 {
		// Permanent ban
		cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to permanently ban IP %s: %v", ip, err)
		} else {
			log.Printf("Permanently banned IP: %s", ip)
		}
	} else {
		// Temporary ban
		cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to temporarily ban IP %s: %v", ip, err)
		} else {
			log.Printf("Temporarily banned IP %s for %d minutes", ip, duration)
			// Schedule unban
			time.AfterFunc(time.Duration(duration)*time.Minute, func() {
				unbanIP(ip)
			})
		}
	}
}

// unbanIP removes the ban on the specified IP.
func unbanIP(ip string) {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to unban IP %s: %v", ip, err)
	} else {
		log.Printf("Unbanned IP: %s", ip)
	}
}

// sendAlert handles alert actions based on the configuration.
func sendAlert(alert Alert, config AlertConfig) {
	// Log to file
	if config.LogToFile {
		logMessage := fmt.Sprintf("%s - Alert: Connection attempt detected on port %d from IP %s",
			alert.Timestamp.Format(time.RFC3339), alert.Port, alert.RemoteIP)
		log.Println(logMessage)
	}

	// Send HTTP POST request
	if config.PostToServer && config.ServerURL != "" {
		payload, err := json.Marshal(alert)
		if err != nil {
			log.Printf("Failed to marshal alert: %v", err)
		} else {
			resp, err := http.Post(config.ServerURL, "application/json", bytes.NewBuffer(payload))
			if err != nil {
				log.Printf("Failed to send alert to server: %v", err)
			} else {
				defer resp.Body.Close()
				log.Printf("Alert sent to server: %s", config.ServerURL)
			}
		}
	}

	// Ban the IP
	if config.BanIP {
		banIP(alert.RemoteIP, config.BanDuration)
	}
}

// isPortListening checks if a given port is already in use.
func isPortListening(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true // Assume port is in use
	}
	ln.Close()
	return false
}

// startPortListener starts listening on a specified port and handles incoming connections.
func startPortListener(port int, wg *sync.WaitGroup, stopChan <-chan struct{}, config AlertConfig) {
	defer wg.Done()

	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Failed to start listener on port %d: %v", port, err)
		return
	}
	defer listener.Close()

	log.Printf("Started listening on port %d as honeypot.", port)

	for {
		// Use channels to handle incoming connections and errors
		connChan := make(chan net.Conn)
		errChan := make(chan error)

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				errChan <- err
				return
			}
			connChan <- conn
		}()

		select {
		case <-stopChan:
			log.Printf("Stopping listener on port %d.", port)
			return
		case err := <-errChan:
			log.Printf("Error on port %d: %v", port, err)
			return
		case conn := <-connChan:
			remoteAddr := conn.RemoteAddr().String()
			log.Printf("Connection attempt detected on port %d from %s", port, remoteAddr)

			// Extract IP without port
			host, _, err := net.SplitHostPort(remoteAddr)
			ip := host
			if err != nil {
				log.Printf("Failed to parse remote address: %v", err)
				ip = remoteAddr // Fallback to the full address
			}

			// Create and send alert
			alert := Alert{
				Port:      port,
				RemoteIP:  ip,
				Timestamp: time.Now(),
			}
			sendAlert(alert, config)

			// Close the connection immediately
			conn.Close()
		}
	}
}

func main() {
	// Load configuration
	config, err := loadConfig("./config.json")
	if err != nil {
		log.Printf("Failed to load config: %v. Using default configuration.", err)
		config = defaultConfig
	}

	// Setup logging
	logpath := "./LogFile.txt"
	if config.LogFile != "" {
		logpath = config.LogFile
	}
	logFile, err := os.OpenFile(logpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	// Capture system interrupt signals to gracefully shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start honeypot listeners
	for _, port := range config.PortsToMonitor {
		if !isPortListening(port) {
			wg.Add(1)
			go startPortListener(port, &wg, stopChan, config)
			log.Printf("Started honeypot on port %d.", port)
		} else {
			log.Printf("Port %d is already in use by a legitimate service. Skipping honeypot setup for this port.", port)
		}
	}

	log.Println("Honeypot is running. Press Ctrl+C to stop.")

	// Wait for interrupt signal
	<-signalChan
	log.Println("Shutting down honeypot...")

	// Close all listeners
	close(stopChan)

	// Wait for all listeners to shut down
	wg.Wait()

	log.Println("Honeypot stopped.")
}
