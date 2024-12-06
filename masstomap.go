package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/Ullaakut/nmap/v2"
)

type Host struct {
	StartTime int64  `xml:"starttime,attr"`
	XML       string `xml:",innerxml"`
}

type Port struct {
	PortID   string `xml:"portid,attr"`
	Protocol string `xml:"protocol,attr"`
	Service  struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
}

type XMLHost struct {
	Address string `xml:"address>addr,attr"`
	Ports   []Port `xml:"ports>port"`
}

var urls []string
var webprotos = []string{"http", "http-proxy", "https", "https-alt", "ssl"}

// Reset the terminal state after execution
func resetTerminal() {
	cmd := exec.Command("stty", "sane")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// Parse the Masscan report into a map of targets and their ports
func parseMasscanReport(reportPath string) (map[string][]string, error) {
	results := make(map[string][]string)
	file, err := os.Open(reportPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "open tcp") || strings.HasPrefix(line, "open udp") {
			parts := strings.Fields(line)
			if len(parts) < 4 {
				continue
			}
			port := parts[2]
			ip := parts[3]
			results[ip] = append(results[ip], port)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	log.Printf("Parsed %d targets from Masscan report.\n", len(results))
	return results, nil
}

// Generate the .new file in IP:PORT1,PORT2 format
func generateNewFile(targets map[string][]string, newFile string) error {
	file, err := os.Create(newFile)
	if err != nil {
		return fmt.Errorf("failed to create .new file: %v", err)
	}
	defer file.Close()

	for ip, ports := range targets {
		line := fmt.Sprintf("%s:%s\n", ip, strings.Join(ports, ","))
		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("failed to write to .new file: %v", err)
		}
	}

	log.Printf(".new file created: %s\n", newFile)
	return nil
}
func anyWeb(result *nmap.Run) []string {
	var interesting []string
	var url string

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			if port.State.State == "open" {
				for _, proto := range webprotos {
					if port.Protocol == proto {
						if port.Protocol == "https" || port.Protocol == "ssl" {
							if port.ID != 443 {
								url = fmt.Sprintf("https://%s:%s", host.Addresses[0], port.ID)
							} else {
								url = fmt.Sprintf("https://%s", host.Addresses[0])
							}
							interesting = append(interesting, url)
						} else {
							if port.ID != 80 {
								url = fmt.Sprintf("http://%s:%s", host.Addresses[0], port.ID)
							} else {
								url = fmt.Sprintf("http://%s", host.Addresses[0])
							}
							interesting = append(interesting, url)
						}
					}
				}
			}
		}
	}
	return interesting
}

// Run Nmap for each target and generate intermediate files
func runNmap(ip, baseName string, ports []string, minRate int, scripts string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	portsStr := strings.Join(ports, ",")
	xmlOutputFile := fmt.Sprintf("%s.%s.ixml", baseName, ip)
	txtOutputFile := fmt.Sprintf("%s.%s.itxt", baseName, ip)
	grepOutputFile := fmt.Sprintf("%s.%s.igrep", baseName, ip)

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	minRateArg := fmt.Sprintf("--min-rate=%d", minRate)
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithPorts(portsStr),
		nmap.WithServiceInfo(),
		nmap.WithOpenOnly(),
		nmap.WithPrivileged(),
		nmap.WithScripts(scripts),
		nmap.WithCustomArguments("-oN", txtOutputFile, "-oG", grepOutputFile, "-oX", xmlOutputFile, minRateArg),
	)
	if err != nil {
		log.Printf("Error creating scanner for %s: %v\n", ip, err)
		return
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Printf("Error running Nmap for %s: %v\n", ip, err)
		return
	}

	if warnings != nil {
		log.Printf("Warnings for %s: %s\n", ip, warnings)
	}

	xmlData, err := xml.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal XML for %s: %v", ip, err)
		return
	}

	found_urls := anyWeb(result)
	urls = append(urls, found_urls...)

	err = os.WriteFile(xmlOutputFile, xmlData, 0644)
	if err != nil {
		log.Printf("Failed to write XML report for %s: %v", ip, err)
	}

	log.Printf("Nmap scan completed for %s with --min-rate=%d\n", ip, minRate)
}

// Combine intermediate reports into final reports
func combineReports(baseName string, targets map[string][]string) error {
	finalXML := fmt.Sprintf("%s.nmap.xml", baseName)
	finalTXT := fmt.Sprintf("%s.nmap.txt", baseName)
	finalGREP := fmt.Sprintf("%s.nmap.grep", baseName)

	// Collect all intermediate files
	var xmlFiles, txtFiles, grepFiles []string
	for ip := range targets {
		xmlFiles = append(xmlFiles, fmt.Sprintf("%s.%s.ixml", baseName, ip))
		txtFiles = append(txtFiles, fmt.Sprintf("%s.%s.itxt", baseName, ip))
		grepFiles = append(grepFiles, fmt.Sprintf("%s.%s.igrep", baseName, ip))
	}

	// Combine XML files
	if err := combineXMLFiles(xmlFiles, finalXML); err != nil {
		return fmt.Errorf("failed to combine XML files: %v", err)
	}

	// Combine TXT files
	if err := combineTextFiles(txtFiles, finalTXT); err != nil {
		return fmt.Errorf("failed to combine TXT files: %v", err)
	}

	// Combine GREP files
	if err := combineTextFiles(grepFiles, finalGREP); err != nil {
		return fmt.Errorf("failed to combine GREP files: %v", err)
	}

	// Remove intermediate files
	removeIntermediateFiles(xmlFiles, txtFiles, grepFiles)

	return nil
}

// Remove intermediate files
func removeIntermediateFiles(xmlFiles, txtFiles, grepFiles []string) {
	allFiles := append(append(xmlFiles, txtFiles...), grepFiles...)
	for _, file := range allFiles {
		if err := os.Remove(file); err != nil {
			log.Printf("Failed to remove intermediate file %s: %v\n", file, err)
		} else {
			log.Printf("Removed intermediate file: %s\n", file)
		}
	}
}

// Combine XML files into a single XML file
func combineXMLFiles(xmlFiles []string, finalXML string) error {
	type HostEntry struct {
		StartTime int64
		Content   string
	}

	var hosts []HostEntry
	for _, file := range xmlFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Failed to read XML file %s: %v", file, err)
			continue
		}
		var host Host
		if err := xml.Unmarshal(content, &host); err != nil {
			log.Printf("Failed to parse XML file %s: %v", file, err)
			continue
		}
		hosts = append(hosts, HostEntry{
			StartTime: host.StartTime,
			Content:   host.XML,
		})
	}

	// Sort hosts by start time
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].StartTime < hosts[j].StartTime
	})

	// Write combined XML
	outputFile, err := os.Create(finalXML)
	if err != nil {
		return fmt.Errorf("failed to create final XML file: %v", err)
	}
	defer outputFile.Close()

	outputFile.WriteString("<nmaprun>\n")
	for _, host := range hosts {
		outputFile.WriteString(host.Content + "\n")
	}
	outputFile.WriteString("</nmaprun>\n")

	log.Printf("Final XML report created: %s\n", finalXML)
	return nil
}

// Combine text or grep files into a single file
func combineTextFiles(files []string, finalFile string) error {
	outputFile, err := os.Create(finalFile)
	if err != nil {
		return fmt.Errorf("failed to create final file: %v", err)
	}
	defer outputFile.Close()

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Failed to read file %s: %v", file, err)
			continue
		}
		outputFile.Write(content)
		outputFile.WriteString("\n")
	}

	log.Printf("Final file created: %s\n", finalFile)
	return nil
}

func main() {
	masscanFile := flag.String("m", "", "Masscan report file (required)")
	outputFile := flag.String("o", "", "Base output file name (required)")
	scriptList := flag.String("sl", "http-title,http-server-header,http-open-proxy,http-methods,http-headers,ssl-cert", "Comma-separated list of Nmap NSE scripts (default: common web scripts)")
	threads := flag.Int("t", 4, "Number of concurrent Nmap scans")
	userRate := flag.Int("r", 200, "Custom --min-rate value (default: 200)")
	dryRun := flag.Bool("n", false, "Generate only the .new file without running Nmap scans")

	flag.Parse()

	if *masscanFile == "" || *outputFile == "" {
		log.Fatal("Masscan report file (-m) and base output file (-o) are required.")
	}

	targets, err := parseMasscanReport(*masscanFile)
	if err != nil {
		log.Fatalf("Error parsing Masscan report: %v", err)
	}

	// Generate .new file
	newFile := fmt.Sprintf("%s.new", *outputFile)
	if err := generateNewFile(targets, newFile); err != nil {
		log.Fatalf("Error generating .new file: %v", err)
	}

	// Exit if dry run is specified
	if *dryRun {
		log.Println("Dry run completed. Only .new file was generated.")
		return
	}

	// Perform Nmap scans
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *threads)

	for ip, ports := range targets {
		wg.Add(1)
		go runNmap(ip, *outputFile, ports, *userRate, *scriptList, &wg, semaphore)
	}
	wg.Wait()

	// Combine intermediate files into final reports
	if err := combineReports(*outputFile, targets); err != nil {
		log.Fatalf("Error combining reports: %v", err)
	}
	weboutfile := fmt.Sprintf("%s.web", *outputFile)
	webf, err := os.Create(weboutfile)
	if err != nil {
		resetTerminal()
		return
	}
	defer webf.Close()

	for _, url := range urls {
		webf.Write([]byte(url))
		//outputFile.WriteString("\n")
	}

	resetTerminal()
	log.Println("Scanning and report generation completed.")
}
