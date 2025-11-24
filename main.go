package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

const version = "1.0.8"

type PeerInfo struct {
	Nickname   string
	Group      string
	Maintainer string
}

type PeerData struct {
	PublicKey           string
	Nickname            string
	Group               string
	Maintainer          string
	Endpoint            string
	AllowedIPs          string
	LatestHandshake     string
	HandshakeSeconds    int64
	Transfer            string
	PersistentKeepalive string
}

type InterfaceData struct {
	Name         string
	PublicKey    string
	ListeningPort string
	Peers        []PeerData
}

func main() {
	showTable := false
	filterMaintainer := ""
	filterGroup := ""
	sortHandshake := ""
	var wgArgs []string

	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-v" {
			fmt.Printf("wg-show version %s\n", version)
			os.Exit(0)
		} else if os.Args[i] == "--show-table" {
			showTable = true
		} else if os.Args[i] == "--filter-maintainer" {
			if i+1 < len(os.Args) {
				filterMaintainer = os.Args[i+1]
				i++
			} else {
				fmt.Fprintf(os.Stderr, "Error: --filter-maintainer requires a value\n")
				os.Exit(1)
			}
		} else if os.Args[i] == "--filter-group" {
			if i+1 < len(os.Args) {
				filterGroup = os.Args[i+1]
				i++
			} else {
				fmt.Fprintf(os.Stderr, "Error: --filter-group requires a value\n")
				os.Exit(1)
			}
		} else if os.Args[i] == "--sort-handshake" {
			if i+1 < len(os.Args) {
				sortHandshake = os.Args[i+1]
				if sortHandshake != "asc" && sortHandshake != "desc" {
					fmt.Fprintf(os.Stderr, "Error: --sort-handshake must be 'asc' or 'desc'\n")
					os.Exit(1)
				}
				i++
			} else {
				fmt.Fprintf(os.Stderr, "Error: --sort-handshake requires a value (asc or desc)\n")
				os.Exit(1)
			}
		} else {
			wgArgs = append(wgArgs, os.Args[i])
		}
	}

	args := []string{"show"}
	if len(wgArgs) > 0 {
		args = append(args, wgArgs...)
	}

	cmd := exec.Command("wg", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Stderr.Write(output)
		os.Exit(cmd.ProcessState.ExitCode())
	}

	interfaceName := extractInterfaceName(string(output), args)
	if interfaceName != "" {
		peerMap, err := parseConfig(interfaceName)
		if err == nil && len(peerMap) > 0 {
			if showTable {
				table := generateTableOutput(string(output), peerMap, interfaceName, filterMaintainer, filterGroup, sortHandshake)
				fmt.Print(table)
				return
			}
			enhanced := enhanceOutput(string(output), peerMap, filterMaintainer, filterGroup, sortHandshake)
			fmt.Print(enhanced)
			return
		}
	}

	os.Stdout.Write(output)
}

func extractInterfaceName(output string, args []string) string {
	if len(args) > 1 {
		return args[1]
	}

	re := regexp.MustCompile(`^interface:\s*(\S+)`)
	for _, line := range regexp.MustCompile(`\r?\n`).Split(output, -1) {
		if match := re.FindStringSubmatch(line); match != nil {
			return match[1]
		}
	}

	return ""
}

func isWgParameter(comment string) bool {
	wgParams := []string{
		"Address", "DNS", "MTU", "Table", "PreUp", "PostUp",
		"PreDown", "PostDown", "SaveConfig", "FwMark", "ListenPort",
		"PrivateKey", "PublicKey", "AllowedIPs", "Endpoint",
		"PersistentKeepalive", "PresharedKey",
	}

	commentTrimmed := strings.TrimSpace(comment)

	if strings.Contains(commentTrimmed, "=") {
		parts := strings.SplitN(commentTrimmed, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			keyLower := strings.ToLower(key)
			for _, param := range wgParams {
				if keyLower == strings.ToLower(param) {
					return true
				}
			}
		}
	}

	commentLower := strings.ToLower(commentTrimmed)
	for _, param := range wgParams {
		if strings.HasPrefix(commentLower, strings.ToLower(param)) {
			return true
		}
	}
	return false
}

func parseConfig(interfaceName string) (map[string]PeerInfo, error) {
	configPath := "/etc/wireguard/" + interfaceName + ".conf"
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	peerMap := make(map[string]PeerInfo)
	maintainerRe := regexp.MustCompile(`\(@(\w+)\)$`)

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if line != "[Peer]" {
			continue
		}

		var nickname, group, maintainer string

		if i > 0 {
			prevLine := strings.TrimSpace(lines[i-1])

			if strings.HasPrefix(prevLine, "##") {
				nickname = strings.TrimSpace(strings.TrimPrefix(prevLine, "##"))

				if match := maintainerRe.FindStringSubmatch(nickname); match != nil {
					maintainer = match[1]
					nickname = strings.TrimSpace(maintainerRe.ReplaceAllString(nickname, ""))
				}

				for j := i - 2; j >= 0; j-- {
					checkLine := strings.TrimSpace(lines[j])
					if checkLine == "" {
						continue
					}
					if checkLine == "[Interface]" {
						break
					}
					if !strings.HasPrefix(checkLine, "#") {
						continue
					}
					if strings.HasPrefix(checkLine, "##") {
						continue
					}

					comment := strings.TrimSpace(strings.TrimPrefix(checkLine, "#"))
					if !isWgParameter(comment) {
						group = comment
						break
					}
				}
			} else if strings.HasPrefix(prevLine, "#") {
				comment := strings.TrimSpace(strings.TrimPrefix(prevLine, "#"))
				if !isWgParameter(comment) {
					nickname = comment

					if match := maintainerRe.FindStringSubmatch(nickname); match != nil {
						maintainer = match[1]
						nickname = strings.TrimSpace(maintainerRe.ReplaceAllString(nickname, ""))
					}
				}
			}
		}

		for j := i + 1; j < len(lines); j++ {
			checkLine := strings.TrimSpace(lines[j])

			if strings.HasPrefix(checkLine, "PublicKey") {
				parts := strings.SplitN(checkLine, "=", 2)
				if len(parts) == 2 {
					publicKey := strings.TrimSpace(parts[1])
					if nickname != "" || group != "" || maintainer != "" {
						peerMap[publicKey] = PeerInfo{
							Nickname:   nickname,
							Group:      group,
							Maintainer: maintainer,
						}
					}
				}
				break
			}

			if checkLine == "[Peer]" || checkLine == "[Interface]" {
				break
			}
		}
	}

	return peerMap, nil
}

func parseHandshakeTime(handshake string) int64 {
	if handshake == "" {
		return time.Now().Unix() + 999999999
	}

	var totalSeconds int64 = 0

	parts := strings.Split(handshake, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "day") {
			re := regexp.MustCompile(`(\d+)\s+day`)
			if match := re.FindStringSubmatch(part); match != nil {
				if days, err := strconv.ParseInt(match[1], 10, 64); err == nil {
					totalSeconds += days * 86400
				}
			}
		} else if strings.Contains(part, "hour") {
			re := regexp.MustCompile(`(\d+)\s+hour`)
			if match := re.FindStringSubmatch(part); match != nil {
				if hours, err := strconv.ParseInt(match[1], 10, 64); err == nil {
					totalSeconds += hours * 3600
				}
			}
		} else if strings.Contains(part, "minute") {
			re := regexp.MustCompile(`(\d+)\s+minute`)
			if match := re.FindStringSubmatch(part); match != nil {
				if minutes, err := strconv.ParseInt(match[1], 10, 64); err == nil {
					totalSeconds += minutes * 60
				}
			}
		} else if strings.Contains(part, "second") {
			re := regexp.MustCompile(`(\d+)\s+second`)
			if match := re.FindStringSubmatch(part); match != nil {
				if seconds, err := strconv.ParseInt(match[1], 10, 64); err == nil {
					totalSeconds += seconds
				}
			}
		}
	}

	return totalSeconds
}

func shouldShowPeer(info PeerInfo, filterMaintainer string, filterGroup string) bool {
	if filterMaintainer != "" && info.Maintainer != filterMaintainer {
		return false
	}
	if filterGroup != "" && info.Group != filterGroup {
		return false
	}
	return true
}

func enhanceOutput(output string, peerMap map[string]PeerInfo, filterMaintainer string, filterGroup string, sortHandshake string) string {
	ifaceData := parseWgOutput(output, peerMap)

	var filteredPeers []PeerData
	for _, peer := range ifaceData.Peers {
		info := PeerInfo{
			Nickname:   peer.Nickname,
			Group:      peer.Group,
			Maintainer: peer.Maintainer,
		}
		if shouldShowPeer(info, filterMaintainer, filterGroup) {
			filteredPeers = append(filteredPeers, peer)
		}
	}

	if sortHandshake == "asc" {
		sort.Slice(filteredPeers, func(i, j int) bool {
			return filteredPeers[i].HandshakeSeconds < filteredPeers[j].HandshakeSeconds
		})
	} else if sortHandshake == "desc" {
		sort.Slice(filteredPeers, func(i, j int) bool {
			return filteredPeers[i].HandshakeSeconds > filteredPeers[j].HandshakeSeconds
		})
	}

	var result strings.Builder
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "interface:") || strings.HasPrefix(trimmed, "public key:") ||
			strings.HasPrefix(trimmed, "private key:") || strings.HasPrefix(trimmed, "listening port:") ||
			strings.HasPrefix(trimmed, "fwmark:") {
			if strings.HasPrefix(trimmed, "interface:") {
				interfaceName := strings.TrimSpace(strings.TrimPrefix(trimmed, "interface:"))
				result.WriteString(cyan("interface: " + interfaceName))
			} else {
				result.WriteString(line)
			}
			result.WriteString("\n")
		} else if strings.HasPrefix(trimmed, "peer:") {
			break
		} else if trimmed == "" {
			result.WriteString("\n")
		}
	}

	for _, peer := range filteredPeers {
		result.WriteString(yellow("peer: " + peer.PublicKey))
		result.WriteString("\n")

		if peer.Nickname != "" {
			result.WriteString("  nickname: ")
			result.WriteString(green(peer.Nickname))
			result.WriteString("\n")
		}
		if peer.Maintainer != "" {
			result.WriteString("  maintainer: ")
			result.WriteString(blue(peer.Maintainer))
			result.WriteString("\n")
		}
		if peer.Group != "" {
			result.WriteString("  group: ")
			result.WriteString(magenta(peer.Group))
			result.WriteString("\n")
		}
		if peer.Endpoint != "" {
			result.WriteString("  endpoint: " + peer.Endpoint + "\n")
		}
		if peer.AllowedIPs != "" {
			result.WriteString("  allowed ips: " + peer.AllowedIPs + "\n")
		}
		if peer.LatestHandshake != "" {
			result.WriteString("  latest handshake: " + peer.LatestHandshake + "\n")
		}
		if peer.Transfer != "" {
			result.WriteString("  transfer: " + peer.Transfer + "\n")
		}
		if peer.PersistentKeepalive != "" {
			result.WriteString("  persistent keepalive: " + peer.PersistentKeepalive + "\n")
		}
		result.WriteString("\n")
	}

	return result.String()
}

func parseWgOutput(output string, peerMap map[string]PeerInfo) InterfaceData {
	var ifaceData InterfaceData
	var currentPeer *PeerData

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "interface:") {
			ifaceData.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "interface:"))
		} else if strings.HasPrefix(trimmed, "public key:") {
			if currentPeer == nil {
				ifaceData.PublicKey = strings.TrimSpace(strings.TrimPrefix(trimmed, "public key:"))
			}
		} else if strings.HasPrefix(trimmed, "listening port:") {
			ifaceData.ListeningPort = strings.TrimSpace(strings.TrimPrefix(trimmed, "listening port:"))
		} else if strings.HasPrefix(trimmed, "peer:") {
			if currentPeer != nil {
				ifaceData.Peers = append(ifaceData.Peers, *currentPeer)
			}
			publicKey := strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
			currentPeer = &PeerData{
				PublicKey: publicKey,
			}
			if info, exists := peerMap[publicKey]; exists {
				currentPeer.Nickname = info.Nickname
				currentPeer.Group = info.Group
				currentPeer.Maintainer = info.Maintainer
			}
		} else if currentPeer != nil {
			if strings.HasPrefix(trimmed, "endpoint:") {
				currentPeer.Endpoint = strings.TrimSpace(strings.TrimPrefix(trimmed, "endpoint:"))
			} else if strings.HasPrefix(trimmed, "allowed ips:") {
				currentPeer.AllowedIPs = strings.TrimSpace(strings.TrimPrefix(trimmed, "allowed ips:"))
			} else if strings.HasPrefix(trimmed, "latest handshake:") {
				handshake := strings.TrimSpace(strings.TrimPrefix(trimmed, "latest handshake:"))
				currentPeer.LatestHandshake = handshake
				currentPeer.HandshakeSeconds = parseHandshakeTime(handshake)
			} else if strings.HasPrefix(trimmed, "transfer:") {
				currentPeer.Transfer = strings.TrimSpace(strings.TrimPrefix(trimmed, "transfer:"))
			} else if strings.HasPrefix(trimmed, "persistent keepalive:") {
				currentPeer.PersistentKeepalive = strings.TrimSpace(strings.TrimPrefix(trimmed, "persistent keepalive:"))
			}
		}
	}

	if currentPeer != nil {
		ifaceData.Peers = append(ifaceData.Peers, *currentPeer)
	}

	return ifaceData
}

func generateTableOutput(output string, peerMap map[string]PeerInfo, interfaceName string, filterMaintainer string, filterGroup string, sortHandshake string) string {
	ifaceData := parseWgOutput(output, peerMap)

	var result strings.Builder

	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()
	white := color.New(color.FgWhite, color.Bold).SprintFunc()

	result.WriteString(cyan("Interface: ") + ifaceData.Name + "\n")
	if ifaceData.PublicKey != "" {
		result.WriteString(white("Public Key: ") + ifaceData.PublicKey + "\n")
	}
	if ifaceData.ListeningPort != "" {
		result.WriteString(white("Listening Port: ") + ifaceData.ListeningPort + "\n")
	}
	result.WriteString("\n")

	var filteredPeers []PeerData
	for _, peer := range ifaceData.Peers {
		info := PeerInfo{
			Nickname:   peer.Nickname,
			Group:      peer.Group,
			Maintainer: peer.Maintainer,
		}
		if shouldShowPeer(info, filterMaintainer, filterGroup) {
			filteredPeers = append(filteredPeers, peer)
		}
	}

	if sortHandshake == "asc" {
		sort.Slice(filteredPeers, func(i, j int) bool {
			return filteredPeers[i].HandshakeSeconds < filteredPeers[j].HandshakeSeconds
		})
	} else if sortHandshake == "desc" {
		sort.Slice(filteredPeers, func(i, j int) bool {
			return filteredPeers[i].HandshakeSeconds > filteredPeers[j].HandshakeSeconds
		})
	}

	if len(filteredPeers) == 0 {
		result.WriteString("No peers found.\n")
		return result.String()
	}

	result.WriteString(white("Peers:\n"))
	result.WriteString(strings.Repeat("─", 120) + "\n")

	header := fmt.Sprintf("%-20s %-15s %-15s %-30s %-20s",
		"Nickname", "Maintainer", "Group", "Endpoint", "Handshake")
	result.WriteString(white(header) + "\n")
	result.WriteString(strings.Repeat("─", 120) + "\n")

	for _, peer := range filteredPeers {
		nickname := peer.Nickname
		if nickname == "" {
			nickname = peer.PublicKey[:16] + "..."
		}

		maintainer := peer.Maintainer
		if maintainer == "" {
			maintainer = "-"
		}

		group := peer.Group
		if group == "" {
			group = "-"
		}

		endpoint := peer.Endpoint
		if endpoint == "" {
			endpoint = "-"
		}

		handshake := peer.LatestHandshake
		if handshake == "" {
			handshake = "-"
		}

		nicknameTrunc := truncate(nickname, 20)
		maintainerTrunc := truncate(maintainer, 15)
		groupTrunc := truncate(group, 15)
		endpointTrunc := truncate(endpoint, 30)
		handshakeTrunc := truncate(handshake, 20)

		result.WriteString(green(padRight(nicknameTrunc, 20)))
		result.WriteString(" ")
		result.WriteString(blue(padRight(maintainerTrunc, 15)))
		result.WriteString(" ")
		result.WriteString(magenta(padRight(groupTrunc, 15)))
		result.WriteString(" ")
		result.WriteString(yellow(padRight(endpointTrunc, 30)))
		result.WriteString(" ")
		result.WriteString(padRight(handshakeTrunc, 20))
		result.WriteString("\n")

		if peer.AllowedIPs != "" {
			result.WriteString(fmt.Sprintf("  Allowed IPs: %s\n", peer.AllowedIPs))
		}
		if peer.Transfer != "" {
			result.WriteString(fmt.Sprintf("  Transfer: %s\n", peer.Transfer))
		}
		result.WriteString("\n")
	}

	return result.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
