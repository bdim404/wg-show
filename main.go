package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

const version = "1.0.7"

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
	var wgArgs []string

	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-v" {
			fmt.Printf("wg-show version %s\n", version)
			os.Exit(0)
		} else if os.Args[i] == "--show-table" {
			showTable = true
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
				table := generateTableOutput(string(output), peerMap, interfaceName)
				fmt.Print(table)
				return
			}
			enhanced := enhanceOutput(string(output), peerMap)
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

func enhanceOutput(output string, peerMap map[string]PeerInfo) string {
	var result strings.Builder

	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()
	blue := color.New(color.FgBlue, color.Bold).SprintFunc()

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "interface:") {
			interfaceName := strings.TrimSpace(strings.TrimPrefix(trimmed, "interface:"))
			result.WriteString(cyan("interface: " + interfaceName))
			result.WriteString("\n")
		} else if strings.HasPrefix(trimmed, "peer:") {
			publicKey := strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			result.WriteString(indent)
			result.WriteString(yellow("peer: " + publicKey))
			result.WriteString("\n")

			if info, exists := peerMap[publicKey]; exists {
				if info.Nickname != "" {
					result.WriteString("  nickname: ")
					result.WriteString(green(info.Nickname))
					result.WriteString("\n")
				}
				if info.Maintainer != "" {
					result.WriteString("  maintainer: ")
					result.WriteString(blue(info.Maintainer))
					result.WriteString("\n")
				}
				if info.Group != "" {
					result.WriteString("  group: ")
					result.WriteString(magenta(info.Group))
					result.WriteString("\n")
				}
			}
		} else {
			result.WriteString(line)
			result.WriteString("\n")
		}
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
				currentPeer.LatestHandshake = strings.TrimSpace(strings.TrimPrefix(trimmed, "latest handshake:"))
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

func generateTableOutput(output string, peerMap map[string]PeerInfo, interfaceName string) string {
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

	if len(ifaceData.Peers) == 0 {
		result.WriteString("No peers found.\n")
		return result.String()
	}

	result.WriteString(white("Peers:\n"))
	result.WriteString(strings.Repeat("─", 120) + "\n")

	header := fmt.Sprintf("%-20s %-15s %-15s %-30s %-20s",
		"Nickname", "Maintainer", "Group", "Endpoint", "Handshake")
	result.WriteString(white(header) + "\n")
	result.WriteString(strings.Repeat("─", 120) + "\n")

	for _, peer := range ifaceData.Peers {
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
