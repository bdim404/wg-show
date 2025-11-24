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

const version = "1.0.5"

type PeerInfo struct {
	Nickname string
	Group    string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-v" {
		fmt.Printf("wg-show version %s\n", version)
		os.Exit(0)
	}

	args := []string{"show"}
	if len(os.Args) > 1 {
		args = append(args, os.Args[1:]...)
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

	commentLower := strings.ToLower(strings.TrimSpace(comment))
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

	peerMap := make(map[string]PeerInfo)
	scanner := bufio.NewScanner(file)

	var currentNickname string
	var currentGroup string
	var inPeerSection bool
	var publicKey string
	var pendingNickname string
	var pendingGroup string
	var persistentGroup string
	var pendingComments []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "##") && !inPeerSection {
			comment := strings.TrimSpace(strings.TrimPrefix(line, "##"))
			pendingNickname = comment

			if pendingGroup == "" && persistentGroup != "" {
				pendingGroup = persistentGroup
			}

			for i := len(pendingComments) - 1; i >= 0; i-- {
				if !isWgParameter(pendingComments[i]) {
					pendingGroup = pendingComments[i]
					persistentGroup = pendingComments[i]
					break
				}
			}

			pendingComments = nil
		} else if strings.HasPrefix(line, "#") && !inPeerSection {
			comment := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			pendingComments = append(pendingComments, comment)

			if !isWgParameter(comment) {
				persistentGroup = comment
			}

			if pendingNickname == "" {
				pendingNickname = comment
			} else if pendingGroup == "" {
				pendingGroup = comment
			}
		} else if line == "[Peer]" {
			inPeerSection = true
			publicKey = ""
			currentNickname = pendingNickname
			currentGroup = pendingGroup
			pendingNickname = ""
			pendingGroup = ""
			pendingComments = nil
		} else if line == "[Interface]" || (strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")) {
			inPeerSection = false
			currentNickname = ""
			currentGroup = ""
			pendingNickname = ""
			pendingGroup = ""
			persistentGroup = ""
			pendingComments = nil
		} else if inPeerSection {
			if strings.HasPrefix(line, "##") {
				currentNickname = strings.TrimSpace(strings.TrimPrefix(line, "##"))
			} else if strings.HasPrefix(line, "#") {
				comment := strings.TrimSpace(strings.TrimPrefix(line, "#"))
				if currentNickname == "" {
					currentNickname = comment
				} else {
					currentGroup = comment
				}
			} else if strings.HasPrefix(line, "PublicKey") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					publicKey = strings.TrimSpace(parts[1])
					if currentNickname != "" || currentGroup != "" {
						peerMap[publicKey] = PeerInfo{
							Nickname: currentNickname,
							Group:    currentGroup,
						}
					}
					currentNickname = ""
					currentGroup = ""
					inPeerSection = false
				}
			}
		} else if line != "" && !strings.HasPrefix(line, "#") {
			pendingNickname = ""
			pendingGroup = ""
			pendingComments = nil
		}
	}

	return peerMap, scanner.Err()
}

func enhanceOutput(output string, peerMap map[string]PeerInfo) string {
	var result strings.Builder

	yellow := color.New(color.FgYellow).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "peer:") {
			publicKey := strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			result.WriteString(indent)
			result.WriteString(yellow("peer: " + publicKey))
			result.WriteString("\n")

			if info, exists := peerMap[publicKey]; exists {
				if info.Nickname != "" && info.Group != "" {
					result.WriteString("  nickname: ")
					result.WriteString(green(info.Nickname))
					result.WriteString(" (group: ")
					result.WriteString(magenta(info.Group))
					result.WriteString(")\n")
				} else if info.Nickname != "" {
					result.WriteString("  nickname: ")
					result.WriteString(green(info.Nickname))
					result.WriteString("\n")
				} else if info.Group != "" {
					result.WriteString("  nickname: ")
					result.WriteString(cyan(info.Group))
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
