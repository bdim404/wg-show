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

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if line != "[Peer]" {
			continue
		}

		var nickname, group string

		if i > 0 {
			prevLine := strings.TrimSpace(lines[i-1])

			if strings.HasPrefix(prevLine, "##") {
				nickname = strings.TrimSpace(strings.TrimPrefix(prevLine, "##"))

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
				}
			}
		}

		for j := i + 1; j < len(lines); j++ {
			checkLine := strings.TrimSpace(lines[j])

			if strings.HasPrefix(checkLine, "PublicKey") {
				parts := strings.SplitN(checkLine, "=", 2)
				if len(parts) == 2 {
					publicKey := strings.TrimSpace(parts[1])
					if nickname != "" || group != "" {
						peerMap[publicKey] = PeerInfo{
							Nickname: nickname,
							Group:    group,
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
