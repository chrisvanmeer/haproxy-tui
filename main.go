package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ServerMember represents a target backend server record parsed from HAProxy stats
type ServerMember struct {
	Backend string
	Server  string
	Status  string
	Weight  string
}

// SSHConfig holds resolved host connection options from ~/.ssh/config
type SSHConfig struct {
	HostName      string
	User          string
	Port          string
	IdentityFiles []string
}

// Commands & Messages for Bubbletea
type statusFetchedMsg []ServerMember
type actionCompletedMsg string
type errMsg error
type tickMsg time.Time

// Model definition
type model struct {
	targetHost       string
	members          []ServerMember
	cursor           int
	statusMsg        string
	err              error
	loading          bool
	terminalWidth    int
	terminalHeight   int
	refreshCountdown int
}

// Cyberpunk Styling Palette (Lipgloss)
var (
	cyan   = lipgloss.Color("#00F5FF")
	pink   = lipgloss.Color("#FF007F")
	purple = lipgloss.Color("#9D00FF")
	yellow = lipgloss.Color("#FFE600")
	green  = lipgloss.Color("#00FF66")
	red    = lipgloss.Color("#FF0055")
	orange = lipgloss.Color("#FF9900")
	darkBg = lipgloss.Color("#120024")
	gray   = lipgloss.Color("#555555")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan).
			Background(darkBg).
			Padding(0, 2).
			Border(lipgloss.DoubleBorder()).
			BorderForeground(pink)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(pink).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(purple)

	rowSelectedStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(darkBg).
				Background(cyan)

	rowNormalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0E0E0"))

	statusMsgStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(yellow).
			MarginTop(1)

	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(red).
			MarginTop(1)

	helpStyle = lipgloss.NewStyle().
			Foreground(gray).
			MarginTop(1)
)

// Column widths definition for visual alignment
const (
	colCursorWidth  = 2
	colBackendWidth = 20
	colServerWidth  = 54
	colStatusWidth  = 14
	colWeightWidth  = 8
)

// Ticker command firing every 1 second
func doTick() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Parse ~/.ssh/config for SSH aliases and configurations
func parseSSHConfig(alias string) SSHConfig {
	cfg := SSHConfig{
		HostName: alias,
		User:     os.Getenv("USER"),
		Port:     "22",
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return cfg
	}

	configFile := filepath.Join(home, ".ssh", "config")
	file, err := os.Open(configFile)
	if err != nil {
		return cfg
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inMatchingHost := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(fields[0])

		if key == "host" {
			inMatchingHost = false
			for _, pattern := range fields[1:] {
				matched, _ := filepath.Match(pattern, alias)
				if matched || pattern == alias {
					inMatchingHost = true
					break
				}
			}
			continue
		}

		if inMatchingHost {
			val := fields[1]
			switch key {
			case "hostname":
				cfg.HostName = val
			case "user":
				cfg.User = val
			case "port":
				cfg.Port = val
			case "identityfile":
				if strings.HasPrefix(val, "~/") {
					val = filepath.Join(home, val[2:])
				}
				cfg.IdentityFiles = append(cfg.IdentityFiles, val)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		_ = err
	}

	return cfg
}

// Collect public key authentication methods from SSH Agent and keyfiles
func getSSHAuthMethods(customKeys []string) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod

	if socketPath := os.Getenv("SSH_AUTH_SOCK"); socketPath != "" {
		if conn, err := net.Dial("unix", socketPath); err == nil {
			agentClient := agent.NewClient(conn)
			auths = append(auths, ssh.PublicKeysCallback(agentClient.Signers))
		}
	}

	home, _ := os.UserHomeDir()
	keyCandidates := append([]string{}, customKeys...)
	if home != "" {
		keyCandidates = append(keyCandidates,
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".ssh", "id_ecdsa"),
			filepath.Join(home, ".ssh", "id_dsa"),
		)
	}

	seen := make(map[string]bool)
	for _, keyPath := range keyCandidates {
		if seen[keyPath] {
			continue
		}
		seen[keyPath] = true

		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			continue
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}

	if len(auths) == 0 {
		return nil, fmt.Errorf("no valid SSH authentication found (check SSH agent or ~/.ssh keys)")
	}

	return auths, nil
}

// Execute HAProxy command over native SSH stream
func executeHAProxySocatNative(target string, socatCmd string) (string, error) {
	user := ""
	host := target
	port := ""

	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		user = parts[0]
		host = parts[1]
	}

	if strings.Contains(host, ":") {
		parts := strings.SplitN(host, ":", 2)
		host = parts[0]
		port = parts[1]
	}

	sshCfg := parseSSHConfig(host)

	if user == "" {
		user = sshCfg.User
	}
	if port == "" {
		port = sshCfg.Port
	}
	resolvedHost := sshCfg.HostName

	auths, err := getSSHAuthMethods(sshCfg.IdentityFiles)
	if err != nil {
		return "", err
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(resolvedHost, port), config)
	if err != nil {
		return "", fmt.Errorf("ssh dial failed (%s@%s:%s): %w", user, resolvedHost, port, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to open ssh session: %w", err)
	}
	defer session.Close()

	bashScript := fmt.Sprintf(`
socat_cmd=%q
socat_socket=$(sudo awk '
	/stats socket/ {
		if ($0 ~ /haproxy_admin/) {
			socket = $3
			exit
		}
		if (!fallback) {
			fallback = $3
		}
	}
	END {
		if (socket) print socket
		else if (fallback) print fallback
	}
' /etc/haproxy/haproxy.cfg)

if [[ -z "$socat_socket" ]]; then
	echo "No stats socket found in /etc/haproxy/haproxy.cfg" >&2
	exit 1
fi

echo "$socat_cmd" | sudo socat unix-connect:"$socat_socket" stdio
`, socatCmd)

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	session.Stdin = strings.NewReader(bashScript)

	err = session.Run("bash -s")
	if err != nil {
		return "", fmt.Errorf("ssh execution failed: %v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
}

// Fetch stats command
func fetchStatsCmd(targetHost string) tea.Cmd {
	return func() tea.Msg {
		out, err := executeHAProxySocatNative(targetHost, "show stat")
		if err != nil {
			return errMsg(err)
		}

		r := csv.NewReader(strings.NewReader(out))
		r.Comment = '#'
		r.FieldsPerRecord = -1

		var members []ServerMember
		for {
			record, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil || len(record) < 19 {
				continue
			}

			pxname := record[0]
			svname := record[1]
			status := record[17]
			weight := record[18]

			if svname == "FRONTEND" || svname == "BACKEND" {
				continue
			}

			members = append(members, ServerMember{
				Backend: pxname,
				Server:  svname,
				Status:  status,
				Weight:  weight,
			})
		}

		sort.Slice(members, func(i, j int) bool {
			if members[i].Backend == members[j].Backend {
				return members[i].Server < members[j].Server
			}
			return members[i].Backend < members[j].Backend
		})

		return statusFetchedMsg(members)
	}
}

// Perform server state toggling (enable/disable)
func toggleServerCmd(targetHost, backend, server, action string) tea.Cmd {
	return func() tea.Msg {
		command := fmt.Sprintf("%s server %s/%s", action, backend, server)
		_, err := executeHAProxySocatNative(targetHost, command)
		if err != nil {
			return errMsg(err)
		}
		return actionCompletedMsg(fmt.Sprintf("[%s] Executed '%s' on %s/%s", strings.ToUpper(action), action, backend, server))
	}
}

func initialModel(targetHost string) model {
	return model{
		targetHost:       targetHost,
		loading:          true,
		refreshCountdown: 10,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		fetchStatsCmd(m.targetHost),
		doTick(),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.terminalWidth = msg.Width
		m.terminalHeight = msg.Height

	case tickMsg:
		m.refreshCountdown--
		if m.refreshCountdown <= 0 {
			m.refreshCountdown = 10
			return m, tea.Batch(
				fetchStatsCmd(m.targetHost),
				doTick(),
			)
		}
		return m, doTick()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.members)-1 {
				m.cursor++
			}

		case "r":
			m.loading = true
			m.err = nil
			m.refreshCountdown = 10
			return m, fetchStatsCmd(m.targetHost)

		case "d":
			if len(m.members) > 0 {
				m.loading = true
				selected := m.members[m.cursor]
				m.refreshCountdown = 10
				return m, toggleServerCmd(m.targetHost, selected.Backend, selected.Server, "disable")
			}

		case "e":
			if len(m.members) > 0 {
				m.loading = true
				selected := m.members[m.cursor]
				m.refreshCountdown = 10
				return m, toggleServerCmd(m.targetHost, selected.Backend, selected.Server, "enable")
			}
		}

	case statusFetchedMsg:
		m.members = msg
		m.loading = false
		if m.cursor >= len(m.members) && len(m.members) > 0 {
			m.cursor = len(m.members) - 1
		}

	case actionCompletedMsg:
		m.statusMsg = string(msg)
		m.refreshCountdown = 10
		return m, fetchStatsCmd(m.targetHost)

	case errMsg:
		m.err = msg
		m.loading = false
	}

	return m, nil
}

// Format status cell with background matching selection state
func formatStatus(status string, isSelected bool) string {
	upper := strings.ToUpper(status)
	style := lipgloss.NewStyle().Bold(true).Width(colStatusWidth)

	if isSelected {
		style = style.Background(cyan)
		switch {
		case strings.HasPrefix(upper, "UP"):
			style = style.Foreground(lipgloss.Color("#005F00"))
		case strings.HasPrefix(upper, "DOWN"):
			style = style.Foreground(red)
		case strings.HasPrefix(upper, "MAINT"):
			style = style.Foreground(lipgloss.Color("#994400"))
		case strings.HasPrefix(upper, "DRAIN"):
			style = style.Foreground(purple)
		default:
			style = style.Foreground(darkBg)
		}
	} else {
		switch {
		case strings.HasPrefix(upper, "UP"):
			style = style.Foreground(green)
		case strings.HasPrefix(upper, "DOWN"):
			style = style.Foreground(red)
		case strings.HasPrefix(upper, "MAINT"):
			style = style.Foreground(orange)
		case strings.HasPrefix(upper, "DRAIN"):
			style = style.Foreground(cyan)
		default:
			style = style.Foreground(lipgloss.Color("#E0E0E0"))
		}
	}

	return style.Render(status)
}

func (m model) View() string {
	var s strings.Builder

	title := fmt.Sprintf("⚡ HAPROXY TUI // TARGET: %s ⚡", strings.ToUpper(m.targetHost))
	s.WriteString(titleStyle.Render(title))
	s.WriteString("\n\n")

	if m.loading && len(m.members) == 0 {
		s.WriteString(lipgloss.NewStyle().Foreground(pink).Render("  [>] Fetching topology & statuses via SSH..."))
		return s.String()
	}

	if m.err != nil {
		s.WriteString(errorStyle.Render(fmt.Sprintf("  ERROR: %v", m.err)))
		s.WriteString("\n\n")
		s.WriteString(helpStyle.Render("  Press 'r' to retry or 'q' to quit."))
		return s.String()
	}

	header := lipgloss.JoinHorizontal(
		lipgloss.Left,
		headerStyle.Width(colCursorWidth).Render(""),
		headerStyle.Width(colBackendWidth).Render("BACKEND"),
		headerStyle.Width(colServerWidth).Render("SERVER"),
		headerStyle.Width(colStatusWidth).Render("STATUS"),
		headerStyle.Width(colWeightWidth).Render("WEIGHT"),
	)
	s.WriteString("  ")
	s.WriteString(header)
	s.WriteString("\n")

	for i, mbr := range m.members {
		isSelected := m.cursor == i
		cursorSymbol := " "
		if isSelected {
			cursorSymbol = "▶"
		}

		statusStr := formatStatus(mbr.Status, isSelected)

		var rowStr string
		if isSelected {
			rowStr = lipgloss.JoinHorizontal(
				lipgloss.Left,
				rowSelectedStyle.Width(colCursorWidth).Render(cursorSymbol),
				rowSelectedStyle.Width(colBackendWidth).Render(mbr.Backend),
				rowSelectedStyle.Width(colServerWidth).Render(mbr.Server),
				statusStr,
				rowSelectedStyle.Width(colWeightWidth).Render(mbr.Weight),
			)
		} else {
			rowStr = lipgloss.JoinHorizontal(
				lipgloss.Left,
				rowNormalStyle.Width(colCursorWidth).Render(cursorSymbol),
				rowNormalStyle.Width(colBackendWidth).Render(mbr.Backend),
				rowNormalStyle.Width(colServerWidth).Render(mbr.Server),
				statusStr,
				rowNormalStyle.Width(colWeightWidth).Render(mbr.Weight),
			)
		}

		s.WriteString("  ")
		s.WriteString(rowStr)
		s.WriteString("\n")
	}

	if m.statusMsg != "" {
		s.WriteString(statusMsgStyle.Render("  ➜ " + m.statusMsg))
		s.WriteString("\n")
	}

	help := fmt.Sprintf("\n  [↑/k] Up  [↓/j] Down  •  [d] Disable Server  •  [e] Enable Server  •  [r] Refresh  •  [q] Quit  (Auto-refresh in: %ds)", m.refreshCountdown)
	s.WriteString(helpStyle.Render(help))
	s.WriteString("\n")

	return s.String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(lipgloss.NewStyle().Foreground(red).Render("Usage: haproxyTUI <[user@]ssh_target_host[:port]>"))
		fmt.Println("Example: haproxyTUI ha02")
		os.Exit(1)
	}

	targetHost := os.Args[1]
	p := tea.NewProgram(initialModel(targetHost), tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}
}
