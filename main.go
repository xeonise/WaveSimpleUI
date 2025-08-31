package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	clientSettingsURL = "https://clientsettingscdn.roblox.com/v2/client-version/WindowsPlayer"
	wsHost            = "localhost"
	wsPort            = 61416
)

type clientSettings struct {
	Version             string `json:"version"`
	ClientVersionUpload string `json:"clientVersionUpload"`
	BootstrapperVersion string `json:"bootstrapperVersion"`
}

type clientConn struct {
	id       string
	conn     *websocket.Conn
	mu       sync.Mutex
	identify *IdentifyData
	isUI     bool
}

type IdentifyData struct {
	Raw map[string]interface{} `json:"raw"`
}

type MessagePacket struct {
	Op   string      `json:"op"`
	Data interface{} `json:"data"`
}

func (i *IdentifyData) PlayerName() string {
	if player, ok := i.Raw["player"].(map[string]interface{}); ok {
		if name, ok := player["name"].(string); ok && name != "" {
			return name
		}
		if username, ok := player["username"].(string); ok && username != "" {
			return username
		}
		if user, ok := player["user"].(string); ok && user != "" {
			return user
		}
		if displayName, ok := player["displayName"].(string); ok && displayName != "" {
			return displayName
		}
	}
	return "<unknown>"
}

func (c *clientConn) sendJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(v)
}

func main() {
	settings, err := fetchClientSettings()
	if err != nil {
		logErr("failed to fetch client settings: %v", err)
		runServerOnly()
		return
	}

	exeDir, err := os.Executable()
	if err != nil {
		logErr("os.Executable failed: %v", err)
		runServerOnly()
		return
	}

	baseDir := filepath.Dir(exeDir)
	binDir := filepath.Join(baseDir, "bin")
	targetDir := filepath.Join(binDir, settings.ClientVersionUpload)

	if err := os.MkdirAll(binDir, 0755); err != nil {
		logErr("failed to create bin dir: %v", err)
		runServerOnly()
		return
	}

	if err := cleanupOldVersions(binDir, settings.ClientVersionUpload); err != nil {
		logErr("cleanupOldVersions: %v", err)
	}

	cmPath := filepath.Join(targetDir, "ClientManager.exe")
	dllPath := filepath.Join(targetDir, "Wave.dll")

	if !fileExists(cmPath) || !fileExists(dllPath) {
		logInfo("Files not found, downloading...")
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			logErr("failed to create target dir: %v", err)
			runServerOnly()
			return
		}

		cmURL := fmt.Sprintf("https://cdn.wavify.cc/versions/%s/ClientManager.exe", settings.ClientVersionUpload)
		dllURL := fmt.Sprintf("https://cdn.wavify.cc/versions/%s/Wave.dll", settings.ClientVersionUpload)
		if err := downloadFile(cmURL, cmPath); err != nil {
			logErr("download ClientManager.exe failed: %v", err)
		}
		if err := downloadFile(dllURL, dllPath); err != nil {
			logErr("download Wave.dll failed: %v", err)
		}
	}

	if fileExists(cmPath) {
		logInfo("Launching ClientManager.exe...")
		if err := launchClientManager(cmPath, targetDir); err != nil {
			logErr("launch ClientManager.exe failed: %v", err)
		}
	} else {
		logErr("ClientManager.exe not found at %s", cmPath)
	}

	if err := runWebSocketServer(); err != nil {
		logErr("websocket server error: %v", err)
	}
}

func fetchClientSettings() (*clientSettings, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest("GET", clientSettingsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var s clientSettings
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	if s.ClientVersionUpload == "" {
		return nil, errors.New("missing clientVersionUpload in client settings")
	}
	return &s, nil
}

func cleanupOldVersions(binDir, current string) error {
	entries, err := os.ReadDir(binDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == current {
			continue
		}
		_ = os.RemoveAll(filepath.Join(binDir, name))
	}
	return nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

func downloadFile(url, dest string) error {
	tmp := dest + ".tmp"
	_ = os.Remove(tmp)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(context.Background())
	req.Header.Set("User-Agent", "Wave-Downloader/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s failed with status %d", url, resp.StatusCode)
	}

	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func launchClientManager(path, workdir string) error {
	cmd := exec.Command(path)
	cmd.Dir = workdir
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return nil
}

func logInfo(format string, a ...any) { fmt.Printf("[Wave] "+format+"\n", a...) }
func logErr(format string, a ...any)  { fmt.Printf("[Wave][ERR] "+format+"\n", a...) }

func runServerOnly() {
	if err := runWebSocketServer(); err != nil {
		logErr("websocket server error: %v", err)
	}
}

func runWebSocketServer() error {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  8192,
		WriteBufferSize: 8192,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}

	var (
		clientsMu sync.Mutex
		clients   = map[string]*clientConn{}
	)

	// Helper: send a packet to all connected UIs
	sendToUIs := func(v any) {
		clientsMu.Lock()
		defer clientsMu.Unlock()
		for _, c := range clients {
			if !c.isUI {
				continue
			}
			_ = c.sendJSON(v)
		}
	}

	handleConnect := func(socketID string, identity *IdentifyData) {
		pname := identity.PlayerName()
		logInfo("Client connected: %s player=%s", socketID[:8], pname)
		if client, ok := clients[socketID]; ok {
			_ = client.sendJSON(map[string]interface{}{
				"op":   "server/identify/ack",
				"data": map[string]interface{}{"message": "identified"},
			})
			// If this is a non-UI agent, notify UIs of join
			if !client.isUI {
				sendToUIs(map[string]any{
					"op": "client/join",
					"data": map[string]any{
						"client": map[string]any{
							"id":   socketID,
							"name": pname,
						},
					},
				})
			}
		}
	}

	handleUpdate := func(socketID string, identity *IdentifyData) {
		pname := identity.PlayerName()
		logInfo("Client updated: %s player=%s", socketID[:8], pname)
		// NEW: push name/identity updates to all UIs so the UI can refresh labels immediately
		sendToUIs(map[string]any{
			"op": "client/update",
			"data": map[string]any{
				"id":   socketID,
				"name": pname,
			},
		})
	}

	handleDisconnect := func(socketID string) {
		logInfo("Client disconnected: %s", socketID[:8])
		// If an agent disconnected, let UIs know
		clientsMu.Lock()
		if c, ok := clients[socketID]; ok && !c.isUI {
			clientsMu.Unlock()
			sendToUIs(map[string]any{
				"op": "client/leave",
				"data": map[string]any{
					"id": socketID,
				},
			})
			return
		}
		clientsMu.Unlock()
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Serve UI at /ui or /ui.html
		if r.Method == http.MethodGet && (r.URL.Path == "/ui" || r.URL.Path == "/ui.html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "ui.html")
			return
		}

		// Upgrade to WebSocket if requested
		if strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			c, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				logErr("upgrade error: %v", err)
				return
			}

			id := fmt.Sprintf("%d", time.Now().UnixNano())
			cc := &clientConn{id: id, conn: c}

			clientsMu.Lock()
			clients[id] = cc
			clientsMu.Unlock()

			go func() {
				defer func() {
					clientsMu.Lock()
					delete(clients, id)
					clientsMu.Unlock()
					_ = c.Close()
					handleDisconnect(id)
				}()

				c.SetReadLimit(4 << 20)
				c.SetReadDeadline(time.Now().Add(60 * time.Second))
				c.SetPongHandler(func(string) error {
					c.SetReadDeadline(time.Now().Add(60 * time.Second))
					return nil
				})

				for {
					_, data, err := c.ReadMessage()
					if err != nil {
						return
					}

					var pkt MessagePacket
					if err := json.Unmarshal(data, &pkt); err != nil {
						logErr("malformed packet from %s: %v", id[:8], err)
						continue
					}

					switch pkt.Op {
					case "client/identify":
						identifyRaw := make(map[string]interface{})
						if dataMap, ok := pkt.Data.(map[string]interface{}); ok {
							identifyRaw = dataMap
						}
						identify := &IdentifyData{Raw: identifyRaw}

						// Decide if this connection is the Web UI
						playerName := identify.PlayerName()
						if strings.EqualFold(playerName, "Web UI") {
							cc.isUI = true
						}

						if cc.identify != nil {
							cc.identify = identify
							handleUpdate(id, identify)
						} else {
							cc.identify = identify
							handleConnect(id, identify)
						}

					case "client/ping":
						_ = cc.sendJSON(map[string]interface{}{
							"op":   "client/pong",
							"data": map[string]interface{}{},
						})

					// -------- UI ops --------
					case "ui/requestClients":
						// Build list of non-UI clients
						clientsMu.Lock()
						list := make([]map[string]any, 0, len(clients))
						for cid, cl := range clients {
							if cl.isUI {
								continue
							}
							name := "Client"
							if cl.identify != nil {
								if n := cl.identify.PlayerName(); n != "" {
									name = n
								}
							}
							list = append(list, map[string]any{"id": cid, "name": name})
						}
						clientsMu.Unlock()
						_ = cc.sendJSON(map[string]any{
							"op":   "client/list",
							"data": map[string]any{"clients": list},
						})

					case "ui/broadcast":
						// Expect: { targets: []string, textDocument: { text: string } }
						targets := []string{}
						script := ""
						if dm, ok := pkt.Data.(map[string]any); ok {
							if t, ok := dm["targets"].([]any); ok {
								for _, v := range t {
									if s, ok := v.(string); ok {
										targets = append(targets, s)
									}
								}
							}
							if td, ok := dm["textDocument"].(map[string]any); ok {
								if tx, ok := td["text"].(string); ok {
									script = tx
								}
							}
						}
						if script == "" {
							break
						}
						// Construct agent message
						msg := map[string]interface{}{
							"op": "client/onDidTextDocumentExecute",
							"data": map[string]interface{}{
								"textDocument": map[string]interface{}{
									"text": script,
								},
							},
						}

						clientsMu.Lock()
						if len(targets) == 0 {
							for aid, ag := range clients {
								if ag.isUI {
									continue
								}
								if err := ag.sendJSON(msg); err != nil {
									logErr("Failed to broadcast to %s: %v", aid[:8], err)
								}
							}
						} else {
							set := make(map[string]struct{}, len(targets))
							for _, t := range targets {
								set[t] = struct{}{}
							}
							for aid, ag := range clients {
								if ag.isUI {
									continue
								}
								if _, ok := set[aid]; ok {
									if err := ag.sendJSON(msg); err != nil {
										logErr("Failed to send to %s: %v", aid[:8], err)
									}
								}
							}
						}
						clientsMu.Unlock()

					default:
						// Handle console/error/compiler output from client
						if strings.Contains(pkt.Op, "console") || strings.Contains(pkt.Op, "error") || strings.Contains(pkt.Op, "compiler") {
							logInfo("Output from %s: %s - %v", id[:8], pkt.Op, pkt.Data)

							// Send error notifications to UIs (extract message)
							if strings.Contains(pkt.Op, "error") {
								errorMsg := ""
								if dataMap, ok := pkt.Data.(map[string]interface{}); ok {
									if msg, ok := dataMap["error_message"].(string); ok {
										errorMsg = msg
									} else if msg, ok := dataMap["message"].(string); ok {
										errorMsg = msg
									}
								}
								if errorMsg != "" {
									sendToUIs(map[string]any{
										"op": "notification",
										"data": map[string]any{
											"type":    "error",
											"message": fmt.Sprintf("Error from %s: %s", id[:8], errorMsg),
										},
									})
								}
							}
						}
					}
				}
			}()
			return
		}

		_, _ = w.Write([]byte("Wave WS running"))
	})

	// Command line interface
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// Parse command line with quoted arguments support
			parts := parseCommandLine(line)
			if len(parts) == 0 {
				continue
			}

			switch parts[0] {
			case "list":
				clientsMu.Lock()
				if len(clients) == 0 {
					logInfo("No connected clients")
				} else {
					logInfo("Connected clients (%d):", len(clients))
					for id, client := range clients {
						playerName := "<not identified>"
						if client.identify != nil {
							playerName = client.identify.PlayerName()
						}
						logInfo("  %s: %s", id[:8], playerName)
					}
				}
				clientsMu.Unlock()

			case "send":
				if len(parts) < 3 {
					logErr("Usage: send <playerName|clientID> <script>")
					continue
				}
				target := parts[1]
				script := strings.Join(parts[2:], " ")
				msg := map[string]interface{}{
					"op": "client/onDidTextDocumentExecute",
					"data": map[string]interface{}{
						"textDocument": map[string]interface{}{
							"text": script,
						},
					},
				}
				clientsMu.Lock()
				sent := 0
				for id, client := range clients {
					playerName := ""
					if client.identify != nil {
						playerName = client.identify.PlayerName()
					}
					if id[:8] == target || playerName == target {
						if err := client.sendJSON(msg); err == nil {
							sent++
							logInfo("Sent script to %s (%s)", playerName, id[:8])
						} else {
							logErr("Failed to send to %s: %v", playerName, err)
						}
					}
				}
				clientsMu.Unlock()
				if sent == 0 {
					logErr("No clients found matching: %s", target)
				}

			case "broadcast":
				if len(parts) < 2 {
					logErr("Usage: broadcast <script>")
					continue
				}
				script := strings.Join(parts[1:], " ")
				msg := map[string]interface{}{
					"op": "client/onDidTextDocumentExecute",
					"data": map[string]interface{}{
						"textDocument": map[string]interface{}{
							"text": script,
						},
					},
				}
				clientsMu.Lock()
				sent := 0
				for id, client := range clients {
					playerName := ""
					if client.identify != nil {
						playerName = client.identify.PlayerName()
					}
					if err := client.sendJSON(msg); err == nil {
						sent++
						logInfo("Broadcasted to %s (%s)", playerName, id[:8])
					} else {
						logErr("Failed to broadcast to %s: %v", playerName, err)
					}
				}
				clientsMu.Unlock()
				logInfo("Broadcasted to %d client(s)", sent)

			default:
				// Convenience: if user typed a bare script and exactly one client is connected, send it
				clientsMu.Lock()
				if len(clients) == 1 {
					script := line
					for id, client := range clients {
						playerName := ""
						if client.identify != nil {
							playerName = client.identify.PlayerName()
						}
						msg := map[string]interface{}{
							"op": "client/onDidTextDocumentExecute",
							"data": map[string]interface{}{
								"textDocument": map[string]interface{}{
									"text": script,
								},
							},
						}
						if err := client.sendJSON(msg); err == nil {
							logInfo("Sent script to %s (%s)", playerName, id[:8])
						} else {
							logErr("Failed to send to %s: %v", playerName, err)
						}
					}
				} else {
					logInfo("Available commands: list, send <player|id> <script>, broadcast <script>")
				}
				clientsMu.Unlock()
			}
		}
	}()

	addr := fmt.Sprintf("%s:%d", wsHost, wsPort)
	logInfo("Listening on ws://%s/", addr)
	srv := &http.Server{Addr: addr}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// parseCommandLine properly parses a command line string with quoted arguments
func parseCommandLine(line string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false
	quoteChar := byte(' ')

	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' || c == '\'' {
			if inQuotes {
				if quoteChar == c {
					inQuotes = false
					quoteChar = ' '
				} else {
					current.WriteByte(c)
				}
			} else {
				inQuotes = true
				quoteChar = c
			}
		} else if c == ' ' && !inQuotes {
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}
