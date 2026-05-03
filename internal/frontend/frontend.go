package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	peer "github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// Controller is the narrow node surface needed by the frontend network screen.
type Controller interface {
	PeerID() string
	ListenMultiaddrs() []string
	ConnectedPeerCount() int
	BootstrapPeers() []string
	ConnectPeer(ctx context.Context, multiaddr string) error
	RefreshPeers(ctx context.Context) ([]string, error)
}

type Server struct {
	controller Controller
}

func NewServer(controller Controller) *Server {
	return &Server{controller: controller}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/network/status", s.handleStatus)
	mux.HandleFunc("/api/network/connect", s.handleConnect)
	return mux
}

type statusResponse struct {
	NodeName               string   `json:"node_name"`
	PeerID                 string   `json:"peer_id"`
	ListenMultiaddrs       []string `json:"listen_multiaddrs"`
	ConnectedPeerCount     int      `json:"connected_peer_count"`
	ConnectedPeerLabel     string   `json:"connected_peer_label"`
	BootstrapPeers         []string `json:"bootstrap_peers"`
	BootstrapPeerCount     int      `json:"bootstrap_peer_count"`
	BootstrapPeerCountNote string   `json:"bootstrap_peer_count_note"`
}

type connectRequest struct {
	Bootstrap           string   `json:"bootstrap"`
	BootstrapMultiaddrs []string `json:"bootstrap_multiaddrs"`
}

type connectResponse struct {
	Error              string       `json:"error,omitempty"`
	Connected          []string     `json:"connected"`
	Failed             []string     `json:"failed,omitempty"`
	Warnings           []string     `json:"warnings,omitempty"`
	InvalidEntries     []entryError `json:"invalid_entries,omitempty"`
	ConnectedPeerCount int          `json:"connected_peer_count"`
}

type entryError struct {
	Entry string `json:"entry"`
	Error string `json:"error"`
}

type errorResponse struct {
	Error          string       `json:"error"`
	InvalidEntries []entryError `json:"invalid_entries,omitempty"`
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, indexHTML)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.status())
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	defer r.Body.Close()

	var req connectRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}

	addrs, invalid := parseBootstrapInput(req)
	if len(addrs) == 0 {
		msg := "at least one bootstrap multiaddr is required"
		if len(invalid) > 0 {
			msg = "no valid bootstrap multiaddrs"
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: msg, InvalidEntries: invalid})
		return
	}
	var connected []string
	var failed []string
	for _, addr := range addrs {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		err := s.controller.ConnectPeer(ctx, addr)
		cancel()
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", addr, err))
			continue
		}
		connected = append(connected, addr)
	}

	var warnings []string
	if len(connected) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		refreshWarnings, err := s.controller.RefreshPeers(ctx)
		cancel()
		warnings = append(warnings, refreshWarnings...)
		if err != nil {
			warnings = append(warnings, "refresh peers: "+err.Error())
		}
	}

	status := http.StatusOK
	var topLevelError string
	if len(connected) == 0 {
		status = http.StatusBadGateway
		topLevelError = "failed to connect to any bootstrap multiaddr"
	}
	writeJSON(w, status, connectResponse{
		Error:              topLevelError,
		Connected:          connected,
		Failed:             failed,
		Warnings:           warnings,
		InvalidEntries:     invalid,
		ConnectedPeerCount: s.controller.ConnectedPeerCount(),
	})
}

func (s *Server) status() statusResponse {
	bootstrap := s.controller.BootstrapPeers()
	return statusResponse{
		NodeName:               "LibreVote Node",
		PeerID:                 s.controller.PeerID(),
		ListenMultiaddrs:       s.controller.ListenMultiaddrs(),
		ConnectedPeerCount:     s.controller.ConnectedPeerCount(),
		ConnectedPeerLabel:     "currently connected libp2p peers",
		BootstrapPeers:         bootstrap,
		BootstrapPeerCount:     len(bootstrap),
		BootstrapPeerCountNote: "configured bootstrap addresses only; discovered peers are reflected in connected_peer_count",
	}
}

func parseBootstrapInput(req connectRequest) ([]string, []entryError) {
	var raw []string
	if req.Bootstrap != "" {
		raw = append(raw, splitAddressText(req.Bootstrap)...)
	}
	for _, item := range req.BootstrapMultiaddrs {
		raw = append(raw, splitAddressText(item)...)
	}

	seen := map[string]struct{}{}
	var valid []string
	var invalid []entryError
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		if err := validateBootstrapMultiaddr(entry); err != nil {
			invalid = append(invalid, entryError{Entry: entry, Error: err.Error()})
			continue
		}
		valid = append(valid, entry)
	}
	return valid, invalid
}

func splitAddressText(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
}

func validateBootstrapMultiaddr(s string) error {
	addr, err := ma.NewMultiaddr(s)
	if err != nil {
		return fmt.Errorf("parse multiaddr: %w", err)
	}
	if _, err := peer.AddrInfoFromP2pAddr(addr); err != nil {
		return fmt.Errorf("full peer multiaddr with /p2p/<peer_id> is required: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
