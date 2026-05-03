package frontend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	peer "github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"librevote/internal/app"
)

// Controller is the narrow node surface needed by the frontend network screen.
type Controller interface {
	PeerID() string
	ListenMultiaddrs() []string
	ConnectedPeerCount() int
	ConnectedPeerIDs() []string
	BootstrapPeers() []string
	ConnectPeer(ctx context.Context, multiaddr string) error
	RefreshPeers(ctx context.Context) ([]string, error)
}

type ElectionController interface {
	ElectionStatus(ctx context.Context, localPeerID string) (app.ElectionStatus, error)
	CreateElectionInvite(ctx context.Context, input app.CreateElectionInviteInput) (app.ElectionStatus, error)
	AcceptElectionInvite(ctx context.Context, electionID, voterPeerID string) (app.ElectionStatus, error)
	DeclineElectionInvite(ctx context.Context, electionID, voterPeerID string) (app.ElectionStatus, error)
	FinalizeElectionInvite(ctx context.Context, electionID, requesterPeerID string) (app.ElectionStatus, error)
	CastFrontendVote(ctx context.Context, electionID, voterID, choice string) (app.FrontendVoteResult, error)
	GetElectionResult(ctx context.Context, electionID, requesterPeerID string) (app.ElectionResultResponse, error)
}

type localVoterElectionController interface {
	ElectionStatusForLocalVoter(ctx context.Context, voterID string) (app.ElectionStatus, error)
}

type Server struct {
	controller         Controller
	electionController ElectionController
}

func NewServer(controller Controller, electionController ...ElectionController) *Server {
	server := &Server{controller: controller}
	if len(electionController) > 0 {
		server.electionController = electionController[0]
	}
	return server
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/network/status", s.handleStatus)
	mux.HandleFunc("/api/network/connect", s.handleConnect)
	mux.HandleFunc("/api/elections/status", s.handleElectionStatus)
	mux.HandleFunc("/api/elections/invite", s.handleElectionInvite)
	mux.HandleFunc("/api/elections/accept", s.handleElectionAccept)
	mux.HandleFunc("/api/elections/decline", s.handleElectionDecline)
	mux.HandleFunc("/api/elections/finalize", s.handleElectionFinalize)
	mux.HandleFunc("/api/elections/result", s.handleElectionResult)
	mux.HandleFunc("/api/vote/cast", s.handleVoteCast)
	return mux
}

type statusResponse struct {
	NodeName               string   `json:"node_name"`
	PeerID                 string   `json:"peer_id"`
	ListenMultiaddrs       []string `json:"listen_multiaddrs"`
	ConnectedPeerCount     int      `json:"connected_peer_count"`
	ConnectedPeerIDs       []string `json:"connected_peer_ids"`
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

type voteCastRequest struct {
	ElectionID string `json:"election_id"`
	VoterID    string `json:"voter_id"`
	Choice     string `json:"choice"`
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

type inviteRequest struct {
	Title          string   `json:"title"`
	Options        []string `json:"options"`
	InvitedPeerIDs []string `json:"invited_peer_ids"`
	IncludeSelf    bool     `json:"include_self"`
}

type acceptRequest struct {
	ElectionID string `json:"election_id"`
}

type finalizeRequest struct {
	ElectionID string `json:"election_id"`
}

func (s *Server) handleElectionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	status, err := s.electionStatus(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleElectionInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.electionController == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "election service is not available"})
		return
	}
	localPeerID := strings.TrimSpace(s.controller.PeerID())
	if localPeerID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "local peer ID is not available"})
		return
	}
	defer r.Body.Close()
	var req inviteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}
	status, err := s.electionController.CreateElectionInvite(r.Context(), app.CreateElectionInviteInput{
		Title:          req.Title,
		Options:        req.Options,
		InvitedPeerIDs: req.InvitedPeerIDs,
		CreatorPeerID:  localPeerID,
		IncludeSelf:    req.IncludeSelf,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleElectionAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.electionController == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "election service is not available"})
		return
	}
	localPeerID := strings.TrimSpace(s.controller.PeerID())
	if localPeerID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "local peer ID is not available"})
		return
	}
	defer r.Body.Close()
	var req acceptRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}
	status, err := s.electionController.AcceptElectionInvite(r.Context(), req.ElectionID, localPeerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleElectionDecline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.electionController == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "election service is not available"})
		return
	}
	localPeerID := strings.TrimSpace(s.controller.PeerID())
	if localPeerID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "local peer ID is not available"})
		return
	}
	defer r.Body.Close()
	var req acceptRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}
	status, err := s.electionController.DeclineElectionInvite(r.Context(), req.ElectionID, localPeerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleElectionFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.electionController == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "election service is not available"})
		return
	}
	defer r.Body.Close()
	var req finalizeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}
	localPeerID := strings.TrimSpace(s.controller.PeerID())
	status, err := s.electionController.FinalizeElectionInvite(r.Context(), req.ElectionID, localPeerID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleElectionResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.electionController == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "election service is not available"})
		return
	}
	localPeerID := strings.TrimSpace(s.controller.PeerID())
	if localPeerID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "local peer ID is not available"})
		return
	}
	defer r.Body.Close()
	var req acceptRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}
	result, err := s.electionController.GetElectionResult(r.Context(), req.ElectionID, localPeerID)
	if err != nil {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleVoteCast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}
	if s.electionController == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Error: "election service is not available"})
		return
	}
	localVoterID := strings.TrimSpace(s.controller.PeerID())
	if localVoterID == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "local peer ID is not available"})
		return
	}
	defer r.Body.Close()

	var req voteCastRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return
	}
	req.VoterID = strings.TrimSpace(req.VoterID)
	if req.VoterID != "" && req.VoterID != localVoterID {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "voter_id does not match local voter binding"})
		return
	}
	result, err := s.electionController.CastFrontendVote(r.Context(), req.ElectionID, localVoterID, req.Choice)
	if err != nil {
		writeJSON(w, voteErrorStatus(err), errorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func voteErrorStatus(err error) int {
	switch {
	case errors.Is(err, app.ErrFrontendElectionUnavailable), errors.Is(err, app.ErrFrontendTallyKeySetUnavailable):
		return http.StatusConflict
	case errors.Is(err, app.ErrFrontendVoterNotEligible), errors.Is(err, app.ErrFrontendInvalidChoice):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) status() statusResponse {
	bootstrap := s.controller.BootstrapPeers()
	return statusResponse{
		NodeName:               "LibreVote Node",
		PeerID:                 s.controller.PeerID(),
		ListenMultiaddrs:       s.controller.ListenMultiaddrs(),
		ConnectedPeerCount:     s.controller.ConnectedPeerCount(),
		ConnectedPeerIDs:       s.controller.ConnectedPeerIDs(),
		ConnectedPeerLabel:     "currently connected libp2p peers",
		BootstrapPeers:         bootstrap,
		BootstrapPeerCount:     len(bootstrap),
		BootstrapPeerCountNote: "configured bootstrap addresses only; discovered peers are reflected in connected_peer_count",
	}
}

func (s *Server) electionStatus(ctx context.Context) (app.ElectionStatus, error) {
	if s.electionController == nil {
		return app.ElectionStatus{Message: "election service is not available"}, nil
	}
	localPeerID := strings.TrimSpace(s.controller.PeerID())
	if localPeerID == "" {
		return s.electionController.ElectionStatus(ctx, "")
	}
	if controller, ok := s.electionController.(localVoterElectionController); ok {
		return controller.ElectionStatusForLocalVoter(ctx, localPeerID)
	}
	return s.electionController.ElectionStatus(ctx, localPeerID)
}

func (s *Server) meshVoterIDs() []string {
	seen := make(map[string]struct{})
	var voterIDs []string
	for _, id := range append([]string{s.controller.PeerID()}, s.controller.ConnectedPeerIDs()...) {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		voterIDs = append(voterIDs, id)
	}
	sort.Strings(voterIDs)
	return voterIDs
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
