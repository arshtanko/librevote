package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"librevote/internal/domain"
	"librevote/internal/storage"
	"librevote/internal/sync"
)

const DefaultHTTPTimeout = 30 * time.Second

type jsonObjectRef struct {
	ObjectID   string `json:"object_id"`
	ObjectType string `json:"object_type"`
	Scope      string `json:"scope"`
	ScopeID    string `json:"scope_id"`
	CreatedAt  int64  `json:"created_at"`
}

type jsonObjectEnvelope struct {
	ObjectID        string `json:"object_id"`
	ObjectType      string `json:"object_type"`
	ProtocolVersion string `json:"protocol_version"`
	NetworkID       string `json:"network_id"`
	Scope           string `json:"scope"`
	ScopeID         string `json:"scope_id"`
	Payload         []byte `json:"payload"`
	Pow             []byte `json:"pow"`
	CreatedAt       int64  `json:"created_at"`
}

type jsonErrorBody struct {
	Error string `json:"error"`
}

// Server serves HTTP endpoints for the LibreVote direct sync protocol.
type Server struct {
	store     sync.StoreQuerier
	networkID string
}

// NewServer creates an HTTP server backed by a StoreQuerier.
func NewServer(store sync.StoreQuerier, networkID string) *Server {
	return &Server{store: store, networkID: networkID}
}

// Handler returns an http.Handler for this server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/inventory", s.handleInventory)
	mux.HandleFunc("/object/", s.handleObject)
	return mux
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = string(domain.ScopeNetwork)
	}
	scopeID := r.URL.Query().Get("scope_id")

	var objectTypes []string
	if typesParam := r.URL.Query().Get("object_types"); typesParam != "" {
		for _, t := range strings.Split(typesParam, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				objectTypes = append(objectTypes, t)
			}
		}
	}

	refs, err := s.store.ListServableObjectRefs(r.Context(), scope, scopeID, objectTypes)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	jsonRefs := make([]jsonObjectRef, len(refs))
	for i, ref := range refs {
		jsonRefs[i] = jsonObjectRef{
			ObjectID:   ref.ObjectID,
			ObjectType: ref.ObjectType,
			Scope:      ref.Scope,
			ScopeID:    ref.ScopeID,
			CreatedAt:  ref.CreatedAt,
		}
	}

	writeJSON(w, http.StatusOK, jsonRefs)
}

func (s *Server) handleObject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	rawID := strings.TrimPrefix(r.URL.Path, "/object/")
	objectID, err := url.PathUnescape(rawID)
	if err != nil || objectID == "" {
		writeJSONError(w, http.StatusBadRequest, "object_id is required")
		return
	}

	envelope, err := s.store.LoadObjectEnvelope(r.Context(), objectID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "object not found or not servable")
		return
	}

	jsonEnv := jsonObjectEnvelope{
		ObjectID:        envelope.ObjectID,
		ObjectType:      string(envelope.ObjectType),
		ProtocolVersion: envelope.ProtocolVersion,
		NetworkID:       envelope.NetworkID,
		Scope:           string(envelope.Scope),
		ScopeID:         envelope.ScopeID,
		Payload:         envelope.Payload,
		Pow:             envelope.Pow,
		CreatedAt:       envelope.CreatedAt,
	}

	writeJSON(w, http.StatusOK, jsonEnv)
}

// HTTPTransport implements sync.Transport over HTTP JSON.
type HTTPTransport struct {
	client *http.Client
}

// NewHTTPTransport creates an HTTP transport with a finite timeout.
func NewHTTPTransport() *HTTPTransport {
	return &HTTPTransport{client: &http.Client{Timeout: DefaultHTTPTimeout}}
}

// NewHTTPTransportWithClient creates an HTTP transport with a custom client.
func NewHTTPTransportWithClient(client *http.Client) *HTTPTransport {
	return &HTTPTransport{client: client}
}

// Inventory fetches object refs from a peer via GET /inventory.
func (t *HTTPTransport) Inventory(ctx context.Context, peerID string, scope string, scopeID string, objectTypes []string) ([]storage.ObjectRef, error) {
	u := peerID + "/inventory?scope=" + url.QueryEscape(scope)
	if scopeID != "" {
		u += "&scope_id=" + url.QueryEscape(scopeID)
	}
	if len(objectTypes) > 0 {
		u += "&object_types=" + url.QueryEscape(strings.Join(objectTypes, ","))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("create inventory request: %w", err)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("inventory request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("inventory failed: %s: %s", resp.Status, string(body))
	}

	var jsonRefs []jsonObjectRef
	if err := json.NewDecoder(resp.Body).Decode(&jsonRefs); err != nil {
		return nil, fmt.Errorf("decode inventory response: %w", err)
	}

	refs := make([]storage.ObjectRef, len(jsonRefs))
	for i, jr := range jsonRefs {
		refs[i] = storage.ObjectRef{
			ObjectID:   jr.ObjectID,
			ObjectType: jr.ObjectType,
			Scope:      jr.Scope,
			ScopeID:    jr.ScopeID,
			CreatedAt:  jr.CreatedAt,
		}
	}
	return refs, nil
}

// GetObject fetches a full object from a peer via GET /object/{objectID}.
func (t *HTTPTransport) GetObject(ctx context.Context, peerID string, objectID string) (domain.ObjectEnvelope, error) {
	u := peerID + "/object/" + url.PathEscape(objectID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("create get-object request: %w", err)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("get-object request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return domain.ObjectEnvelope{}, fmt.Errorf("get-object failed: %s: %s", resp.Status, string(body))
	}

	var jsonEnv jsonObjectEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&jsonEnv); err != nil {
		return domain.ObjectEnvelope{}, fmt.Errorf("decode object response: %w", err)
	}

	return domain.ObjectEnvelope{
		ObjectID:        jsonEnv.ObjectID,
		ObjectType:      domain.ObjectType(jsonEnv.ObjectType),
		ProtocolVersion: jsonEnv.ProtocolVersion,
		NetworkID:       jsonEnv.NetworkID,
		Scope:           domain.Scope(jsonEnv.Scope),
		ScopeID:         jsonEnv.ScopeID,
		Payload:         jsonEnv.Payload,
		Pow:             jsonEnv.Pow,
		CreatedAt:       jsonEnv.CreatedAt,
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, jsonErrorBody{Error: msg})
}
