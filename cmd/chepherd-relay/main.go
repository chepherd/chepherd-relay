// chepherd-relay — signaling + auth + push proxy for chepherd-rc.
//
// See README.md for the privacy contract + endpoint surface.
// See https://github.com/chepherd/chepherd/blob/main/docs/PROTOCOL.md for
// the wire protocol this server implements.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/chepherd/chepherd-relay/internal/auth"
	"github.com/chepherd/chepherd-relay/internal/obs"
	"github.com/chepherd/chepherd-relay/internal/registry"
)

// Version is overridden at build time via -ldflags.
var Version = "0.0.1-dev"

func main() {
	addr := flag.String("addr", ":9889",
		"HTTP listen address (CAO convention port 9889)")
	jwksURL := flag.String("jwks", os.Getenv("CHEPHERD_RELAY_JWKS"),
		"identity-svc JWKS endpoint (also: CHEPHERD_RELAY_JWKS env)")
	issuer := flag.String("issuer", os.Getenv("CHEPHERD_RELAY_ISSUER"),
		"expected JWT issuer (also: CHEPHERD_RELAY_ISSUER env)")
	audience := flag.String("audience", "chepherd-rc",
		"expected JWT audience")
	flag.Parse()

	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer bootCancel()
	obsShutdown, err := obs.Init(bootCtx, obs.FromEnv("chepherd-relay", Version))
	if err != nil {
		log.Fatalf("obs init: %v", err)
	}

	srv := newRelay()

	// Auth verifier — required for signaling endpoints; bypassed for health.
	var verifier *auth.Verifier
	if *jwksURL != "" {
		verifier = auth.New(*jwksURL, *issuer, *audience)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", srv.health)
	mux.HandleFunc("/v1/stats", srv.stats)

	// Protected endpoints — wrap with auth middleware when verifier is set.
	protect := func(h http.HandlerFunc) http.HandlerFunc {
		if verifier == nil {
			// Dev mode without JWKS — allow all (logs a warning).
			return h
		}
		wrapped := verifier.Middleware(http.HandlerFunc(h))
		return wrapped.ServeHTTP
	}
	mux.HandleFunc("/v1/signaling/initiate", protect(srv.signalingInitiate))
	mux.HandleFunc("/v1/signaling/poll", protect(srv.signalingPoll))
	mux.HandleFunc("/v1/signaling/answer", protect(srv.signalingAnswer))
	mux.HandleFunc("/v1/register", protect(srv.registerBastion))
	mux.HandleFunc("/v1/bastions", protect(srv.listMyBastions))
	// Future:
	//   /v1/ws           WebSocket relay fallback (opt-in)
	//   /v1/push/*       APNs / FCM proxy

	if verifier == nil {
		log.Println("WARNING: --jwks not set; auth bypassed (dev mode only).")
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           obs.Middleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	go func() {
		log.Printf("chepherd-relay %s listening on %s", Version, *addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	if obsShutdown != nil {
		_ = obsShutdown(shutCtx)
	}
}

// ─── relay core ─────────────────────────────────────────────────────────

type relay struct {
	mu sync.Mutex
	// pendingOffers: bastion_id → queue of waiting offers from clients
	pendingOffers map[string]chan *signalEnvelope
	// pendingAnswers: client_id → waiting answer from bastion
	pendingAnswers map[string]chan *signalEnvelope
	// startedAt
	startedAt time.Time
	// registry tracks which bastions are registered + their daemon tokens
	registry registry.Registry
}

func newRelay() *relay {
	return &relay{
		pendingOffers:  map[string]chan *signalEnvelope{},
		pendingAnswers: map[string]chan *signalEnvelope{},
		startedAt:      time.Now().UTC(),
		registry:       registry.NewMemory(),
	}
}

// registerBastion mints a fresh daemon token for a bastion.
// POST /v1/register
// Authenticated (user token); body: {id, capabilities, chepherd_version}
// Response: {daemon_token, bastion: {...}}
func (r *relay) registerBastion(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	claims := auth.ClaimsFromContext(req.Context())
	if claims == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		ID              string   `json:"id"`
		Capabilities    []string `json:"capabilities"`
		ChepherdVersion string   `json:"chepherd_version"`
		Hostname        string   `json:"hostname"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	tok, err := r.registry.Register(req.Context(), registry.Bastion{
		ID:              body.ID,
		UserID:          claims.UserID,
		ChepherdVersion: body.ChepherdVersion,
		Capabilities:    body.Capabilities,
		Hostname:        body.Hostname,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	b, _ := r.registry.Get(req.Context(), body.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"daemon_token": tok,
		"bastion":      b,
	})
}

// listMyBastions returns the bastions owned by the authenticated user.
// GET /v1/bastions
func (r *relay) listMyBastions(w http.ResponseWriter, req *http.Request) {
	claims := auth.ClaimsFromContext(req.Context())
	if claims == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	bastions, _ := r.registry.ListByUser(req.Context(), claims.UserID)
	writeJSON(w, http.StatusOK, map[string]any{
		"bastions": bastions,
	})
}

// signalEnvelope is the relay's internal pass-through shape. It carries the
// SDP + ICE blob opaquely — the relay never inspects the contents.
type signalEnvelope struct {
	Peer string          `json:"peer"`
	SDP  json.RawMessage `json:"sdp"`
	ICE  json.RawMessage `json:"ice,omitempty"`
}

func (r *relay) health(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"uptime_sec": int(time.Since(r.startedAt).Seconds()),
		"version":    Version,
	})
}

func (r *relay) stats(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_sec":              int(time.Since(r.startedAt).Seconds()),
		"pending_offer_queues":    len(r.pendingOffers),
		"pending_answer_channels": len(r.pendingAnswers),
	})
}

// signalingInitiate: client posts offer + ICE for a named bastion.
// Blocks until the bastion responds with an answer (or 60s timeout).
//
// Note this endpoint does NOT see DataChannel contents — SDP only.
// Per protocol v1 §1 + §8 privacy contract.
func (r *relay) signalingInitiate(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var env signalEnvelope
	if err := json.NewDecoder(req.Body).Decode(&env); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if env.Peer == "" {
		http.Error(w, "peer (bastion_id) required", http.StatusBadRequest)
		return
	}

	// Create the client-side wait channel.
	clientID := genClientID()
	answerCh := make(chan *signalEnvelope, 1)
	r.mu.Lock()
	r.pendingAnswers[clientID] = answerCh
	// Push the offer to the bastion's poll queue.
	queue, ok := r.pendingOffers[env.Peer]
	if !ok {
		queue = make(chan *signalEnvelope, 16)
		r.pendingOffers[env.Peer] = queue
	}
	r.mu.Unlock()

	env.Peer = clientID // overwrite to identify client to the bastion
	select {
	case queue <- &env:
	case <-time.After(2 * time.Second):
		http.Error(w, "bastion offer queue full or unavailable", http.StatusServiceUnavailable)
		return
	}

	// Wait for the answer.
	select {
	case answer := <-answerCh:
		writeJSON(w, http.StatusOK, answer)
	case <-time.After(60 * time.Second):
		http.Error(w, "bastion did not answer within 60s", http.StatusGatewayTimeout)
	case <-req.Context().Done():
		// client gave up
	}

	r.mu.Lock()
	delete(r.pendingAnswers, clientID)
	r.mu.Unlock()
}

// signalingPoll: bastion long-polls for offers addressed to it.
// Long-poll up to 25 sec (under the typical 30-sec proxy timeout).
func (r *relay) signalingPoll(w http.ResponseWriter, req *http.Request) {
	bastionID := req.URL.Query().Get("bastion")
	if bastionID == "" {
		http.Error(w, "?bastion= required", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	queue, ok := r.pendingOffers[bastionID]
	if !ok {
		queue = make(chan *signalEnvelope, 16)
		r.pendingOffers[bastionID] = queue
	}
	r.mu.Unlock()

	select {
	case env := <-queue:
		writeJSON(w, http.StatusOK, env)
	case <-time.After(25 * time.Second):
		w.WriteHeader(http.StatusNoContent)
	case <-req.Context().Done():
	}
}

// signalingAnswer: bastion posts its SDP answer + ICE back to the relay,
// which forwards it to the client's wait channel.
func (r *relay) signalingAnswer(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var env signalEnvelope
	if err := json.NewDecoder(req.Body).Decode(&env); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if env.Peer == "" {
		http.Error(w, "peer (client_id) required", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	ch, ok := r.pendingAnswers[env.Peer]
	r.mu.Unlock()
	if !ok {
		http.Error(w, "client_id not waiting (already timed out?)", http.StatusGone)
		return
	}
	select {
	case ch <- &env:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		http.Error(w, "client wait channel closed", http.StatusGone)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func genClientID() string {
	// Simple monotonic ID for v0.1. Production uses crypto/rand or ULID.
	return fmt.Sprintf("c-%d-%d", os.Getpid(), time.Now().UnixNano())
}
