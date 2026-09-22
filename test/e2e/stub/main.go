package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	listenAddress = "127.0.0.1:18080"
	baseURL       = "http://" + listenAddress
	oauthState    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type authorizeRequest struct {
	CodeChallenge string `json:"code_challenge"`
	RedirectURI   string `json:"redirect_uri"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/oauth/authorize", authorize)
	mux.HandleFunc("POST /v1/oauth/exchange", exchange)
	mux.HandleFunc("POST /login/device/code", deviceCode)
	mux.HandleFunc("POST /login/oauth/access_token", deviceToken)
	mux.HandleFunc("GET /user", githubUser)
	mux.HandleFunc("GET /users/{login}", githubNamedUser)

	server := &http.Server{Addr: listenAddress, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("enbu E2E stub listening on %s", listenAddress)
	log.Fatal(server.ListenAndServe())
}

func authorize(w http.ResponseWriter, r *http.Request) {
	var request authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	query := url.Values{
		"state":                 {oauthState},
		"code_challenge":        {request.CodeChallenge},
		"code_challenge_method": {"S256"},
		"redirect_uri":          {request.RedirectURI},
	}
	writeJSON(w, map[string]string{
		"authorize_url": "https://github.com/login/oauth/authorize?" + query.Encode(),
		"state":         oauthState,
	})
}

func exchange(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"access_token": "e2e-access-token",
		"token_type":   "bearer",
		"scope":        "repo read:org write:packages",
	})
}

func deviceCode(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"device_code":      "e2e-device-code",
		"user_code":        "E2E-1234",
		"verification_uri": baseURL + "/login/device",
		"expires_in":       60,
		"interval":         1,
	})
}

func deviceToken(w http.ResponseWriter, _ *http.Request) {
	exchange(w, nil)
}

func githubUser(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"id": 4242, "login": "e2e-user", "type": "User"})
}

func githubNamedUser(w http.ResponseWriter, r *http.Request) {
	login := r.PathValue("login")
	userType := "User"
	if strings.HasPrefix(login, "org-") {
		userType = "Organization"
	}
	writeJSON(w, map[string]any{"id": 4242, "login": login, "type": userType})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Print(fmt.Errorf("encoding response: %w", err))
	}
}
