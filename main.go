package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/gorilla/sessions"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type Photos struct {
	MediaItems []struct {
		ID         string `json:"id"`
		ProductURL string `json:"productUrl"`
		BaseURL    string `json:"baseUrl"`
		MimeType   string `json:"mimeType"`
		Filename   string `json:"filename"`
	} `json:"mediaItems"`
}

const (
	lenState        = 30
	lenCodeVerifier = 64
	redirectURI     = "http://localhost:8080/callback"
)

var (
	googleClientID     string
	googleClientSecret string
	store              = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))
)

func init() {
	googleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")

	if googleClientID == "" {
		log.Fatal("Env var GOOGLE_CLIENT_ID is required")
	}
	if googleClientSecret == "" {
		log.Fatal("Env var GOOGLE_CLIENT_SECRET is required")
	}
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/oauth", handleOAuth)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/photos", handlePhotos)
	log.Print("Serving web server at localhost:8080")
	http.ListenAndServe("0.0.0.0:8080", nil)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tpl, _ := template.ParseFiles("templates/index.html")
	tpl.Execute(w, nil)
}

func handleOAuth(w http.ResponseWriter, r *http.Request) {
	// Save `state` and `code_verifier` to session
	session, _ := store.Get(r, "session")
	// Generate a random state
	state, _ := randomString(lenState)
	session.Values["state"] = state
	// Generate code_verifier
	codeVerifier, _ := randomString(lenCodeVerifier)
	session.Values["code_verifier"] = codeVerifier
	session.Save(r, w)

	// Generate code_challenge
	b := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b[:])

	// Redirect the user agent == Make a authorization request
	u, _ := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	q := u.Query()
	q.Add("response_type", "code")                                           // Indicate authorization code grant
	q.Add("client_id", googleClientID)                                       // The client ID issued by Google
	q.Add("state", state)                                                    // The random state
	q.Add("scope", "https://www.googleapis.com/auth/photoslibrary.readonly") // The scope we need
	q.Add("redirect_uri", redirectURI)                                       // The redirect URI
	q.Add("code_challenge", codeChallenge)                                   // Code challenge
	q.Add("code_challenge_method", "S256")                                   // Code challenge method
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Confirm `state` matches
	session, _ := store.Get(r, "session")
	if r.URL.Query().Get("state") != session.Values["state"] {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Invalid state")
		return
	}
	// Get `code_verifier`
	codeVerifier := session.Values["code_verifier"].(string)
	// Clear session
	session.Values["state"] = ""
	session.Values["code_verifier"] = ""
	session.Save(r, w)

	// Make a token request
	code := r.URL.Query().Get("code")
	q := url.Values{}
	q.Add("grant_type", "authorization_code") // Indicate token request
	q.Add("code", code)                       // The authorization code
	q.Add("redirect_uri", redirectURI)        // The redirect URI
	q.Add("code_verifier", codeVerifier)      // Code verifier
	req, _ := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(q.Encode()))
	req.SetBasicAuth(googleClientID, googleClientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	// Capture the access token we've received
	body, _ := io.ReadAll(resp.Body)
	var token TokenResponse
	json.Unmarshal(body, &token)
	session.Values["access_token"] = token.AccessToken
	session.Save(r, w)

	// Redirect the user agent to the photos page
	http.Redirect(w, r, "http://localhost:8080/photos", http.StatusFound)
}

func handlePhotos(w http.ResponseWriter, r *http.Request) {
	// Fetch photos from Google Photos Library API using the access_token
	session, _ := store.Get(r, "session")
	accessToken := session.Values["access_token"].(string)
	req, _ := http.NewRequest(http.MethodGet, "https://photoslibrary.googleapis.com/v1/mediaItems", nil)
	req.Header.Add("Authorization", "Bearer "+accessToken)
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var photos Photos
	json.Unmarshal(body, &photos)

	// Render photos
	tpl, _ := template.ParseFiles("templates/photos.html")
	tpl.Execute(w, photos)
}

// randomString generates a secure random string of length `length`.
// It returns an error when `length` is negative or failed to use the platform's
// secure pseudorandom number generator.
func randomString(length int) (string, error) {
	if length < 0 {
		return "", fmt.Errorf("cannot generate random string of negative length %d", length)
	}
	var s strings.Builder
	for s.Len() < length {
		r, err := rand.Int(rand.Reader, big.NewInt(1<<60))
		if err != nil {
			return "", err
		}
		// 1<<60 == 2**60 equals to 1,000,000,000,000,000 in hex.
		s.WriteString(fmt.Sprintf("%015x", r))
	}
	return s.String()[:length], nil
}
