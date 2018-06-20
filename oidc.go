package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
//
// NOTE(ericchiang): this is take from golang.org/x/oauth2
const expiryDelta = 10 * time.Second

func init() {
	rand.Seed(time.Now().UnixNano())
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

const DEFAULT_REDIRECT_URL = "http://127.0.0.1:5555/callback"

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

type OidcAuthHelperConfig struct {
	ClientID          string
	ClientSecret      string
	IssuerUrl         string
	Scopes            []string
	CaCertificateFile string
	RedirectUrl       string
}

type OidcAuthHelper struct {
	*OidcAuthHelperConfig
	redirectUrl *url.URL
	client      *http.Client
	server      *http.Server
	provider    *oidc.Provider
	token       chan *tokenResponse
	state       string
}

type tokenResponse struct {
	token *oauth2.Token
	err   error
}

func NewOidcAuthHelper(config OidcAuthHelperConfig) (*OidcAuthHelper, error) {
	authHelper := &OidcAuthHelper{
		OidcAuthHellperConfig: config,
		server:                &http.Server{},
		client:                &http.Client{},
		token:                 make(chan *tokenResponse, 1),
		state:                 randString(30),
	}

	authHelper.SetRedirectUrl(DEFAULT_REDIRECT_URL)
	ctx := oidc.ClientContext(context.Background(), authHelper.client)
	provider, err := oidc.NewProvider(ctx, issuerUrl)
	if err != nil {
		return nil, err
	}
	authHelper.provider = provider
	return authHelper, nil
}

func (o *OidcAuthHelper) SetRedirectUrl(urlString string) error {
	url, err := url.Parse(urlString)
	if err != nil {
		return err
	}
	if url.Scheme != "http" && url.Scheme != "https" {
		return fmt.Errorf("scheme '%s' not supported", url.Scheme)
	}
	o.redirectUrl = url
	return nil
}

func (o *OidcAuthHelper) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.redirectUrl.String(),
		Endpoint:     o.provider.Endpoint(),
		Scopes:       o.Scopes,
	}
}

func (o *OidcAuthHelper) GetToken() (*oauth2.Token, error) {
	go o.startServer()
	if !waitServer(o.redirectUrl.String()) {
		return nil, fmt.Errorf("failed to start server")
	}
	startBrowser(o.oauth2Config().AuthCodeURL(o.state))
	tokenResponse := <-o.token
	if tokenResponse.err != nil {
		return nil, tokenResponse.err
	}
	return tokenResponse.token, nil
}

func (o *OidcAuthHelper) startServer() {

	o.server.Addr = o.redirectUrl.Host
	http.HandleFunc(o.redirectUrl.Path, o.handleRedirect)

	if err := o.server.ListenAndServe(); err != http.ErrServerClosed {
		o.token <- &tokenResponse{nil, err}
	}
}

func (o *OidcAuthHelper) handleRedirect(w http.ResponseWriter, r *http.Request) {
	//do not start token exchange if the request contains the wrong state
	state := r.URL.Query().Get("state")
	if state != o.state {
		fmt.Fprintln(w, "wrong state")
		return
	}
	ctx := oidc.ClientContext(r.Context(), o.client)
	oauth2Token, err := o.oauth2Config().Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		o.token <- &tokenResponse{nil, err}
		fmt.Fprintln(w, "token exchange failed: ", err)
	} else {
		var id_token string
		extra_id_token, ok := oauth2Token.Extra("id_token").(string)
		if ok {
			id_token = extra_id_token
		}
		fmt.Fprintln(w, "access_token: ", oauth2Token.AccessToken)
		fmt.Fprintln(w, "id_token: ", id_token)
		fmt.Fprintln(w, "refresh_token: ", oauth2Token.RefreshToken)
		o.token <- &tokenResponse{oauth2Token, nil}
	}
	go func() {
		o.server.Shutdown(context.Background())
	}()
}

func startBrowser(url string) bool {
	// try to start the browser
	var args []string
	switch runtime.GOOS {
	case "darwin":
		args = []string{"open"}
	case "windows":
		args = []string{"cmd", "/c", "start"}
		r := strings.NewReplacer("&", "^&")
		url = r.Replace(url)
	default:
		args = []string{"xdg-open"}
	}
	cmd := exec.Command(args[0], append(args[1:], url)...)
	return cmd.Start() == nil
}

func waitServer(url string) bool {
	tries := 20
	for tries > 0 {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
		tries--
	}
	return false
}

func randString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

//
// TODO
//
func idTokenExpired(now func() time.Time, idToken string) (bool, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("ID Token is not a valid JWT")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, err
	}
	var claims struct {
		Expiry jsonTime `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false, fmt.Errorf("parsing claims: %v", err)
	}

	return now().Add(expiryDelta).Before(time.Time(claims.Expiry)), nil
}

// jsonTime is a json.Unmarshaler that parses a unix timestamp.
// Because JSON numbers don't differentiate between ints and floats,
// we want to ensure we can parse either.
type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}

func (j jsonTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(j).Unix())
}
