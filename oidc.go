package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

const DEFAULT_REDIRECT_URL = "http://127.0.0.1:5555/callback"

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

type OidcAuthHelper struct {
	ClientID          string
	ClientSecret      string
	IssuerUrl         string
	Scopes            []string
	CaCertificateFile string
	redirectUrl       *url.URL
	client            *http.Client
	server            *http.Server
	provider          *oidc.Provider
	token             chan *tokenResponse
	state             string
}

type tokenResponse struct {
	token *oauth2.Token
	err   error
}

func NewOidcAuthHelper(clientId, issuerUrl string) (*OidcAuthHelper, error) {
	authHelper := &OidcAuthHelper{
		ClientID:  clientId,
		IssuerUrl: issuerUrl,
		Scopes:    []string{oidc.ScopeOpenID, "offline_access", "profile", "email"},
		server:    &http.Server{},
		client:    &http.Client{},
		token:     make(chan *tokenResponse, 1),
		state:     randString(30),
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
		fmt.Fprintln(w, "access_token: ", oauth2Token.AccessToken)
		fmt.Fprintln(w, "id_token: ", oauth2Token.Extra("id_token").(string))
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
