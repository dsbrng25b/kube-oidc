package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2" //TODO: check import path
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
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

type TokenGetter struct {
	ClientID     string
	ClientSecret string
	IssuerUrl    string
	redirectUrl  string //TODO: use url here
	server       *http.Server
	provider     *oidc.Provider
	token        chan *oauth2.Token
}

func NewTokenGetter(clientId, clientSecret, issuerUrl string) (*TokenGetter, error) {
	tokenGetter := &TokenGetter{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		IssuerUrl:    issuerUrl,
		redirectUrl:  "http://localhost:1337/callback",
		server:       &http.Server{},
	}
	ctx := oidc.ClientContext(context.Background(), &http.Client{})
	provider, err := oidc.NewProvider(ctx, issuerUrl)
	if err != nil {
		return nil, err
	}
	tokenGetter.provider = provider
	return tokenGetter, nil
}

func (tg *TokenGetter) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     tg.ClientID,
		ClientSecret: tg.ClientSecret,
		RedirectURL:  tg.redirectUrl,
		Endpoint:     tg.provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}
}

func (tg *TokenGetter) handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("start callback")
	ctx := oidc.ClientContext(r.Context(), &http.Client{})
	log.Println("exchange token with code ", r.URL.Query().Get("code"))
	oauth2Token, err := tg.oauth2Config().Exchange(ctx, r.URL.Query().Get("code"))
	log.Println(oauth2Token, err)
	fmt.Fprintln(w, "ok")
	if err != nil {
		log.Println("send oauth token to channel")
		tg.token <- oauth2Token
	} else {
		log.Println("send nil token to channel")
		tg.token <- nil
	}
	go func() {
		log.Println("Start stop server")
		tg.server.Shutdown(context.Background())
	}()
	log.Println("end callback")
}

func (tg *TokenGetter) startServer() {
	http.HandleFunc("/callback", tg.handleCallback)
	tg.server.Addr = ":1337"
	if err := tg.server.ListenAndServe(); err != http.ErrServerClosed {
		log.Println("could not start server")
		tg.token <- nil
	}
	log.Println("stop server")
}

func (tg *TokenGetter) GetToken() *oauth2.Token {
	// since we don't wait on shutdown there is the change that the last response is not deliverd to the client
	go tg.startServer()
	if !waitServer("http://localhost:1337/") {
		log.Println("failed to reach server")
		return nil
	}
	startBrowser(tg.oauth2Config().AuthCodeURL("my state", oauth2.AccessTypeOffline))
	log.Println("wait for token")
	token := <-tg.token
	log.Println("got token")
	return token
}
