package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"
)

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

const DEFAULT_REDIRECT_URL = "http://127.0.0.1:5555/callback"

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
		token:     make(chan *tokenResponse, 0),
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
	if !waitServer(fmt.Sprintf("%s/asdfasfasfas", o.redirectUrl.String())) {
		return nil, fmt.Errorf("failed to start server")
	}
	startBrowser(o.oauth2Config().AuthCodeURL("my random state"))
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
	// check if state
	ctx := oidc.ClientContext(r.Context(), o.client)
	oauth2Token, err := o.oauth2Config().Exchange(ctx, r.URL.Query().Get("code"))
	fmt.Fprintln(w, "ok")
	if err != nil {
		o.token <- &tokenResponse{nil, err}
	} else {
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
