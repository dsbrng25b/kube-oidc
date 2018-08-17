package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
//
// NOTE(ericchiang): this is take from golang.org/x/oauth2
const expiryDelta = 10 * time.Second

const defaultRedirectURL = "http://127.0.0.1:5555/callback"

var randomLetterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

type OidcAuthHelperConfig struct {
	ClientID          string
	ClientSecret      string
	IssuerURL         string
	Scopes            []string
	CaCertificateFile string
	RedirectURL       string
}

func (c *OidcAuthHelperConfig) AuthInfoConfig() map[string]string {
	var config = map[string]string{}
	if c.IssuerURL != "" {
		config["idp-issuer-url"] = c.IssuerURL
	}
	if c.ClientID != "" {
		config["client-id"] = c.ClientID
	}
	if c.ClientSecret != "" {
		config["client-secret"] = c.ClientSecret
	}
	if c.CaCertificateFile != "" {
		config["idp-certificate-authority"] = c.CaCertificateFile
	}
	if c.RedirectURL != "" {
		config["_redirect-url"] = c.RedirectURL
	}
	if len(c.Scopes) != 0 {
		config["_scopes"] = strings.Join(c.Scopes, ",")
	}
	return config
}

func (c *OidcAuthHelperConfig) SetFromAuthInfoConfig(config map[string]string) {
	c.IssuerURL, _ = config["idp-issuer-url"]
	c.ClientID, _ = config["client-id"]
	c.ClientSecret, _ = config["client-secret"]
	c.CaCertificateFile, _ = config["idp-certificate-authority"]
	c.RedirectURL, _ = config["_redirect-url"]
	scopes, ok := config["_scopes"]
	if ok {
		c.Scopes = strings.Split(scopes, ",")
	}
}

func (c *OidcAuthHelperConfig) GetScopes() []string {
	var scopes = []string{oidc.ScopeOpenID}
	scopes = append(scopes, c.Scopes...)
	return scopes
}

type OidcAuthHelper struct {
	*OidcAuthHelperConfig
	client   *http.Client
	server   *http.Server
	provider *oidc.Provider
	token    chan *tokenResponse
	state    string
}

type tokenResponse struct {
	token *oauth2.Token
	err   error
}

func NewOidcAuthHelper(config *OidcAuthHelperConfig) (*OidcAuthHelper, error) {
	authHelper := &OidcAuthHelper{
		OidcAuthHelperConfig: config,
	}
	authHelper.token = make(chan *tokenResponse, 1)
	authHelper.state = randString(30)

	// set default values
	if authHelper.RedirectURL == "" {
		authHelper.RedirectURL = defaultRedirectURL
	}

	// initialize http server
	url, err := url.Parse(authHelper.RedirectURL)
	if err != nil {
		return nil, err
	}
	handler := http.NewServeMux()
	handler.HandleFunc(url.Path, authHelper.handleRedirect)
	authHelper.server = &http.Server{
		Addr:    url.Host,
		Handler: handler,
	}

	// initialize http client
	authHelper.client, err = authHelper.httpClient()
	if err != nil {
		return nil, err
	}

	// initialize oidc provider
	ctx := oidc.ClientContext(context.Background(), authHelper.client)
	provider, err := oidc.NewProvider(ctx, authHelper.IssuerURL)
	if err != nil {
		return nil, err
	}
	authHelper.provider = provider
	return authHelper, nil
}

func (o *OidcAuthHelper) GetToken() (*oauth2.Token, error) {
	go o.startServer()
	if !waitServer(o.RedirectURL) {
		return nil, fmt.Errorf("failed to start server")
	}

	out, err := startBrowser(o.oauth2Config().AuthCodeURL(o.state))
	if err != nil {
		return nil, fmt.Errorf("Browser command finished with error: %v, output: %s", err, out)
	}

	select {
	case tokenResponse := <-o.token:
		if tokenResponse.err != nil {
			return nil, tokenResponse.err
		}
		return tokenResponse.token, nil
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("Timeout waiting for token")
	}
}

func (o *OidcAuthHelper) httpClient() (*http.Client, error) {
	var tlsConfig *tls.Config
	if o.CaCertificateFile != "" {
		tlsConfig = &tls.Config{RootCAs: x509.NewCertPool()}
		rootCABytes, err := ioutil.ReadFile(o.CaCertificateFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read ca file: %v", err)
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
			return nil, fmt.Errorf("no certs found in CA file %q", o.CaCertificateFile)
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func (o *OidcAuthHelper) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Endpoint:     o.provider.Endpoint(),
		Scopes:       o.GetScopes(),
	}
}

func (o *OidcAuthHelper) startServer() {
	if err := o.server.ListenAndServe(); err != http.ErrServerClosed {
		o.token <- &tokenResponse{nil, err}
	}
}

func (o *OidcAuthHelper) handleRedirect(w http.ResponseWriter, r *http.Request) {
	//do not start token exchange if the request contains the wrong state
	state := r.URL.Query().Get("state")
	if state != o.state {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "wrong state '%s'", state)
		return
	}
	ctx := oidc.ClientContext(r.Context(), o.client)
	oauth2Token, err := o.oauth2Config().Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		o.token <- &tokenResponse{nil, err}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "token exchange failed: ", err)
	} else {
		fmt.Fprintln(w, "login successful: you can now safely close this browser window")
		o.token <- &tokenResponse{oauth2Token, nil}
	}
	go func() {
		o.server.Shutdown(context.Background())
	}()
}

func isSubsystemForLinux() bool {
	cmd := exec.Command("uname", "-r")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	matched, err := regexp.MatchString("Microsoft", string(out[:]))
	if err != nil {
		return false
	}
	return matched
}

func getOs() string {
	if runtime.GOOS == "linux" && isSubsystemForLinux() {
		return "windows"
	}
	return runtime.GOOS
}

func startBrowser(url string) ([]byte, error) {
	// try to start the browser
	var args []string
	switch getOs() {
	case "darwin":
		args = []string{"open"}
	case "windows":
		args = []string{"cmd.exe", "/c", "start"}
		r := strings.NewReplacer("&", "^&")
		url = r.Replace(url)
	default:
		args = []string{"xdg-open"}
	}
	cmd := exec.Command(args[0], append(args[1:], url)...)
	return cmd.CombinedOutput()
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
		b[i] = randomLetterRunes[rand.Intn(len(randomLetterRunes))]
	}
	return string(b)
}

func prettyToken(idToken string) (bytes.Buffer, error) {
	var prettyJson bytes.Buffer
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return prettyJson, fmt.Errorf("ID Token is not a valid JWT")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return prettyJson, err
	}

	err = json.Indent(&prettyJson, []byte(payload), "", "  ")
	if err != nil {
		return prettyJson, err
	}
	return prettyJson, nil
}

func getTokenExpiryTime(idToken string) (time.Time, error) {
	var expiryTime time.Time
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return expiryTime, fmt.Errorf("ID Token is not a valid JWT")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return expiryTime, err
	}
	var claims struct {
		Expiry jsonTime `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return expiryTime, fmt.Errorf("parsing claims: %v", err)
	}

	return time.Time(claims.Expiry), nil
}

func idTokenExpired(now func() time.Time, idToken string) (bool, error) {
	expiryTime, err := getTokenExpiryTime(idToken)
	if err != nil {
		return false, nil
	}
	return now().Add(expiryDelta).After(expiryTime), nil
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
