package main

import (
	"encoding/json"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauth "k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var defaultRules *clientcmd.ClientConfigLoadingRules

func init() {
	defaultRules = clientcmd.NewDefaultClientConfigLoadingRules()
}

func isOidc(authInfo *api.AuthInfo) bool {
	if authInfo != nil && authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "oidc" {
		return true
	}
	return false
}

func getAuthInfo(user string) (*api.AuthInfo, error) {
	config, err := defaultRules.Load()
	if err != nil {
		return nil, err
	}
	if authInfo, ok := config.AuthInfos[user]; ok {
		return authInfo, nil
	}
	return nil, nil
}

func setAuthInfo(user string, authInfo *api.AuthInfo) error {
	config, err := defaultRules.Load()
	if err != nil {
		return err
	}

	config.AuthInfos[user] = authInfo
	return clientcmd.ModifyConfig(defaultRules, *config, false)
}

func getAuthProviderConfig(user string) (map[string]string, error) {
	authInfo, err := getAuthInfo(user)
	if err != nil {
		return nil, err
	}
	if authInfo != nil && authInfo.AuthProvider != nil && authInfo.AuthProvider.Config != nil {
		return authInfo.AuthProvider.Config, nil
	} else {
		return map[string]string{}, nil
	}
}

func setAuthProviderConfig(user string, config map[string]string) error {
	persister := clientcmd.PersisterForUser(defaultRules, user)
	return persister.Persist(config)
}

func updateAuthProviderConfig(user string, config map[string]string) error {
	currentConfig, err := getAuthProviderConfig(user)
	if err != nil {
		return err
	}

	for key, value := range config {
		currentConfig[key] = value
	}
	return setAuthProviderConfig(user, currentConfig)
}

func createOidcAuthInfo(user string) error {
	authInfo, err := getAuthInfo(user)
	if err != nil {
		return err
	}
	if authInfo != nil {
		return fmt.Errorf("user %s does already exist", user)
	}
	authInfo = api.NewAuthInfo()
	authInfo.AuthProvider = &api.AuthProviderConfig{
		Name:   "oidc",
		Config: map[string]string{},
	}
	return setAuthInfo(user, authInfo)
}

func oidcAuthHelperFromConfig(user string) (*OidcAuthHelper, error) {
	config, err := getAuthProviderConfig(user)
	if err != nil {
		return nil, err
	}

	issuerUrl, ok := config["idp-issuer-url"]
	if !ok {
		return nil, fmt.Errorf("idp-issuer-url missing in config")
	}

	clientId, ok := config["client-id"]
	if !ok {
		return nil, fmt.Errorf("client-id missing in config")
	}

	authHelper, err := NewOidcAuthHelper(clientId, issuerUrl)
	if err != nil {
		return nil, err
	}
	authHelper.ClientSecret = config["client-secret"]
	return authHelper, nil
}

func renderExecCredential(token string) {
	execCredential := &clientauth.ExecCredential{
		metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1alpha1",
		},
		clientauth.ExecCredentialSpec{},
		&clientauth.ExecCredentialStatus{
			Token: token,
		},
	}
	bytes, err := json.Marshal(execCredential)
	if err != nil {
		fmt.Println("error: ", err)
	}
	fmt.Println(string(bytes))
}
