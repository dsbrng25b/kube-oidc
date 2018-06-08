package main

import (
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func isOidc(authInfo *api.AuthInfo) bool {
	if authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "oidc" {
		return true
	}
	return false
}

func getAuthInfoByName(name string) (*api.AuthInfo, error) {
	config, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		return nil, err
	}
	if authInfo, ok := config.AuthInfos[name]; ok {
		return authInfo, nil
	}
	return nil, nil
}

func setAuthInfo(name string, authInfo *api.AuthInfo) error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	config, err := loadingRules.Load()
	if err != nil {
		return err
	}

	config.AuthInfos[name] = authInfo

	return clientcmd.ModifyConfig(loadingRules, *config, false)
}

func NewOidcAuthInfo(clientId, issuerUrl string) *api.AuthInfo {
	authInfo := api.NewAuthInfo()
	authInfo.AuthProvider = &api.AuthProviderConfig{
		Name: "oidc",
		Config: map[string]string{
			"client-id":      clientId,
			"idp-issuer-url": issuerUrl,
		},
	}
	return authInfo
}
