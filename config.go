package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauth "k8s.io/client-go/pkg/apis/clientauthentication/v1alpha1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"os"
	"strings"
)

var defaultRules = clientcmd.NewDefaultClientConfigLoadingRules()

// check if an AuthInfo uses oidc AuthProvider
func isOidc(authInfo *api.AuthInfo) bool {
	if authInfo != nil && authInfo.AuthProvider != nil && authInfo.AuthProvider.Name == "oidc" {
		return true
	}
	return false
}

// get an AuthInfo by user name
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

// set an AuthInfo
func setAuthInfo(user string, authInfo *api.AuthInfo) error {
	config, err := defaultRules.Load()
	if err != nil {
		return err
	}

	config.AuthInfos[user] = authInfo
	return clientcmd.ModifyConfig(defaultRules, *config, false)
}

// get configuration of the AuthProvider from an AuthInfo
func getAuthProviderConfig(user string) (map[string]string, error) {
	authInfo, err := getAuthInfo(user)
	if err != nil {
		return nil, err
	}
	if authInfo != nil && authInfo.AuthProvider != nil && authInfo.AuthProvider.Config != nil {
		return authInfo.AuthProvider.Config, nil
	} else {
		return nil, fmt.Errorf("can't get configuration from user '%s'", user)
	}
}

// sets configuration of an AuthProvider from an AuthInfo
func setAuthProviderConfig(user string, config map[string]string) error {
	persister := clientcmd.PersisterForUser(defaultRules, user)
	return persister.Persist(config)
}

// updates AuthProviderConfig (merges with existing configurations)
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

// creates an AuthInfo with oidc configured as AuthProvider
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

// returuns an OidcAuthHelper configured with the config from the AuthProvider
func oidcAuthHelperFromConfig(user string) (*OidcAuthHelper, error) {
	kubeConfig, err := getAuthProviderConfig(user)
	if err != nil {
		return nil, err
	}

	config := &OidcAuthHelperConfig{}
	config.SetFromAuthInfoConfig(kubeConfig)
	authHelper, err := NewOidcAuthHelper(config)
	if err != nil {
		return nil, err
	}
	return authHelper, nil
}

// updates tokens of user in kube config
func updateToken(user string) (*oauth2.Token, error) {
	authHelper, err := oidcAuthHelperFromConfig(user)
	if err != nil {
		return nil, err
	}

	token, err := authHelper.GetToken()
	if err != nil {
		return nil, err
	}

	id_token, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("could not get id token from response")
	}

	config := map[string]string{
		"id-token": id_token,
	}

	if token.RefreshToken != "" {
		config["refresh-token"] = token.RefreshToken
	}

	if err := updateAuthProviderConfig(user, config); err != nil {
		return nil, err
	}

	return token, nil
}

// returns json encoded ExecCredential object as string
func renderExecCredential(token string) (string, error) {
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
		return "", err
	}
	return string(bytes), nil
}

// setup an AuthInfo which uses kube-oidc as exec-based authentication plugin
func setupPlugin(pluginUser, oidcUser, cmdPath string) error {
	var err error
	if cmdPath == "" {
		cmdPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("could not determine executable: %s", err)
		}
	}

	pluginAuthInfo := api.NewAuthInfo()
	pluginAuthInfo.Exec = &api.ExecConfig{
		Command: cmdPath,
		Args: []string{
			"plugin",
			oidcUser,
		},
		APIVersion: "client.authentication.k8s.io/v1alpha1",
	}

	return setAuthInfo(pluginUser, pluginAuthInfo)
}

// get kubectl config command line to make the configuration for a user
func getConfigCmd(user string) (string, error) {
	config, err := getAuthProviderConfig(user)
	if err != nil {
		return "", err
	}
	args := []string{"kubectl", "config", "set-credentials", user, "--auth-provider=oidc"}
	for key, value := range config {
		args = append(args, fmt.Sprintf("--auth-provider-arg=%s='%s'", key, strings.Replace(value, "'", "'\"'\"'", -1)))
	}
	return strings.Join(args, " "), nil
}
