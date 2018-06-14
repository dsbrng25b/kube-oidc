package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "kube-oidc",
	}
	rootCmd.AddCommand(newSetupCmd(), newLoginCmd(), newPluginCmd())
	return rootCmd
}

func newSetupCmd() *cobra.Command {
	var (
		user         string
		clientId     string
		issuerUrl    string
		clientSecret string
		caFile       string
		redirectUrl  string
		noLogin      bool
	)
	setupCmd := &cobra.Command{
		Use:   "setup <user> <client-id> <issuer-url>",
		Short: "setup kube config",
		Long:  "writes oidc configuration to kube config",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			user = args[0]
			clientId = args[1]
			issuerUrl = args[2]

			authInfo, err := getAuthInfo(user)

			if err != nil {
				log.Fatal(err)
			}

			if authInfo != nil && !isOidc(authInfo) {
				log.Fatal("user", user, "does already exist but does not have oidc auth provider")
			}

			// create oidc user in kubeconfig
			if authInfo == nil {
				err = createOidcAuthInfo(user)
				if err != nil {
					log.Fatal(err)
				}
			}

			config := map[string]string{
				"idp-issuer-url": issuerUrl,
				"client-id":      clientId,
			}
			if clientSecret != "" {
				config["client-secret"] = clientSecret
			}

			if err := updateAuthProviderConfig(user, config); err != nil {
				log.Fatal(err)
			}

			if noLogin {
				return
			}

			authHelper, err := oidcAuthHelperFromConfig(user)
			if err != nil {
				log.Fatal(err)
			}

			if redirectUrl != "" {
				err := authHelper.SetRedirectUrl(redirectUrl)
				if err != nil {
					log.Fatal("failed to set redirect url: ", err)
				}
			}

			token, err := authHelper.GetToken()
			if err != nil {
				log.Fatal(err)
			}

			id_token, ok := token.Extra("id_token").(string)
			if !ok {
				log.Fatal("could not get id token from response")
			}

			config = map[string]string{
				"id-token": id_token,
			}

			if token.RefreshToken != "" {
				config["refresh-token"] = token.RefreshToken
			}

			log.Println("id_token: ", id_token)
			log.Println("refresh_token: ", token.RefreshToken)

			if err := updateAuthProviderConfig(user, config); err != nil {
				log.Fatal(err)
			}

		},
	}
	setupCmd.Flags().StringVar(&clientSecret, "client-secret", "", "client secret to get the token")
	setupCmd.Flags().StringVar(&clientSecret, "ca-file", "", "file with certificate authority")
	setupCmd.Flags().StringVar(&redirectUrl, "redirect", "", "url where the server for the callback is started")
	setupCmd.Flags().BoolVar(&noLogin, "no-login", false, "do only setup the kubeconfig without getting the tokens")

	return setupCmd
}

func newLoginCmd() *cobra.Command {
	var (
		user        string
		redirectUrl string
	)
	loginCmd := &cobra.Command{
		Use:   "login [name]",
		Short: "perform login to update the token",
		Long:  "perform the login with existing information from kubeconfig",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			user = args[0]
			authHelper, err := oidcAuthHelperFromConfig(user)
			if err != nil {
				log.Fatal(err)
			}

			if redirectUrl != "" {
				err := authHelper.SetRedirectUrl(redirectUrl)
				if err != nil {
					log.Fatal("failed to set redirect url: ", err)
				}
			}

			token, err := authHelper.GetToken()
			if err != nil {
				log.Fatal(err)
			}

			id_token, ok := token.Extra("id_token").(string)
			if !ok {
				log.Fatal("could not get id token from response")
			}

			config := map[string]string{
				"id-token": id_token,
			}

			if token.RefreshToken != "" {
				config["refresh-token"] = token.RefreshToken
			}

			log.Println("id_token: ", id_token)
			log.Println("refresh_token: ", token.RefreshToken)

			if err := updateAuthProviderConfig(user, config); err != nil {
				log.Fatal(err)
			}
		},
	}
	loginCmd.Flags().StringVar(&redirectUrl, "redirect", "", "url where the server for the callback is started")
	return loginCmd
}

func newPluginCmd() *cobra.Command {
	var (
		user string
	)
	pluginCmd := &cobra.Command{
		Use:   "plugin [user]",
		Short: "return id_token of user",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			user = args[0]
			config, err := getAuthProviderConfig(user)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(os.Stderr, "exec plugin")

			id_token, ok := config["id-token"]
			if !ok {
				log.Fatal("could not get id token")
			}
			renderExecCredential(id_token)
		},
	}
	return pluginCmd
}

func main() {
	newRootCmd().Execute()
}
