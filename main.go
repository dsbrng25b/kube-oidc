package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"time"
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
		config  = &OidcAuthHelperConfig{}
		user    string
		noLogin bool
	)
	setupCmd := &cobra.Command{
		Use:   "setup <user> <client-id> <issuer-url>",
		Short: "setup kube config",
		Long:  "writes oidc configuration to kube config",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			user = args[0]
			config.ClientID = args[1]
			config.IssuerURL = args[2]

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

			config := config.AuthInfoConfig()

			if err := updateAuthProviderConfig(user, config); err != nil {
				log.Fatal(err)
			}

			if noLogin {
				return
			}

			// update
			token, err := updateToken(user)
			if err != nil {
				log.Fatal(err)
			}

			id_token, _ := token.Extra("id_token").(string)

			log.Println("id_token: ", id_token)
			log.Println("refresh_token: ", token.RefreshToken)

		},
	}
	setupCmd.Flags().StringVar(&config.ClientSecret, "client-secret", "", "client secret")
	setupCmd.Flags().StringVar(&config.CaCertificateFile, "ca-file", "", "file with certificate authority for the idp")
	setupCmd.Flags().StringVar(&config.RedirectURL, "redirect", "", "url where the server for the callback is started")
	setupCmd.Flags().StringSliceVar(&config.Scopes, "scope", nil, "a comma-seperated list of scopes to send (e.g offline_access, profile, email, etc.)")
	setupCmd.Flags().BoolVar(&noLogin, "no-login", false, "do only setup the kubeconfig without getting the tokens")

	return setupCmd
}

func newLoginCmd() *cobra.Command {
	var (
		user string
	)
	loginCmd := &cobra.Command{
		Use:   "login [name]",
		Short: "perform login to update the token",
		Long:  "perform the login with existing information from kubeconfig",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			user = args[0]
			token, err := updateToken(user)
			if err != nil {
				log.Fatal(err)
			}
			idToken, _ := token.Extra("id_token").(string)
			log.Println("id_token: ", idToken)
			log.Println("refresh_token: ", token.RefreshToken)
		},
	}
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

			idToken, ok := config["id-token"]
			if ok {
				expired, err := idTokenExpired(time.Now, idToken)
				if err != nil {
					log.Fatal(err)
				}
				if !expired {
					renderExecCredential(idToken)
					return
				}
			}
			token, err := updateToken(user)
			if err != nil {
				log.Fatal(err)
			}
			idToken, _ = token.Extra("id_token").(string)
			renderExecCredential(idToken)
		},
	}
	return pluginCmd
}

func main() {
	newRootCmd().Execute()
}
