package main

import (
	"github.com/spf13/cobra"
	"log"
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "kube-oidc",
	}
	rootCmd.AddCommand(newSetupCommand(), newLoginCommand())
	return rootCmd
}

func newSetupCommand() *cobra.Command {
	var (
		authInfoName string
		clientId     string
		issuerUrl    string
		clientSecret string
		noLogin      bool
	)
	setupCmd := &cobra.Command{
		Use:   "setup <name> <client-id> <issuer-url>",
		Short: "setup kube config",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			authInfoName = args[0]
			clientId = args[1]
			issuerUrl = args[2]

			authInfo, err := getAuthInfoByName(authInfoName)
			if err != nil {
				log.Fatal(err)
			}
			if !isOidc(authInfo) {
				log.Fatal(authInfoName, " already exists but is not of type oidc")
			}
			if authInfo == nil {
				authInfo = NewOidcAuthInfo(clientId, issuerUrl)
			} else {
				authInfo.AuthProvider.Config["idp-issuer-url"] = issuerUrl
				authInfo.AuthProvider.Config["client-id"] = clientId
				if clientSecret != "" {
					authInfo.AuthProvider.Config["client-secret"] = clientSecret
				}
			}
			tokenGetter, err := NewTokenGetter(clientId, clientSecret, issuerUrl)
			if err != nil {
				log.Fatal(err)
			}
			token := tokenGetter.GetToken()

			id_token, ok := token.Extra("id_token").(string)
			if !ok {
				log.Fatal("could not get id token from response")
			}
			authInfo.AuthProvider.Config["id-token"] = id_token

			if token.RefreshToken != "" {
				authInfo.AuthProvider.Config["refresh-token"] = token.RefreshToken
			}

			err = setAuthInfo(authInfoName, authInfo)
			if err != nil {
				log.Fatal(err)
			}

		},
	}
	setupCmd.Flags().StringVar(&clientSecret, "client-secret", "", "client secret to get the token")
	setupCmd.Flags().BoolVar(&noLogin, "no-login", false, "do only setup the kubeconfig without getting the tokens")

	return setupCmd
}

func newLoginCommand() *cobra.Command {
	loginCmd := &cobra.Command{
		Use:   "login [name]",
		Short: "do the login",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("run setup")
		},
	}
	return loginCmd
}

func main() {
	newRootCmd().Execute()
}
