# kube-oidc

Kube-oidc helps you to bootstrap the OIDC configuration for users in the `kubectl` configuration (usually `$HOME/.kube/config`).
It also helps you to refresh the id_token if you don't have a refresh_token or if your refresh_token has expired.

## Usage
### Setup
Create a user in the `kubectl` configuration with OIDC auth provider enabled:
```
kube-oidc setup <user> <client-id> <issuer-url>
```
| Option            | Description |
| ----------------  | ----------- |
| `--client-secret` | The client secret which is used to obtain the id_token |
| `--ca-file`       | An additional CA which is used to trust the issuer url |
| `--scope`         | A scope additional to the standard openid scope |
| `--redirect-url`  | The url where the OIDC provider shuld redirect to (default: http://127.0.0.1:5555/callback) |
To get a list of all available options run `kube-oidc setup --help`.

The `kube-oidc setup` command does the following things:

* Create a user in the `kubectl` configuration and sets `oidc` as authentication provider
* Starts a browser and opens the login page of the OIDC provider
* Starts a web server (binds to the host of the redirect-url) to get the code after the redirection from the OIDC provider to obtain the id_token
* Obtain the id_token from the OIDC provider
* Write id_token and refresh_token (if available) to `kubectl` configuration

Usually you want to pass `--scope offline_access` to the setup command to obtain a refresh token.
If you have a valid refresh token `kubectl` can update expired id_tokens itself and `kube-oidc` is no longer required.

After you have successfully ran the `setup` command you can show your token:
```
kube-oidc info <user>
```

If your refresh_token has expired or you don't have one you can get a new id_token with the login command:
```
kube-oidc login <user>
```

The login command uses the settings which are already in the `kubectl` configuration.

## kubectl
To use the created user with `kubectl` you have to set your context accordingly:
```
kube-oidc setup my-oidc-user kubernetes https://idp.yourcorp.com
kubectl config set-context my-context --cluster=my-cluster --user=my-oidc-user
kubectl config use-context my-context
```

## client-go credential plugin
If your OIDC provider does not support the offline_access scope (you can't obtain a refresh_token) you can use `kube-oidc plugin` as a [credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins).
Therefor you first have to configure a normal OIDC user (e.g. `oidc-user`):
```
kube-oidc setup oidc-user kubernetes https://idp.yourcorp.ch
```
Then you configure a second user (e.g. `oidc-plugin`) in the `kubectl` configuration with the credential plugin enabled:
```yaml
# ...
users:
- name: oidc-plugin
  user:
    exec:
	  apiVersion: client.authentication.k8s.io/v1alpha1
	  # refers to $HOME/.kube/bin/kube-oidc
	  command: "./bin/kube-oidc"
	  args:
	  - plugin
	  - oidc-user

# already created by kube-oidc setup
- name: oidc-user
  user:
    auth-provider:
	  name: oidc
	  config:
	    client-id: kubernetes
		idp-issuer-url: https://idp.yourcorp.com
		id-token: <YOUR_ID_TOKEN>
# ...
```
The plugin command then simply returns the id_token of the normal `oidc-user`. If the `oidc-user` does not have an id_token or the id_token has expired, it updates the id_token first (`kube-oidc login oidc-user`).

