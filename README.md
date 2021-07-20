# YubiWall - Nginx ingress Yubikey authentication

YubiWall is a simple authentication engine that can be integrated with Nginx auth_request module to provide simple authentication when accessing HTTPS resoures. It is light weight and is designed to integrate easily with Kubernets Nignx ingress controller.

While YubiWall can be helful to prevent unauthorized access to ingress resources, it is not recommended to use this as the only form of authentication.

## Installation

You will need Nginx ingress controller installed. Also recommended to have cert-manager installed, Kubernetes templates will assume you have cert-manager configured with Lets Encrypt issuer (feel free to edit this in `kubernetes/ingress.yaml`).

Configure ENV variables in `kubernetes/deployment.yaml`, you will need to set the following:

- `YUBICO_CLIENT_ID`
  - Get from https://upgrade.yubico.com/getapikey/
- `YUBICO_SECRET_KEY`
- `ALLOWED_KEYS`
  - Comma separated list of allowed keys, this is the first 12 characters you get when pressing your yubikey
- `JWT_SECRET` (optional)
  - Set a secret value here to support persistent authentications across yubiwall restarts
- `KEY_TTL` (optional)
  - How many minutes an authentication will be valid.


```
$ kubectl apply -f kubernetes/deployment.yaml
$ kubectl apply -f kubernetes/service.yaml
$ kubectl apply -f kubernetes/ingress.yaml
```

## Configuration

Adding authentication to an ingress is easy, simply add these annotations:

```
nginx.ingress.kubernetes.io/auth-url: "https://auth.example.com/verify"
nginx.ingress.kubernetes.io/auth-signin: "https://auth.example.com/login"
```

Where `https://auth.example.com` points to your yubiwall instance.

## Authentication 

Navigate to your protected resource and you should be presented with this view. Tap your Yubikey to authenticate and you will be redirected.

![auth](https://raw.githubusercontent.com/rctl/yubiwall/master/demo/auth.png)

One authenticated you will be able to access during the session (also for resources that share the same top level domain)

![success](https://raw.githubusercontent.com/rctl/yubiwall/master/demo/success.png)

Yubiwall and your protected ingress need to share the same top level hostname. Ex. `auth.example.com` and `my-service.example.com` will work, but you cannot host Yubiwall on another host (ex. `something-else.com`). Tokens are shared across all sub-domains, you only need to authenticate once per top level hostname.

## Troubleshooting 

Here are some common error messages:

`Token was invalid, please try again.`

Authentication with Yubico API failed (ex. entered token is malformed)

`Token was valid, but is not in list of allowed keys.`

Make sure your key ID is in the allowed keys (first 12 chars of your token)

`Authentication failed, please try again.`

Token is not valid (ex. reused or invalid)

## Improvements 

Here are some improvements I am planning:

- Multi domain handling
- Set yubikey ID per ingress
- Automatic configure of Ingress via Kubernetes API and separate annotation
- Code clean-up
- Better logging
