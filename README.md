# YubiWall - Nginx ingress Yubikey authentication

YubiWall is a simple authentication engine that can be integrated with Nginx auth_request module to provide simple authentication when accessing HTTPS resoures. It is light weight and is designed to integrate easily with Kubernets Nignx ingress controller.

## Installation

You will need Nginx ingress controller installed. Also recommended to have cert-manager installed, templates will assume you have cert-manager configured with Lets Encrypt issuer (feel free to edit this in `kubernetes/ingress.yaml`).

Configure ENV variables in `kubernetes/deployment.yaml`, you will need to set the following:

- YUBICO_CLIENT_ID
  - Get from https://upgrade.yubico.com/getapikey/
- YUBICO_SECRET_KEY
- JWT_SECRET
  - Some random secret value (to allow session persistance across yubiwall restarts)
- DOMAIN
  - Domain to use for setting cookie. This needs to be same domain as Yubiwall **and** the protected resource. Cross domain validation is not supported. You can use different sub domains for Yubiwall and other resources, if you do, configure the top level shared domain here.
- ALLOWED_KEYS
  - Comma separated list of allowed keys, this is the first 12 characters you get when pressing your yubikey


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

## Troubleshooting 

Here are some common error messages:

`Token was invalid, please try again.` - Authentication with Yubico API failed (ex. entered token is malformed)

`Token was valid, but is not in list of allowed keys.` - Make sure your key ID is in the allowed keys (first 12 chars of your token)

`Authentication failed, please try again.` - Token is not valid (ex. reused or invalid)
