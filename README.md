# oidc-2-k8s-impersonation

This application helps translating OIDC JWT token to set of kubernetes impersonation headers

## Development

### Local environment

Add to `/etc/hosts` file the following line:
```
127.0.0.1 oidc-provider
```

In `./hack` directory execute `docker compose up -d` to start a local OIDC provider.

Enter `http://localhost:4180` in your browser with one of Dex local users:
* user@example.com / password
* admin@example.com / admin

# test
