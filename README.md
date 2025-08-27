# failscale
Like tailscale but with additional fail

## wtf
This is the server component of failscale, which implements a single "failnet", analogous to a single tailscale tailnet.  The server daemon, failscaled, introduces clients to each other and coordinates endpoints so that the clients can generate wireguard configs.
