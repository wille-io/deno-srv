# deno-srv
**World's first** Deno web server for multiple hosts.

- Uses Deno's new, yet currently unofficial, sni callback!
- Comes with automatic tls certificate request! (while auto-renew isn't there, yet)

Configure your web server in a language we all know and love: TypeScript.

Example on how to host your own, automatically https secured static website with automatic http-to-https redirect:
```typescript
import * as Srv from "https://deno.land/x/srv@v0.3.0/srv.ts"

new Srv.HttpsListener(
  {
    autoRedirectHttps: true,
    hostHandlers:
    [
      new Srv.HostHandler("example.com",
        {
          handlers:
          [
            new Srv.FileHandler("/var/www/"),
          ]
        }
      ),
    ]
  }
);
```

Warning: This project is in active development (as of 25-Jun-24) and its api is subject to change at any time without prior warning.

**Warning**: There's currently a DoS bug in rustls-tokio-stream which unfortunately makes this project **not production ready**: https://github.com/denoland/rustls-tokio-stream/pull/28

If you somehow still want to use this web server in production (as I already do!), you have to build Deno with the rustls-tokio-stream fix from here: https://github.com/wille-io/rustls-tokio-stream on branch 'cancel-accept-on-client-disconnect'.

## Features
- Automatically get one certificate per host
- Fileserver
- Reverse Proxy
- Request Logging
- Basic Auth
- Redirect
- Mark requests as forbidden
- Add a default response function for unhandeled requests
- Add default response headers to all responses
- ... and many more

## How to run the sni callback test
- Use Deno with version >= v1.43.3
- `deno run -A ./config.ts`
- Finally visit https://localhost:8008/test.txt
  - Note: You will receive a warning about an insecure certificate (because the certificate for 'localhost' is obviously self-signed)
- Now visit https://127.0.0.1:8008/test.txt, which will give you an error as '127.0.0.1' non-sni connections are currently not handled properly and there is no certificate for the host '127.0.0.1'
