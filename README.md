# deno-srv
**World's first** Deno web server for multiple hosts.

- Uses Deno's new, yet currently unofficial, sni callback!
- Comes with automatic tls certificate request! (while auto-renew isn't there, yet - but will be included in the next release!)

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

Warning: This project is in active development (as of 19-Sep-24) and its api is subject to change at any time without prior warning.

**Update:** Deno v1.45.3 and up do not contain the DoS bug from rustls-tokio-stream anymore!

## Features
- Automatically get one certificate per host
- Fileserver
- Reverse Proxy (socket.io websockets work, pure websockets do not yet)
- Request Logging
- Basic Auth
- Redirect
- Mark requests as forbidden
- Add a default response function for unhandeled requests
- Add default response headers to all responses
- ... and many more

## For people interested in Deno's new sni callback
### How to run the sni callback test
- Use Deno with version >= v1.43.3
- `deno run -A ./config.ts`
- Finally visit https://localhost:8008/test.txt
  - Note: You will receive a warning about an insecure certificate (because the certificate for 'localhost' is obviously self-signed)
- Now visit https://127.0.0.1:8008/test.txt, which will give you an error as '127.0.0.1' non-sni connections are currently not handled properly and there is no certificate for the host '127.0.0.1'
