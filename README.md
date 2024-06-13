# deno-srv
... now uses Deno's new, yet currently unofficial, sni callback!
... now comes with automatic tls certificate request!

## How to run the sni callback test
- Checkout Deno's main branch (as currrent release v1.44.0 does not contain the sni callback yet)
- [Build Deno as described here](https://docs.deno.com/runtime/manual/references/contributing/building_from_source#building-deno)
- `<path to deno sources>/target/debug/deno run -A ./config.ts`
- Finally visit https://localhost:8008/test.txt
  - Note: You will receive a warning about an insecure certificate (because the certificate for 'localhost' is obviously self-signed)
- Now visit https://127.0.0.1:8008/test.txt, which will give you an error as '127.0.0.1' non-sni connections are currently not handled properly and there is no certificate for the host '127.0.0.1'