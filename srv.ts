import * as brotli from "https://deno.land/x/brotli@0.1.7/mod.ts";
import * as acme from "https://deno.land/x/acme@v0.4.1/acme.ts";
import { X509, zulutodate } from "npm:jsrsasign";
import { decode as decodeBase64 } from "https://deno.land/std@0.192.0/encoding/base64.ts"; // basic auth
import { typeByExtension } from "https://deno.land/std@0.200.0/media_types/type_by_extension.ts";
import { db } from "https://deno.land/std@0.200.0/media_types/_db.ts"; // list of compressible content-types
import { extname } from "https://deno.land/std@0.200.0/path/extname.ts";
import { fromFileUrl } from "https://deno.land/std@0.200.0/path/from_file_url.ts";
import { resolve } from "https://deno.land/std@0.200.0/path/resolve.ts";
import { decodeHex } from "jsr:@std/encoding/hex"; // basic auth

/*
  There's currently a DoS bug in rustls-tokio-stream: https://github.com/denoland/rustls-tokio-stream/pull/28
*/

/*
  TODO: etag, x-forwarded-*, set-header handler, keep alive?, deno metrics handler, system metrics handler, system info handler,
  browse handler, reload config on signal, reload config (without killing listeners?), 431, 503 handler with on/off url,
  503 via system signal, 504 in proxy handler, etag with file size limit, etag with hashed last modified timestamp?,
  path matching with wildcards, add headers handler, rate limiter, update checker, auto-updater?, cors handler,
  zstd compression, HSTS, add `charset=utf-8` to non-binary content-types, vary accept-encoding
*/

/*
TODO: etag => if-match / if-none-match
import {
  calculate,
  ifNoneMatch,
} from "https://deno.land/std@0.201.0/http/etag.ts";
import { assert } from "https://deno.land/std@0.201.0/assert/assert.ts"

const body = "hello deno!";

Deno.serve(async (req) => {
  const ifNoneMatchValue = req.headers.get("if-none-match");
  const etag = await calculate(body);
  assert(etag);
  if (!ifNoneMatch(ifNoneMatchValue, etag)) {
    return new Response(null, { status: 304, headers: { etag } });
  } else {
    return new Response(body, { status: 200, headers: { etag } });
  }
*/

/* Mendatory HTTP Security:
  HSTS: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload // HSTS, remember for 2 years
  X-Content-Type-Options: nosniff // browser blocks a request if `content-type` header doesn't match the requested resource - e.g. if a `<script>` is loaded and `content-type` is not 'text/javascript'
  X-XSS-Protection: 1; mode=block // prevents XSS for older browsers (maybe 0, without block is enough?)
  (for api endpoints:) Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
*/

/* Security Considerations (see https://infosec.mozilla.org/guidelines/web_security#x-xss-protection):
  Content-Security-Policy: default-src https: 'unsafe-eval'; frame-ancestors 'none' // limit all requests to https only, allows inline scripts in html, but blocks js's `eval()`, and blocks this site from being inside an iframe from a foreign origin
  X-Frame-Options: SAMEORIGIN // prevents iframes from foreign origins from making a request to this server (NOTE: superseded by content security policy’s frame-ancestors, but good for older browsers)
  (if using cookies:) Set-Cookie: <key>=<value>; max-age=<seconds>; Secure; HttpOnly; SameSite=Lax // Use `Path=/<your_path>` if a reverse proxy is used to prevent the browser from sending the proxied application's cookie to other paths!; SameSite=Lax` prevents cookies to be sent to cross-site requests (but allows cookies to be sent if user was navigated from other origin); add `Domain=<this_comain>; ` for access to the cookie to all of domain's subdomains; Secure for HTTPS only; HttpOnly for deactivating access to Document.cookie via JS
  Access-Control-Allow-Origin: https://a-foreign-website.org // allow the given domain(s) to access that currently requested resource
*/

// TODO: only request from env, if no dataDir was given - prevents unnecessary `--allow-env`
//let dataDir = (Deno.env.get("HOME") || ".") + "/.config/deno-srv/"; // TODO: (macos), windows

// export function setDataDir(newDataDir: string)
// {
//   dataDir = newDataDir;
// }

// let acmeEmail: string | undefined = undefined;

// export function setAcmeEmail(newAcmeEmail: string)
// {
//   acmeEmail = newAcmeEmail;
// }

// export class TlsStore
// {
//   public servername: string; // for sni
//   public cert: string;
//   public key: string;

//   constructor(servername: string, cert: string, key: string)
//   {
//     this.servername = servername;
//     this.cert = cert;
//     this.key = key;
//   }
// }

// export class TlsManager
// {
//   domainName: string;
//   store: TlsStore | null = null;

//   // ... auto acme stuff here
//   constructor(domainName: string)
//   {
//     this.domainName = domainName;
//   }

//   private async fileExists(filename: string)
//   {
//     return (await Deno.stat(`${dataDir}/${filename}`)).isFile;
//   }

//   private async readFile(filename: string)
//   {
//     return (await Deno.readTextFile(`${dataDir}/${filename}`));
//   }

//   async waitForStore()
//   {
//     try
//     {
//       await Deno.mkdir(dataDir+"/", { recursive: true });
//     }
//     catch(_e){}

//     // first check if there is a (valid) cert available in the dataDir
//     try
//     {
//       const domainCertificate = await this.readFile(this.domainName + ".crt");
//       const domainPrivateKey = await this.readFile(this.domainName + ".pem");

//       this.store = new TlsStore(domainCertificate, domainPrivateKey);
//       tlsStores[this.domainName] = this.store;
//       return this.store;
//     }
//     catch(_e)
//     {
//       //console.debug("no cert for domain " + this.domainName + " - getting new cert");
//       throw new Error("NOT DOING THIS RN!");
//     }

//     let accountPublicKey;
//     let accountPrivateKey;

//     try
//     {
//       accountPublicKey = await this.readFile("acc.pub.pem");
//       accountPrivateKey = await this.readFile("acc.prv.pem");
//     }
//     catch(_e)
//     {
//       //console.debug("no account keys");
//     }

//     const { domainCertificate, pemAccountKeys } = // TODO: user editable directory url
//       await acme.getCertificateForDomain(this.domainName, "https://acme-staging-v02.api.letsencrypt.org/directory", //"https://acme-v02.api.letsencrypt.org/directory",
//       acmeEmail,
//       ( (accountPublicKey && accountPrivateKey) ? { pemPublicKey: accountPublicKey, pemPrivateKey: accountPrivateKey } : undefined )
//       );

//     if (!domainCertificate)
//     {
//       // TODO: try again later!
//       const x = "failed to get cert for domain " + this.domainName + "!";
//       console.error(x);
//       throw new Error(x);
//     }

//     if (!accountPublicKey && !accountPrivateKey)
//     {
//       await Deno.writeTextFile(`${dataDir}/acc.pub.pem`, pemAccountKeys.pemPublicKey);
//       await Deno.writeTextFile(`${dataDir}/acc.prv.pem`, pemAccountKeys.pemPrivateKey);
//     }

//     this.store = new TlsStore(domainCertificate.pemCertificate, domainCertificate.pemPrivateKey);
//     tlsStores[this.domainName] = this.store;
//     return this.store;
//   }
// }

// const tlsStores: Record<string, TlsStore> = {};

type HandlerFunction = (
  request: Request,
) => Promise<Response | null> | Response | null;

export abstract class ListenerBase {
  protected run: boolean;
  protected listener: Deno.Listener;
  protected handlers: (Handler | HandlerFunction)[];
  public static hijackers: Record<string, acme.HttpRequestQueue> = {};
  protected isTls: boolean = false;

  constructor(
    listener: Deno.Listener,
    handlers?: (Handler | HandlerFunction)[],
    isTls?: boolean,
  ) {
    this.run = true;
    this.listener = listener;
    this.handlers = handlers ?? [];
    this.isTls = !!isTls;
    this.acceptLoop();
  }

  close(): void {
    this.run = false;
    this.listener.close();
  }

  async accept(conn: Deno.Conn) {
    // console.debug("new connection", conn, conn.remoteAddr);

    try {
      //const con = await this.listener.accept();
      const requests = Deno.serveHttp(conn);
      for await (const { request, respondWith } of requests) {
        try {
          // console.debug("new request from connection", request);

          if (request.url.length >= 1024) {
            console.error("Request url length >= 1024");
            respondWith(getDefaultResponseFunction(414)(request)).catch(() =>
              null
            );
            continue;
          }

          let responded: boolean = false;
          if (!this.isTls && Object.keys(ListenerBase.hijackers).length) { // auto tls needs to hijack all http connections to answer acme http requests for validation
            // console.debug("hijackers");

            for (
              const [key, queue] of Object.entries<acme.HttpRequestQueue>(
                ListenerBase.hijackers,
              )
            ) {
              // console.debug("hijacker", key);

              if (queue.stopped) {
                delete ListenerBase.hijackers[key];
                // console.debug("hijacker deleted", key);
                continue;
              }

              const response = await new Promise<Response | null>(
                (resolver) => {
                  queue.push({ request, resolver });
                },
              );

              // console.debug("request response!", key, response);

              if (response) {
                for (const header in defaultResponseHeaders) {
                  if (!response.headers.has(header)) { // only add default response headers if they were not set by a handler already, effectively overwriting them
                    //response.headers.set(header, defaultResponseHeaders[header]);
                  }
                }
                respondWith(response).catch(() => {});
                responded = true;
                break;
              }
            }
          }

          if (responded) {
            continue;
          }

          let requestHandeled = false;
          for (const handler of this.handlers) {
            let response: Response | Promise<Response | null> | null;
            if (typeof handler === "function") {
              const _handler = handler as HandlerFunction;
              response = _handler(request);
            } else {
              const _handler = handler as Handler;
              response = _handler.newRequest(request);
            }

            if (response instanceof Promise) {
              response = await response;
            } else {
              if (response !== null) {
                console.warn(
                  "WARNING: Handler was not async and blocked the execution!",
                  response,
                );
              }
            }

            if (response === null) {
              continue; // try next handler
            }

            for (const header in defaultResponseHeaders) {
              if (!response.headers.has(header)) { // only add default response headers if they were not set by a handler already, effectively overwriting them
                //response.headers.set(header, defaultResponseHeaders[header]);
              }
            }

            respondWith(response).catch(() => null); //.catch((reason) => { console.log("Couldn't respond to request:", reason.message) });
            requestHandeled = true;
            break;
          }

          if (!requestHandeled) {
            console.error("no handler found for request");
            respondWith(getDefaultResponseFunction(400)(request)).catch(() =>
              null
            ); //.catch((reason) => { console.log("Couldn't respond to request with a 400 response:", reason) });;
          }
        } catch (e) {
          console.error("connection error", e);
          respondWith(getDefaultResponseFunction(500)(request)).catch(() =>
            null
          ); // TODO: how to "respond"?
        }
      }
    } catch (e) {
      console.log("failed to serve request:", e.message);
    }
  }

  async acceptLoop() {
    while (this.run) {
      this.accept(await this.listener.accept()); // async
    }
  }

  addHandler(handler: Handler | HandlerFunction) {
    this.handlers.push(handler);
  }
}

export class HttpListener extends ListenerBase // TODO: refactor!
{
  // private static httpListeners : Record<string, HttpListener> = {};

  constructor(
    options?: {
      ip?: string;
      port?: number;
      handlers?: (Handler | HandlerFunction)[];
    },
  ) {
    const _ip = options?.ip ?? "0.0.0.0";
    const _port = options?.port ?? 80;

    const listener = Deno.listen({ hostname: _ip, port: _port }); // TODO: Deno.serve
    console.log(`listening on ${_ip}:${_port} (http)`);

    super(listener, options?.handlers, false);
    // HttpListener.httpListeners[_ip+":"+_port] = this;
  }

  close(): void {
    super.close();
  }
}

export class Handler {
  protected handlers: (Handler | HandlerFunction)[];
  protected checkSubHandlers = true;
  protected excludeUrlPath?: string;
  protected cutExcludePath = false;

  constructor(handlers?: (Handler | HandlerFunction)[]) {
    this.handlers = handlers || [];
  }

  addHandler(handler: Handler | HandlerFunction, prepend?: boolean) // adds a sub handler!
  {
    if (handler instanceof Handler && this.excludeUrlPath) {
      handler.addExcludeUrlPath(this.excludeUrlPath, this.cutExcludePath);
    }

    if (prepend) {
      this.handlers.unshift(handler);
    } else {
      this.handlers.push(handler);
    }
  }

  setCutExcludePath(cutExcludePath: boolean): Handler {
    for (const subhandler of this.handlers) { // NOTE: recursive
      if (subhandler instanceof Handler) {
        subhandler.setCutExcludePath(cutExcludePath);
      }
    }

    return this;
  }

  protected fixPath(path: string | null): string | null {
    if (!path) {
      return null;
    }

    return this.fixPath2(path);
  }

  protected fixPath2(path: string): string {
    let _path = path;
    if (!_path.startsWith("/")) {
      _path = "/" + _path;
    }
    // if (!_path.endsWith("/"))
    //   _path += "/";

    _path = _path.replaceAll("//", "/");

    //console.debug("fixPath: b4", path, "after", _path);
    return _path;
  }

  addExcludeUrlPath(urlPath: string | null, cutExcludePath: boolean): Handler {
    const path = this.fixPath(
      this.excludeUrlPath || "" + this.fixPath(urlPath),
    );

    if (path) {
      this.excludeUrlPath = path;
    }
    this.cutExcludePath = cutExcludePath;

    // tell all subhandlers to cut, too
    // TODO: how to tell the handlerFunction?? do we need to edit Request's url? .. which is readonly

    for (const subhandler of this.handlers) { // NOTE: recursive
      if (subhandler instanceof Handler) {
        subhandler.addExcludeUrlPath(path, cutExcludePath);
      }
    }

    return this;
  }

  handleRequest(request: Request): Promise<Response | null> | Response | null {
    // console.debug("Handler: handleRequest");

    if (!this.excludeUrlPath) {
      // console.debug("Handler: handleRequest: empty handler, checking subhandlers...");
      return this.checkSubhandlers(request);
    }

    // path excluded (or cut)
    const url = new URL(request.url);
    if (
      !url.pathname.startsWith(
        this
          .excludeUrlPath, /* FIXME: this, but ctor guarantees that this var is set */
      )
    ) {
      // console.debug(`Handler: path '${url.pathname}' does not start with '${this.excludeUrlPath}' - skip`);
      return null; // so the next handler can be called, because the path does not match!
    }

    // path starts with requested path:
    // console.debug(`Handler: path '${url.pathname}' starts with '${this.excludeUrlPath}' - checking subhandlers...`);
    return this.checkSubhandlers(request);
  }

  async checkSubhandlers(request: Request): Promise<Response | null> {
    //console.debug("Handler: checkSubhandlers: asking subhandlers");
    for (const handler of this.handlers) {
      let res;

      if (handler instanceof Handler) {
        res = handler.handleRequest(request);
      } else {
        res = (handler as HandlerFunction)(request);
      }

      if (!res) {
        continue;
      }

      if (res instanceof Promise) {
        res = await res;
        if (res) {
          return res;
        }
      } else {
        return res; // not a promise, but also not null => so a Response!
      }
    }

    //console.debug("Handler: checkSubhandlers: no subhandler matched...");
    return null;
  }

  newRequest(request: Request): Promise<Response | null> | Response | null {
    //console.debug("Handler: newRequest", new URL(request.url).hostname);

    const res1 = this.handleRequest(request);

    if (res1) {
      return res1;
    }

    if (!this.checkSubHandlers) {
      //console.debug("Handler: newRequest: own handler did not match, but NOT checking subhandlers!");
      return null;
    }

    //console.debug("Handler: newRequest: own handler did not match, checking subhandlers...");
    return this.checkSubhandlers(request);
  }
}

export interface Tls {
  cert: string;
  key: string;
}

// @ts-ignore api not ready yet, use private symbol
const { resolverSymbol } = Deno[Deno.internal];

const hostHandlers: HostHandler[] = [];

Deno.cron("check certs", "0 1 * * *", // every day at 1am
  () =>
{
  console.log(`check certs cron`);
  hostHandlers.forEach((hostHandler) => hostHandler.requestCert());
});

export class HostHandler extends Handler {
  #hostname: string;
  #tls?: Tls;

  get hostname(): string {
    return this.#hostname;
  }
  get tls() {
    return this.#tls;
  }

  constructor(
    hostname: string,
    options?: { tls?: Tls; handlers?: (Handler | HandlerFunction)[] },
  ) // if keys undefined, gets cert itself
  {
    super(options?.handlers);
    this.checkSubHandlers = false;

    this.#hostname = hostname;
    this.#tls = options?.tls;

    if (!options?.tls) { // no cert given - request cert by using deno-acme
      this.requestCert();
    }

    hostHandlers.push(this);
  }

  private reschedule(currentTry: number) {
    const timeouts = [60, 10 * 60, 100 * 60, 86400]; // see https://letsencrypt.org/docs/integration-guide/#retrying-failures
    const timeout = (currentTry >= timeouts.length)
      ? timeouts[timeouts.length - 1]
      : timeouts[currentTry];
    setTimeout(() => this.requestCert(currentTry), timeout * 1000); // try again in n seconds
    console.log(
      "trying again in",
      timeout,
      "seconds (retry #",
      currentTry,
      ")",
    );
  }

  /*private*/ async requestCert(currentTry?: number) {
    console.debug("requestCert", currentTry === undefined ? "first try" : "try #" + currentTry);

    // load cert
    try {
      const cert = await Deno.readTextFile(
        `./.deno-srv/certs/${this.#hostname}.crt`,
      );
      const key = await Deno.readTextFile(
        `./.deno-srv/certs/${this.#hostname}.prv.pem`,
      );

      // check if cert is valid for long enough
      const x509 = new X509();

      // get first (main) cert from cert chain
      const certList = cert.split("-----END CERTIFICATE-----").map(certPart => certPart + "-----END CERTIFICATE-----");
      if (certList.length < 1)
      {
        console.error("requestCert: unable to find certificate end marker...");
        throw new Error("unable to find certificate end marker...");
      }
      const mainCert = certList[0];

      x509.readCertPEM(mainCert);
      const notAfter = zulutodate(x509.getNotAfter()).getTime();
      console.log("notAfter", notAfter);

      const now = (new Date()).getTime();
      console.log("now     ", now);

      if (now + 259200000 /* 3 days */ > notAfter)
      {
        console.debug(`Certificate for '${this.#hostname}' is too old, requesting new certificate.`);
        throw new Error(`Certificate for '${this.#hostname}' is too old, requesting new certificate.`);
      }
      else
      {
        console.debug(`cert for '${this.#hostname}' is valid for long enough`);
      }

      this.#tls = { cert, key };
      // console.debug("cert already available - loading from file - done!");
      return;
    } catch (_e) {
      // console.debug("cert doesn't exist - requesting!");
    }

    // load account
    let accountPublicKey: string | null = null;
    let accountPrivateKey: string | null = null;
    try {
      // TODO: one account per acme directory
      accountPublicKey = await Deno.readTextFile(
        `./.deno-srv/accountPublicKey.pem`,
      );
      accountPrivateKey = await Deno.readTextFile(
        `./.deno-srv/accountPrivateKey.pem`,
      );

      // console.debug("acme account already available - loading from file - done!");
    } catch (_e) {
      // console.debug("acme account not available - creating a new one");
    }

    // TODO: wait until listener is ready
    // TODO: check if cert is fresh enough
    // TODO: create HttpListener on 0.0.0.0:80 if there isn't

    const hijackerQueue = acme.createHttpRequestQueue();
    ListenerBase.hijackers[this.#hostname] = hijackerQueue;

    try {
      const result = await acme.getCertificateWithHttp(this.#hostname, {
        // acmeDirectoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory", // TODO: !
        // TODO: all other options!
        httpRequestQueue: hijackerQueue,
        ...((accountPublicKey && accountPrivateKey)
          ? {
            pemAccountKeys: {
              publicKeyPEM: accountPublicKey,
              privateKeyPEM: accountPrivateKey,
            },
          }
          : {}),
      });

      // save account
      if (
        result.pemAccountKeys.publicKeyPEM &&
        result.pemAccountKeys.privateKeyPEM
      ) {
        try {
          await Deno.stat(`./.deno-srv/`);
        } catch (_e) {
          console.debug("./.deno-srv/ doesn't exist - creating dir");
          await Deno.mkdir(`./.deno-srv/`, { recursive: true }); // uncaught
        }

        // TODO: one account per acme directory
        await Deno.writeTextFile(
          `./.deno-srv/accountPublicKey.pem`,
          result.pemAccountKeys.publicKeyPEM,
        ); // uncaught
        await Deno.writeTextFile(
          `./.deno-srv/accountPrivateKey.pem`,
          result.pemAccountKeys.privateKeyPEM,
        ); // uncaught
      }

      if (
        !result.domainCertificate.pemCertificate ||
        !result.domainCertificate.pemPrivateKey
      ) {
        throw new Error(
          `Failed to request certificate for '${this.#hostname}'`,
        );
      }

      // save cert
      const cert = result.domainCertificate.pemCertificate;
      const key = result.domainCertificate.pemPrivateKey;

      try {
        await Deno.stat(`./.deno-srv/certs/`);
      } catch (_e) {
        // console.debug("./.deno-srv/certs/ doesn't exist - creating dir");
        await Deno.mkdir(`./.deno-srv/certs/`, { recursive: true }); // uncaught
      }

      await Deno.writeTextFile(`./.deno-srv/certs/${this.#hostname}.crt`, cert); // uncaught
      await Deno.writeTextFile(
        `./.deno-srv/certs/${this.#hostname}.prv.pem`,
        key,
      ); // uncaught

      this.#tls = { cert, key }; // TODO: re-create listener for the tls cache to use new cert ?
      // console.debug("DONE!!! tls ready!!! :)")
    } catch (e) {
      console.error(
        `HostHandler: requesting cert for host '${this.#hostname}' failed! ${
          Deno.inspect(e)
        }`,
      );
      this.reschedule(currentTry != undefined ? currentTry++ : 0);
    } finally {
      delete ListenerBase.hijackers[this.#hostname];
      // console.debug("deleted hijacker", this.#hostname);
    }
  }

  handleRequest(request: Request): Promise<Response | null> | Response | null {
    // console.debug("HostHandler: handleRequest");

    const hostHeader = request.headers.get("host")?.trim() ?? "";
    const hostHeader2 = hostHeader.match(/^[^:]*/)?.[0] ?? hostHeader;

    if (hostHeader2 !== this.#hostname) {
      // console.debug("HostHandler: handleRequest: handler '" + this.#hostname + "' doesn't match '" + hostHeader2 + "'");
      return null; // so the next handler can be called, because the host does not match!
    }

    // console.debug("HostHandler: handleRequest: hostname match! checking subhandlers now");
    return this.checkSubhandlers(request);
  }
}

export class HttpsListener extends ListenerBase {
  private hosts: Record<string, HostHandler> = {};

  public addHostHandler(hostHandler: HostHandler): void {
    this.hosts[hostHandler.hostname.toLowerCase()] = hostHandler;
    this.handlers.push(hostHandler);
  }

  constructor(
    options?: {
      ip?: string;
      port?: number;
      hostHandlers?: HostHandler[];
      autoRedirectHttps?: boolean;
    },
  ) {
    const _ip = options?.ip ?? "0.0.0.0";
    const _port = options?.port ?? 443;

    const tempOpts: unknown = {
      hostname: _ip,
      port: _port,
      // @ts-ignore api not ready yet, use private symbol
      [resolverSymbol]: (sni: string) => {
        const host = this.hosts[sni];
        // console.log("host?", host?.hostname);
        return host.tls!;
      },
    };

    // TODO: correctly handle non-sni connections
    const listener = Deno.listenTls(
      <Deno.ListenTlsOptions & Deno.TlsCertifiedKeyConnectTls> tempOpts,
    );
    console.log(`listening on ${_ip}:${_port} (https)`);

    super(listener, options?.hostHandlers, true);
    options?.hostHandlers?.forEach((hostHandler) =>
      this.hosts[hostHandler.hostname] = hostHandler
    );

    if (options?.autoRedirectHttps) {
      new HttpListener( // TODO: stop this listener on stop(), too
        {
          ip: _ip,
          handlers: [
            new HttpsRedirectHandler(),
          ],
        },
      );
    }
  }
}

// export class ListenerManager
// {
//   private listeners: Record<string, Listener>;

//   constructor()
//   {
//     this.listeners = {};
//   }

//   contains(ip: string, port: number): boolean
//   {
//     const key = `${ip}:${port}`;
//     return this.containsKey(key);
//   }

//   containsKey(key: string): boolean
//   {
//     return (key in this.listeners);
//   }

//   addHandler(ip: string, port: number, handler: Handler, tlsStore?: TlsStore)
//   {
//     const key = `${ip}:${port}`;
//     if (!(key in this.listeners))
//       this.listeners[key] = new Listener(ip, port, { tlsStore });

//     this.listeners[key].addHandler(handler);
//   }
// }

// const listenerManager = new ListenerManager();

export class CheckHostnameHandler extends Handler {
  private hostnames: string[];

  constructor(hostname: string | string[], options?: { handlers?: Handler[] }) {
    super(options?.handlers);
    this.hostnames = Array.isArray(hostname) ? hostname : [hostname];
    this.checkSubHandlers = false; // !! aka. negate - cancel, instead of checking subhandlers if they might match
  }

  handleRequest(request: Request): Promise<Response | null> | Response | null {
    // console.debug("CheckHostnameHandler: handleRequest");

    const url = new URL(request.url);
    if (!this.hostnames.includes(url.hostname)) {
      // console.debug(`CheckHostnameHandler: handleRequest: hostname '${url.hostname}' does not match required hostname '${this.hostname}' - skipping`);
      return null; // so the next handler can be called, because the path does not match!
    }

    // console.debug("CheckHostnameHandler: match! checking subhandlers now");
    return this.checkSubhandlers(request);
  }
}

export class CheckPathHandler extends Handler {
  constructor(
    path: string,
    options?: {
      cutExcludePath?: boolean;
      handlerFunction?: HandlerFunction;
      handlers?: (Handler | HandlerFunction)[];
    },
  ) {
    super(options?.handlers);
    this.checkSubHandlers = false; // !!

    this.addExcludeUrlPath(path, options?.cutExcludePath || false); // FIXME: also cuts this handler's path... is this critical?
  }
}

export class FileHandler extends Handler {
  private fsBasePath: string;
  private compression: boolean; // use whatever compression is best for particular file

  constructor(
    path: string,
    options?: {
      compression?: boolean;
      handlers?: (Handler | HandlerFunction)[];
    },
  ) {
    super(options?.handlers);
    this.fsBasePath = resolve(path);
    //console.debug("FileHandler: fsBasePath", this.fsBasePath);

    if (!Deno.statSync(this.fsBasePath).isDirectory) {
      throw new Error("FileHandler: path `" + path + "` is not a directory!");
    }

    this.compression = options?.compression || false /* default */;
    this.checkSubHandlers = false; // always either responds or fails
    //console.debug("FileHandler: path", path);
  }

  private response(request: Request) {
    if (this.handlers.length < 1) {
      //console.debug("FileHandler: handleRequest: no subhandlers - directly returning 404");
      return getDefaultResponseFunction(404)(request);
    }

    return null; // redirect to parent's subhandler(s)!
  }

  private processRange(
    request: Request,
    file: Deno.FsFile,
    size: number,
  ): { newReadable: ReadableStream; newFileSize: number } /* throws! */ {
    const rangeHeader = request.headers.get("range");

    if (!rangeHeader) {
      //console.debug("FileHandler: processRange: no range header set");
      return { newReadable: file.readable, newFileSize: size };
    }

    if (rangeHeader.includes(",")) {
      throw new Error("multiple ranges not implemented");
    }

    const params = rangeHeader.split("=");

    if (params.length != 2) {
      throw new Error("params.length != 2");
    }

    if (params[0] !== "bytes") {
      throw new Error("unit != bytes");
    }

    const range = params[1].split("-"); // either 'n-n' => start & end; 'n' => start only; '-n' => last

    // if (range.length != 2)
    //   throw new Error("range.length != 2");

    const rangeStart = range[0] ? parseInt(range[0]) : undefined;
    const rangeEnd = range[1] ? parseInt(range[1]) : undefined;

    if (rangeStart === undefined && rangeEnd === undefined) {
      throw new Error("one of rangeStart or rangeEnd needed");
    }

    if (
      rangeStart !== undefined && rangeEnd !== undefined &&
      rangeStart >= rangeEnd
    ) {
      throw new Error("rangeStart >= rangeEnd");
    }

    if (rangeStart !== undefined && rangeStart > size) {
      throw new Error("rangeStart > file size");
    }

    if (rangeEnd !== undefined && rangeEnd > size) {
      throw new Error("rangeEnd > file size");
    }

    let newFileSize;
    let newReadable = file.readable;

    //console.debug("FileHandler: processRange: rangeStart", rangeStart, "rangeEnd", rangeEnd);

    if (rangeStart !== undefined && rangeEnd === undefined) {
      file.seek(rangeStart, Deno.SeekMode.Start);
      newFileSize = size - rangeStart;
    } else if (rangeStart === undefined && rangeEnd !== undefined) { // MDN: <suffix-length> (last n bytes of file requested)
      file.seek(-rangeEnd, Deno.SeekMode.End);
      newFileSize = rangeEnd; // last n bytes
    } else if (rangeStart !== undefined && rangeEnd !== undefined) {
      file.seek(rangeStart, Deno.SeekMode.Start);

      class SkipBytesTransformStream
        extends TransformStream<Uint8Array, Uint8Array> {
        private end: number; // end of wanted bytes
        private current: number; // current chunk position in readable

        constructor(start: number, end: number) {
          super(
            {
              transform: (chunk, controller) => {
                const chunkStart = this.current;
                const chunkSize = chunk.byteLength;
                const chunkEnd = this.current + chunkSize;

                // console.debug("SkipBytesTransformStream: chunk:", "end", this.end, "chunkEnd", chunkEnd, "chunkSize", chunkSize);
                if (this.end > chunkEnd) { // more data available than the chunk holds - enqueue the whole chunk
                  // console.debug("SkipBytesTransformStream: enqueuing WHOLE chunk");
                  controller.enqueue(chunk);
                  this.current += chunkSize;
                  return;
                } // TODO: don't branch on more likely condition for performance reasons - check how V8 handles this

                // console.debug("SkipBytesTransformStream: enqueuing chunk partly:", (this.end - chunkStart), chunk);
                controller.enqueue(chunk.subarray(0, this.end - chunkStart));
                controller.terminate();
              },
            },
          );

          this.current = start;
          this.end = end;
        }
      }

      newFileSize = rangeEnd - rangeStart;
      newReadable = file.readable.pipeThrough(
        new SkipBytesTransformStream(rangeStart, rangeEnd),
      );
      // console.debug("FileHandler: processRange: piping to SkipBytesTransformStream");
    } else {
      console.error("Something went wrong!");
      throw new Error("Something went wrong!");
    }

    return { newReadable, newFileSize };
  }

  private async openFile(filepath: string) {
    const stat = await Deno.stat(filepath);
    if (!stat.isFile) {
      //console.debug("FileHandler: handleRequest: error opening requested file: not a file");
      //return this.response(request);
      throw new Error("openFile: error opening requested file: not a file");
    }

    if (!(await Deno.realPath(filepath)).startsWith(this.fsBasePath)) {
      throw new Error(`[!!!] openFile: requested filepath (${filepath}) doesn't start with fsBasePath (${this.fsBasePath})`);
    }

    //console.debug("FileHandler: handleRequest: stat.mtime", stat.mtime, "stat.mtime?.toUTCString()", stat.mtime?.toUTCString() || "???");

    const file = await Deno.open(filepath, { read: true });

    return { stat, file };
  }

  async handleRequest(request: Request): Promise<Response | null> {
    //console.debug("FileHandler: handleRequest", this.excludeUrlPath, this.cutExcludePath, request);

    //console.debug("FileHandler: handleRequest: request.url", request.url);

    const url = new URL(request.url); // eliminates bad paths like '..'
    //console.debug("FileHandler: handleRequest: url", url);

    const path = (this.excludeUrlPath && this.cutExcludePath)
      ? url.pathname.replace(this.excludeUrlPath, "")
      : url.pathname;
    //console.debug("FileHandler: handleRequest: path", path);

    // TODO: sanitize url and path !!!

    const fileUrl = `file://${this.fsBasePath}${path}`;
    //console.debug("FileHandler: handleRequest: fileUrl", fileUrl);
    let filepath = fromFileUrl(fileUrl); //getPath(path);//`${this.fsBasePath}/${path}`;
    //console.debug("FileHandler: handleRequest: filepath", filepath);

    let res;

    try {
      res = await this.openFile(filepath);
    } catch (_e) {
      if (!filepath.endsWith("/")) {
        //console.debug("FileHandler: handleRequest: error opening requested file:", _e);
        return this.response(request);
      }

      try {
        filepath = filepath + "index.html";
        res = await this.openFile(filepath);
      } catch (_e2) {
        //console.debug("FileHandler: handleRequest: error opening requested file after trying with 'index.html':", _e2);
        return this.response(request);
      }
    }

    const { stat, file } = res;

    let fileSize: number | null = stat.size;
    let readable: ReadableStream<Uint8Array> | ArrayBuffer = file.readable;
    let isPartial = false;

    try {
      const { newReadable, newFileSize } = this.processRange(
        request,
        file,
        stat.size,
      );

      if (newReadable !== readable || newFileSize !== fileSize) {
        isPartial = true;
        //console.debug("FileHandler: handleRequest: `Range` header was set and accepted", newReadable);
      }

      fileSize = newFileSize;
      readable = newReadable;
    } catch (e) {
      console.log("FileHandler: handleRequest: processRange failed", e);
      return new Response(null, { status: 416 });
    }

    // compression stuff:
    // TODO: how to handle etag?
    // TODO: don't compress if content-encoding / content-range is set
    // TODO: how to handle cache?

    // get content-type of file
    const fileExt = extname(filepath); //filepath.split("/" /* TODO: windows */).pop()?.split(".").slice(1).join("."); // NOTE: allows for multi extensino files like (.tar.gz)
    //console.debug("FileHandler: handleRequest: fileExt", fileExt);

    const hasExt = fileExt && (fileExt.length > 0);
    const defaultContentType = "application/octet-stream";
    const contentType: string = hasExt
      ? typeByExtension(fileExt) ?? defaultContentType
      : defaultContentType;

    //const x = hasExt ? typeByExtension(fileExt) : "default";
    // console.debug("FileHandler: handleRequest: contentType", contentType);

    // check if file is compressible
    const compressible = (contentType in db)
      ? db[contentType]?.compressible === true
      : false; // TODO: fix [] access
    //console.debug("FileHandler: handleRequest: compressible", compressible);

    function isBrotliCompressible(contentType: string) {
      return [
        "text/plain",
        "text/html",
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/json",
        "application/xml",
      ].includes(contentType);
    }

    // TODO: use Deno's / hyper's compression logic and constraints? check if the speedup is significant or even there
    let encoding: string | null = null;

    //this.compression = false;
    if (
      this.compression !== false && contentType && compressible &&
      fileSize > 5 * 1024 /* only compress files to be worthy by size (5kb) */
    ) {
      //console.log("???", request.headers);
      const encodings = request.headers.get("accept-encoding")?.toLowerCase();
      if (encodings) {
        if (
          (encodings.includes("br") || encodings.includes("*")) &&
          isBrotliCompressible(contentType) && fileSize <= 65536
        ) { // let's not load more than 65536 bytes directly into js memory
          // NOTE: brotli lib doesn't provide streams
          //const buf = new Uint8Array(fileSize);
          const reader = readable.getReader();

          let runaway = 500;
          let buf: Uint8Array | null = null;
          while (runaway-- > 0) {
            const _read = await reader.read();
            if (!_read.done && _read.value) {
              if (!buf) {
                buf = _read.value;
              }

              const newBuf: Uint8Array = new Uint8Array(
                buf.length + _read.value.length,
              );
              newBuf.set(buf, 0);
              newBuf.set(_read.value, buf.length);
              buf = newBuf;
            }
          }

          if (buf) {
            const compressed = brotli.compress(buf);
            readable = compressed;
            encoding = "br";
            fileSize = compressed.byteLength;
            //console.debug("FileHandler: handleRequest: encoding: br", encodings.includes("br"), encodings.includes("*"), isBrotliCompressible(contentType), (stat.size < 5 * 1024 * 1024));
          } // TODO: handle else ... ?
        } else if ((encodings.includes("gzip") || encodings.includes("*"))) {
          const cs = new CompressionStream("gzip");
          readable.pipeTo(cs.writable); // TODO: necessary to close file manually?
          readable = cs.readable;
          encoding = "gzip";
          fileSize = null; // unknown when compressing & streaming
          //console.debug("FileHandler: handleRequest: encoding: gzip", encodings.includes("gzip"), encodings.includes("*"));
        } else {
          //console.debug("FileHandler: handleRequest: client requested unsupported encoding(s):", encodings);
        }

        //console.debug("FileHandler: handleRequest: encoding was set to", encoding);
      } else {
        //console.debug("FileHandler: handleRequest: client doesn't want its answer to be compressed");
      }
    } else {
      //console.debug("FileHandler: handleRequest: not compressing, because one of these is false:", this.compression, compressible, (stat.size > 5 * 1024));
    }

    //console.debug("FileHandler: handleRequest: encoding", encoding);
    //console.log("#########", stat.ino);

    /* TODO: if `content-encoding` is not set, Deno's webserver (using the hyper crate) will attempt to compress the body itself
    PR with Response.noCompress and op_http_write_headers with noCompress */
    const resp = new Response(readable, {
      status: isPartial ? 206 : 200,
      headers: {
        ...(fileSize ? { "content-length": "" + fileSize } : {}),
        "content-type": contentType,
        ...(encoding ? { "content-encoding": encoding } : {}),
        ...(stat.mtime ? { "last-modified": stat.mtime.toUTCString() } : {}),
        "accept-ranges": "bytes",
      },
    });

    //console.debug("FileHandler: handleRequest: response", res);

    return resp;
  }
}

export function isHtmlAccepted(r: Request): boolean {
  const acceptHeader = r.headers.get("accept");
  const isHtmlAccepted = acceptHeader?.includes("*/*") ||
    acceptHeader?.split(",").includes("text/html") || false;
  return isHtmlAccepted;
}

function getDefaultResponseFunction(statusNumber: number) {
  return defaultResponseFunctions[statusNumber] ||
    function (r: Request) {
      const htmlAccepted = isHtmlAccepted(r);

      return new Response(
        htmlAccepted ? "<h1>" + statusNumber + ".</h1>" : null,
        {
          status: statusNumber,
          //...((html) ? { headers: { "content-type": "text/html" } } : {})
          headers: {
            ...(htmlAccepted ? { "content-type": "text/html" } : {}),
            ...defaultResponseHeaders,
          },
        },
      );
    };
}

export class ReverseProxyHandler extends Handler {
  private connectTo: string;
  private a503Response: (r: Request) => Response;
  private addHeaders?: Record<string, string>;

  constructor(
    connectTo: string,
    options?: {
      addHeaders?: Record<string, string>;
      a503Response?: (r: Request) => Response;
      excludeUrlPath?: string;
      cutExcludePath?: boolean;
    },
  ) {
    super();
    this.connectTo = connectTo;
    this.checkSubHandlers = false; // always either responds or fails
    this.a503Response = options?.a503Response ||
      getDefaultResponseFunction(503); //defaultResponseFunctions[503] || function (_r: Request) { return new Response("503", { status: 503 }) };
    this.addHeaders = options?.addHeaders;

    this.excludeUrlPath = options?.excludeUrlPath;
    this.cutExcludePath = options?.cutExcludePath || false;

    //console.debug("ReverseProxyHandler", connectTo);
  }

  async handleRequest(request: Request): Promise<Response | null> // TODO: websockets
  {
    // console.debug("ReverseProxyHandler", request);

    const r = request;

    const headers: Record<string, string> = {};
    r.headers.forEach((val, key) => {
      if (["authorization"/*, "host"*/].includes(key)) { // do not forward some headers
        return;
      }
      headers[key] = val;
    });

    const url = new URL(request.url);

    // console.debug("ReverseProxyHandler: headers", request.headers);

    let isWs = false;
    const connectionHeader = r.headers.get("connection");
    if (
      connectionHeader?.toLowerCase() === "upgrade" &&
      r.headers.get("upgrade")?.toLowerCase() === "websocket"
    ) {
      console.log("IS WS!");
      isWs = true;
    }

    let resp;
    try
    {
      const pathname =
        (this.excludeUrlPath && this.cutExcludePath &&
            url.pathname.startsWith(this.excludeUrlPath))
          ? url.pathname.replace(this.excludeUrlPath, "") /* TODO: not cool */
          : url.pathname;
      const targetUrl = new URL(pathname + url.search, this.connectTo);

      //headers["host"] = targetUrl.host;

      console.debug("pathname", pathname, "targetUrl", targetUrl.toString());

      if (isWs)
      {
        const { socket, response } = Deno.upgradeWebSocket(r);

        const _queue: Blob[] = [];
        const queue = (data: Blob) =>
          {
            _queue.push(data);

            if (socket.readyState !== WebSocket.OPEN)
            {
              return;
            }

            _queue.forEach((value) => socket.send(value));
          };

        try
        {
          const proxyTargetWs = await new Promise<WebSocket>((resolve, reject) =>
          {
            console.log("websocket reverse proxy", targetUrl.toString());
            const proxyTargetWs = new WebSocket(targetUrl.toString()); // TODO: prots?; X-Forwarded-*
            proxyTargetWs.addEventListener("open", () => resolve(proxyTargetWs));
            proxyTargetWs.addEventListener("error", (err) => reject(err));
            proxyTargetWs.addEventListener("message", (e) => { console.log("T MSG!", socket.readyState, WebSocket.OPEN, e.data); queue(e.data); });
          });

          socket.addEventListener("open", () => { console.log("S OPEN!"); _queue.forEach((value) => socket.send(value)); });

          // proxyTargetWs.addEventListener("message", (e) => { console.log("T MSG", socket.readyState, WebSocket.OPEN, e.data); if (socket.readyState === WebSocket.OPEN) socket.send(e.data); });
          socket.addEventListener("message", (e) => { console.log("S MSG", proxyTargetWs.readyState); if (proxyTargetWs.readyState === WebSocket.OPEN) proxyTargetWs.send(e.data); });

          proxyTargetWs.addEventListener("close", (e) => { console.log("T CLOSE: code", e.code); socket.close(e.code, e.reason); });
          socket.addEventListener("close", (e) => { console.log("S CLOSE: code", e.code); proxyTargetWs.close(1000, e.reason); });

          console.debug("ReverseProxyHandler: ws response", response);

          return response;
        }
        catch(e)
        {
          console.error("ReverseProxyHandler: failed to upgrade websocket", e);
          return new Response(null, { status: 503 });
        }
      }

      console.log("ReverseProxyHandler: targetUrl", targetUrl.toString(), "url.hostname", url.hostname, "headers", headers);

      resp = await fetch(targetUrl.toString(), // TODO: timeout + 504 response
        {
          method: r.method,
          headers: {
            // TODO: ? "X-Forwarded-For": ...,
            "X-Forwarded-Host": url.hostname,
            "X-Forwarded-Proto": url.protocol, //targetUrl.protocol,
            ...headers,
            ...this.addHeaders,
          },
          body: r.body,
          // keepalive: keepAlive,
        },
      );
    }
    catch (e)
    {
      console.error("ReverseProxyHandler: fetch failed:", e);
      return this.a503Response(request);
    }

    const respHeaders: Record<string, string> = {};
    resp.headers.forEach((val, key) => {
      respHeaders[key] = val;
    });

    console.debug("ReverseProxyHandler: response", resp, "respHeaders", respHeaders);

    // return new Response(resp.body,
    // {
    //   status: resp.status,
    //   headers: respHeaders,
    // });

    return resp;
  }
}

export class RequestLoggerHandler extends Handler
{
  private outputFn: (request: Request) => void | Promise<void>;
  protected toTextFn: (request: Request) => string;

  constructor(
    output?: "stdout" | "stderr" | { filename: string } | {
      (r: Request): void;
    },
  )
  {
    super();
    //this.output = output || "stdout";
    //console.debug("RequestLoggerHandler");

    this.toTextFn = (r: Request) => {
      const headers: Record<string, string> = {};
      r.headers.forEach((value: string, key: string) => headers[key] = value);
      return JSON.stringify(
        {
          "method": r.method,
          "url": r.url,
          "headers": headers,
          // TODO; remote_ip (last octet masked!)
        },
      );
    };

    if (!output || output === "stdout") {
      this.outputFn = (request: Request) =>
        console.log("request", this.toTextFn(request));
      return;
    }

    if (output === "stderr") {
      this.outputFn = (request: Request) =>
        console.error("request", this.toTextFn(request));
      return;
    }

    if ("filename" in output) { // TODO: do it the right way ;)
      this.outputFn = (request: Request) =>
        Deno.writeTextFile(output.filename, `${this.toTextFn(request)}\r\n`, {
          append: true,
        }); // async!
      return;
    }

    if (typeof output === "function") {
      this.outputFn = output;
      return;
    }

    throw new Error("RequestLoggerHandler: unknown output:", output);
  }

  handleRequest(request: Request): null {
    // const ret =
    this.outputFn(request); // maybe it's better to have this unhandeled as this is quite a critical error
    // if (ret instanceof Promise)
    // {
    //   ret.catch((reason) => ...);
    // }
    return null;
  }
}

export class JournaldRequestLoggerHandler extends RequestLoggerHandler {
  private socket: Deno.UnixConn | null;

  constructor() {
    // if (!Deno.args.includes("--unstable"))
    // {
    //   console.error("")
    // }

    // super(this.fn);  TODO: do this somehow
    super((r: Request) => this.log(r));

    this.socket = null;
    // TODO: Deno is missing a Deno.connectDatagram function x_x
    //Deno.connect({ transport: "unix", path: "/run/systemd/journal/socket" } as Deno.UnixConnectOptions).then((socket) => { this.socket = socket; });
  }

  log(r: Request): void {
    if (!this.socket) {
      console.error(
        "JournaldRequestLoggerHandler: log: journald socket not ready yet!",
      ); // TODO: rate limit message
      // TODO: put into buffer
      return;
    }

    this.socket.write(
      new TextEncoder().encode(
        "MESSAGE=" + this.toTextFn(r).replaceAll("\n", "\\n") + "\n",
      ),
    ); // TODO: use '(non-aligned) little-endian unsigned 64-bit integer encoding the size of the value' for multiline / binary message value
  }
}

export class BasicAuthHandler extends Handler {
  private username: string;
  private password?: Uint8Array; // sha256 encoded
  private realm: string;

  constructor(
    username: string,
    password: { raw: string } | { sha256Hex: string },
    realm: string,
    options?: { handlers?: Handler[] },
  ) {
    if ("raw" in password && "sha256Hex" in password) {
      throw new Error(
        "BasicAuthHandler: you need to set at least and at most one of password.raw or password.sha256Hex!",
      );
    }

    super(options?.handlers);

    if ("raw" in password && password.raw) {
      const enc = new TextEncoder().encode(password.raw);
      crypto.subtle.digest("SHA-256", enc).then((arrayBuffer) =>
        this.password = new Uint8Array(arrayBuffer)
      ); // TODO: ctor + async = :(
    } else if ("sha256Hex" in password && password.sha256Hex) {
      this.password = decodeHex(password.sha256Hex);
    } else {
      throw new Error(
        "BasicAuthHandler: you need to set at least and at most one of password.raw or password.base64!",
      );
    }

    //console.debug("BasicAuthHandler");
    this.checkSubHandlers = true; // DO (!) check subhandlers

    this.username = username;
    this.realm = realm;
  }

  async isAuthorized(req: Request): Promise<boolean> {
    const authHeader = req.headers.get("Authorization");
    const basicStr = "Basic ";

    if (!authHeader || !authHeader.startsWith(basicStr)) {
      return false;
    }

    const encodedCredentials = authHeader.substring(basicStr.length);
    const decodedCredentials = new TextDecoder().decode(
      decodeBase64(encodedCredentials),
    );

    const [username, password] = decodedCredentials.split(":");

    const pwEnc = new TextEncoder().encode(password);
    const pwSha256 = new Uint8Array(
      await crypto.subtle.digest("SHA-256", pwEnc),
    ); // encoded => sha256

    // console.log("username", username, "vs", this.username, "- password (sha256)", encodeHex(pwSha256), "vs", encodeHex(this.password || ""), "?", !!this.password);
    //console.debug("BasicAuthHandler:", username, password, this.username, this.password);

    function arraysEqual(arr1: Uint8Array, arr2: Uint8Array) {
      if (arr1.length !== arr2.length) {
        return false;
      }
      for (let i = 0; i < arr1.length; i++) {
        if (arr1[i] !== arr2[i]) {
          return false;
        }
      }
      return true;
    }

    if (
      username === this.username && this.password &&
      arraysEqual(pwSha256, this.password)
    ) {
      // console.debug("authorized!");
      return true;
    }

    // console.debug("not authorized!");
    return false;
  }

  async handleRequest(request: Request): Promise<Response | null> {
    if (!await this.isAuthorized(request)) {
      //console.debug("unauthorized");
      const r = getDefaultResponseFunction(401)(request);
      r.headers.set("www-authenticate", `Basic realm="${this.realm}"`);
      return r;
    }

    //console.debug("authorized! - checking subhandlers");
    return null;
  }
}

export class HttpsRedirectHandler extends Handler {
  constructor() {
    super();
    this.checkSubHandlers = false;
  }

  handleRequest(request: Request): Response | null {
    const url = new URL(request.url);
    url.protocol = "https";
    url.port = "443";

    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/gi;
    if (ipv4Regex.test(url.hostname) || url.hostname.includes(":")) {
      console.log("HttpsRedirectHandler: not redirecting ip address hostname to https", url.hostname);
      return null;
    }

    // console.debug("redir to", url.toString());

    return new Response(null, {
      status: 301,
      headers: {
        "location": url.toString(),
      },
    });
  }
}

export class RedirectHandler extends Handler {
  private destination: string | ((request: Request) => string);
  private matchesPath: string | null;
  private redirStatus: number;
  private keepOriginalPath: boolean;

  constructor(
    destination: string | ((request: Request) => string),
    options?: {
      matchesPath?: string;
      redirStatus?: number;
      keepOriginalPath: boolean;
    },
  ) {
    super();
    //console.debug("RedirectHandler");
    //this.checkSubHandlers = false; //

    if (typeof destination === "function" && options?.keepOriginalPath) {
      throw new Error(
        "RedirectHandler: don't use a destination function and keepOriginalPath together",
      );
    }

    this.destination = destination;
    this.matchesPath = options?.matchesPath || null;
    this.redirStatus = options?.redirStatus || 302;
    this.keepOriginalPath = options?.keepOriginalPath || false;
  }

  handleRequest(request: Request): Response | null {
    const url = new URL(request.url);
    if (this.matchesPath && url.pathname !== this.matchesPath) {
      return null; // path doesn't match - continue
    }

    return new Response(null, {
      status: this.redirStatus,
      headers: {
        "location": (typeof (this.destination) === "function"
          ? this.destination(request)
          : this.destination + (this.keepOriginalPath ? url.pathname : "")),
      },
    });
  }
}

export class ForbiddenHandler extends Handler {
  private paths: string[];

  constructor(paths: string[], options?: { handlers?: Handler[] }) {
    super(options?.handlers);
    //console.debug("ForbiddenHandler");
    //this.checkSubHandlers = false; //

    this.paths = paths;
  }

  handleRequest(request: Request): Response | null {
    const url = new URL(request.url);

    for (const path of this.paths) {
      if (url.pathname.startsWith(path)) {
        return getDefaultResponseFunction(403)(request);
      }
    }

    //if (this.paths.includes(url.pathname)) // TODO: wildcard matching
    //return getDefaultResponseFunction(403)(request);

    return null;
  }
}

export const defaultResponseFunctions: Record<
  number,
  (r: Request) => Response
> = {};

export const defaultResponseHeaders: Record<string, string> = {
  "server": "deno-srv",
};

export function serveFiles(
  path: string,
  options?: {
    hostname?: string;
    ip?: string;
    port?: number;
    cutUrlPath?: string;
    the404handlerFunction?: HandlerFunction;
  },
) {
  const mainHandler = new Handler();
  let lastHandler = mainHandler;

  if (options?.hostname) {
    lastHandler = new CheckHostnameHandler(options.hostname);
    mainHandler.addHandler(lastHandler);
  }

  if (options?.cutUrlPath) {
    lastHandler = new CheckPathHandler(options?.cutUrlPath, {
      cutExcludePath: true,
    });
    mainHandler.addHandler(lastHandler);
  }

  lastHandler.addHandler(new FileHandler(path));

  // append a 404 handler function, as last handler, for not-found files
  mainHandler.addHandler(
    options?.the404handlerFunction || getDefaultResponseFunction(404),
  );

  new HttpListener({
    ip: options?.ip || "127.0.0.1",
    port: options?.port || 6453,
    handlers: [mainHandler],
  });

  // if (!options?.tlsStore &&
  //   options?.hostname?.includes(".") &&
  //   !options?.hostname.endsWith(".local"))
  // {
  //   console.log("Using TlsManager! Waiting for acme...");
  //   const tlsManager = new TlsManager(options?.hostname);
  //   tlsManager.waitForStore().then((tlsStore: TlsStore) =>
  //   {
  //     console.log("TlsManager done! Starting listener");
  //     start(tlsStore);
  //   });
  // }
  // else
  //   start(options?.tlsStore);

  // function start(tlsStore?: TlsStore)
  // {
  //   console.log("starting listener");
  //   listenerManager.addHandler(options?.ip || "0.0.0.0", options?.port || 80 /*443*/, mainHandler, tlsStore);
  // }
}
