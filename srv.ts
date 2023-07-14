// import * as brotli from "https://deno.land/x/brotli@0.1.7/mod.ts";


export class TlsStore
{
  public cert: string;
  public key: string;

  constructor(cert: string, key: string)
  {
    this.cert = cert;
    this.key = key;
  }
}


export class TlsManager
{
  // ... auto acme stuff here
}


type HandlerFunction = (request: Request) => Promise<Response | null> | Response | null;


export class Listener
{
  private handlers: (Handler | HandlerFunction)[];
  private listener: Deno.Listener;
  private isTls: boolean;

  constructor(ip: string, port: number, options?: { tlsStore?: TlsStore, handlers?: (Handler | HandlerFunction)[] })
  {
    const key = `${ip}:${port}`;
    if (listenerManager.containsKey(key))
      throw new Error("Listener: listener with ip + port already exists!");

    this.handlers = options?.handlers || [];
    if (options?.tlsStore)
    {
      this.listener = Deno.listenTls({ hostname: ip, port: port, cert: options?.tlsStore.cert, key: options.tlsStore.key });
      this.isTls = true;
    }
    else
    {
      this.listener = Deno.listen({ hostname: ip, port: port });
      this.isTls = false;
    }

    console.debug("new listener for", ip, port, this.isTls ? "with tls" : "no tls");

    this.acceptLoop();
  }


  acceptLoop()
  {
    this.listener.accept().then(async (conn) => 
      {
        console.debug("new connection", conn);
        const requests = Deno.serveHttp(conn);
        for await (const { request, respondWith } of requests) 
        {
          let requestHandeled = false;
          console.debug("new request", request);
          for (const handler of this.handlers)
          {
            let response;
            if (typeof(handler) === "function")
            {
              const _handler = handler as HandlerFunction;
              response = _handler(request);
            }
            else
            {
              const _handler = handler as Handler;
              response = _handler.newRequest(request);
            }

            if (response instanceof Promise)
            {
              response = await response;
            }

            if (response === null)
              continue;

            respondWith(response);
            requestHandeled = true;
            break;
          }

          if (!requestHandeled)
          {
            console.error("no handler found for request");
            // TODO: default handler?
            respondWith(new Response("400", { status: 400 }));
          }
        }

        this.acceptLoop();
      });
  }


  addHandler(handler: Handler | HandlerFunction)
  {
    this.handlers.push(handler);
  }
}


export class ListenerManager
{
  private listeners: Record<string, Listener>;


  constructor()
  {
    this.listeners = {};
  }


  contains(ip: string, port: number): boolean
  {
    const key = `${ip}:${port}`;
    return this.containsKey(key);
  }


  containsKey(key: string): boolean
  {
    return (key in this.listeners);
  }


  addHandler(ip: string, port: number, handler: Handler, tlsStore?: TlsStore)
  {
    const key = `${ip}:${port}`;
    if (!(key in this.listeners))
      this.listeners[key] = new Listener(ip, port, { tlsStore });

    this.listeners[key].addHandler(handler);
  }
}


const listenerManager = new ListenerManager();


export class Handler
{
  protected handlers: (Handler | HandlerFunction)[];
  protected checkSubHandlers = true;
  protected excludeUrlPath: string | null = null;
  protected cutExcludePath = false;


  constructor(handlers?: (Handler | HandlerFunction)[])
  {
    this.handlers = handlers || [];
  }


  addHandler(handler: Handler | HandlerFunction) // adds a sub handler!
  {
    if (handler instanceof Handler && this.excludeUrlPath)
    {
      handler.addExcludeUrlPath(this.excludeUrlPath, this.cutExcludePath);
    }

    this.handlers.push(handler);
  }


  setCutExcludePath(cutExcludePath: boolean): Handler
  {
    for (const subhandler of this.handlers) // NOTE: recursive
    {
      if (subhandler instanceof Handler)
        subhandler.setCutExcludePath(cutExcludePath);
    }

    return this;
  }


  private fixPath(path: string | null): string | null
  {
    if (!path)
      return null;

    let _path = path;
    if (!_path.startsWith("/"))
      _path = "/" + _path;
    if (!_path.endsWith("/"))
      _path += "/";

    _path = _path.replaceAll("//", "/");

    console.debug("fixPath: b4", path, "after", _path);
    return _path;
  } 


  addExcludeUrlPath(urlPath: string | null, cutExcludePath: boolean): Handler
  {
    const path = this.fixPath(this.excludeUrlPath || "" + this.fixPath(urlPath));

    this.excludeUrlPath = path;
    this.cutExcludePath = cutExcludePath;

    // tell all subhandlers to cut, too
    // TODO: how to tell the handlerFunction?? do we need to edit Request's url? .. which is readonly

    for (const subhandler of this.handlers) // NOTE: recursive
    {
      if (subhandler instanceof Handler)
        subhandler.addExcludeUrlPath(path, cutExcludePath);
    }

    return this;
  }


  handleRequest(request: Request): Promise<Response | null> | Response | null
  {
    console.debug("Handler: handleRequest");

    if (!this.excludeUrlPath)
    {
      console.debug("Handler: handleRequest: empty handler, checking subhandlers...");
      return this.checkSubhandlers(request);
    }

    // path excluded (or cut)
    const url = new URL(request.url);
    if (!url.pathname.startsWith(this.excludeUrlPath /* FIXME: this, but ctor guarantees that this var is set */))
    {
      console.debug(`Handler: path '${url.pathname}' does not start with '${this.excludeUrlPath}' - skip`);
      return null; // so the next handler can be called, because the path does not match!
    }

    // path starts with requested path:
    console.debug(`Handler: path '${url.pathname}' starts with '${this.excludeUrlPath}' - checking subhandlers...`);
    return this.checkSubhandlers(request);
  }


  async checkSubhandlers(request: Request): Promise<Response | null>
  {
    console.debug("Handler: checkSubhandlers: asking subhandlers");
    for (const handler of this.handlers)
    {
      let res;
      
      if (handler instanceof Handler)
        res = handler.handleRequest(request);
      else
        res = (handler as HandlerFunction)(request);

      if (!res)
        continue;

      if (res instanceof Promise)
      {
        res = await res;
        if (res)
          return res;
      }
      else
        return res; // not a promise, but also not null => so a Response!
    }

    console.debug("Handler: checkSubhandlers: no subhandler matched...");
    return null;
  }


  newRequest(request: Request): Promise<Response | null> | Response | null
  {
    console.debug("Handler: newRequest", new URL(request.url).hostname);

    const res1 = this.handleRequest(request);

    if (res1)
      return res1;

    if (!this.checkSubHandlers)
    {
      console.debug("Handler: newRequest: own handler did not match, but NOT checking subhandlers!");
      return null;
    }

    console.debug("Handler: newRequest: own handler did not match, checking subhandlers...");
    return this.checkSubhandlers(request);
  }
}


export class CheckHostnameHandler extends Handler
{
  private hostname: string;


  constructor(hostname: string, options?: {  handlers?: Handler[] })
  {
    super(options?.handlers);
    this.hostname = hostname;
    this.checkSubHandlers = false; // !! aka. negate - cancel, instead of checking subhandlers if they might match
  }


  handleRequest(request: Request): Promise<Response | null> | Response | null
  {
    console.debug("CheckHostnameHandler: handleRequest");

    const url = new URL(request.url);
    if (url.hostname !== this.hostname)
    {
      console.debug(`CheckHostnameHandler: handleRequest: hostname '${url.hostname}' does not match required hostname '${this.hostname}' - skipping`);
      return null; // so the next handler can be called, because the path does not match!
    }

    console.debug("CheckHostnameHandler: match! checking subhandlers now");
    return this.checkSubhandlers(request);
  }
}


export class CheckPathHandler extends Handler
{
  constructor(path: string, 
    options?: { cutExcludePath?: boolean, handlerFunction?: HandlerFunction, handlers?: Handler[] })
  {
    super(options?.handlers);
    this.checkSubHandlers = false; // !!
  
    this.addExcludeUrlPath(path, options?.cutExcludePath || false); // FIXME: also cuts this handler's path... is this critical?
  }
}


export class FileHandler extends Handler
{
  private fsBasePath: string;


  constructor(path: string)
  {
    super();
    this.fsBasePath = path;
    this.checkSubHandlers = false; // always either responds or fails
    console.debug("FileHandler for path:", path);
  }


  async handleRequest(request: Request): Promise<Response | null>
  {
    console.debug("FileHandler: handleRequest", this.excludeUrlPath, this.cutExcludePath, request);

    const url = new URL(request.url);

    const path = ((this.excludeUrlPath && this.cutExcludePath) 
      ? url.pathname.replace(this.excludeUrlPath, "") 
      : url.pathname)
        .replaceAll("..", ".") /* ugly, first sanitation */;
    console.debug("FileHandler: handleRequest: path", path);

    // TODO: sanitize url and path !!!

    try
    {
      const file = await Deno.open(`${this.fsBasePath}/${path}`, { read: true });
      return new Response(file.readable, { status: 200 });
    }
    catch(e)
    {
      console.debug("FileHandler: error opening requested file:", e);
      return null; // redirect to parent's subhandler(s)!
    }
  }
}


export function default404Response()
{
  return new Response("404", { status: 404 });
}


export function default404HandlerFunction(_request: Request)
{
  console.debug("default404HandlerFunction");
  return default404Response();
}


export function serveFiles(path: string, 
  options?: { hostname?: string, ip?: string, port?: number, cutUrlPath?: string, 
    tlsStore?: TlsStore, the404handlerFunction?: HandlerFunction })
{
  const mainHandler = new Handler(); 
  let lastHandler = mainHandler;

  if (options?.hostname)
  {
    lastHandler = new CheckHostnameHandler(options.hostname);
    mainHandler.addHandler(lastHandler);
  }

  if (options?.cutUrlPath)
  {
    lastHandler = new CheckPathHandler(options?.cutUrlPath, { cutExcludePath: true });
    mainHandler.addHandler(lastHandler);
  }

  lastHandler.addHandler(new FileHandler(path));

  // append a 404 handler function, as last handler, for not-found files
  mainHandler.addHandler(options?.the404handlerFunction || default404HandlerFunction);

  listenerManager.addHandler(options?.ip || "0.0.0.0", options?.port || 80 /*443*/, mainHandler, options?.tlsStore);
}