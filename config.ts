#!/usr/bin/env -S deno run -A --watch 

import * as srv from "./srv.ts";


if (!Deno.args.includes("debug"))
  console.debug = ()=>{};


const tests = 
[
  () => 
  {
    srv.serveFiles(".");
  },

  () => 
  {
    srv.serveFiles(".", { hostname: "localhost" });
  },

  () => 
  {
    srv.serveFiles(".", { cutUrlPath: "/test123" });
  },

  () => 
  {
    srv.serveFiles(".", { hostname: "localhost", cutUrlPath: "/test123" });
  },

  () => 
  {
    new srv.Listener("0.0.0.0", 80, 
      {
        handlers:
        [
          new srv.FileHandler("."),
        ]
      }
    );
  },

  () => 
  {
    new srv.Listener("0.0.0.0", 80, 
      {
        handlers:
        [
          new srv.FileHandler("."),
          (request: Request) => { return new Response(request.method + " 404", { status: 404 }) },
        ]
      }
    );
  },

  () =>
  {
    new srv.Listener("0.0.0.0", 80, 
    {
      handlers:
      [
        new srv.CheckHostnameHandler("localhost",
        {
          handlers:
          [
            new srv.CheckPathHandler("/test123", 
            { 
              cutExcludePath: true, 
              handlers:
              [
                new srv.FileHandler("."),
              ],
            }),

            new srv.CheckPathHandler("/test1234", 
            { 
              cutExcludePath: true, 
              handlers:
              [
                new srv.FileHandler("."),
              ],
            }),
          ]
        }),
        
        (request: Request) => { if (new URL(request.url).pathname === "/test.html") return new Response("hello"); return null; },
        (request: Request) => { console.log("last handler!"); return new Response(request.method + " 404", { status: 404 }); },
      ]
    }
    );
  },
]


const testId = parseInt(Deno.args.at(0)||"0");
if (testId >= tests.length)
{
  console.error("select a test, as parameter, from 0 to " + (tests.length - 1));
  Deno.exit(1);
}
else
{
  console.info("test #", testId);
  tests[testId]();
}

console.info("ready");