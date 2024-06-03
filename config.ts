#!/usr/bin/env -S deno run -A --watch

/*
  This is an example / test config to test deno-srv with.
  There are multiple tests to choose from.
  Example: Start test #3: `./config.ts 3`
*/

import * as srv from "./srv.ts";


if (!Deno.args.includes("debug"))
  console.debug = ()=>{};


srv.defaultResponseHeaders["server"] = "deno-srv test";


// creates a tls listener using Deno's brand new (currently unofficial) sni callback
const cert = Deno.readTextFileSync("test/localhost.crt");
const key = Deno.readTextFileSync("test/localhost.pem");

new srv.HostListener("127.0.0.1", 8008,
{
  hosts:
  [
    new srv.Host("localhost",
    {
      tls: { cert, key },
      handlers:
      [
        new srv.FileHandler("test/"),
      ]
    }),
  ]
});

console.log("ready");



// TODO: reactivate tests

// const tests =
// [
//   // () =>
//   // {
//   //   new srv.Listener("0.0.0.0", 80,
//   // },

//   () => // 0
//   {
//     srv.serveFiles(".");
//   },

//   () => // 1
//   {
//     srv.serveFiles(".", { hostname: "localhost" });
//   },

//   () => // 2
//   {
//     srv.serveFiles(".", { cutUrlPath: "/test123" });
//   },

//   () => // 3
//   {
//     srv.serveFiles(".", { hostname: "localhost", cutUrlPath: "/test123" });
//   },

//   () => // 4
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.FileHandler("."),
//         ]
//       }
//     );
//   },

//   () => // 5
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.RequestLoggerHandler(),
//           new srv.FileHandler("."),
//         ]
//       }
//     );
//   },

//   () => // 6
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.RequestLoggerHandler({ filename: "./requests.log" }),
//           new srv.FileHandler("."),
//         ]
//       }
//     );
//   },

//   () => // 7
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.FileHandler("."),
//           (request: Request) => { return new Response(request.method + " 404", { status: 404 }) },
//         ]
//       }
//     );
//   },

//   () => // 8
//   {
//     new srv.Listener("0.0.0.0", 80,
//     {
//       handlers:
//       [
//         new srv.CheckHostnameHandler("localhost",
//         {
//           handlers:
//           [
//             new srv.CheckPathHandler("/test123",
//             {
//               cutExcludePath: true,
//               handlers:
//               [
//                 new srv.FileHandler("."),
//               ],
//             }),

//             new srv.CheckPathHandler("/test1234",
//             {
//               cutExcludePath: true,
//               handlers:
//               [
//                 new srv.FileHandler("."),
//               ],
//             }),
//           ]
//         }),

//         (request: Request) => { if (new URL(request.url).pathname === "/test.html") return new Response("hello"); return null; },
//         (request: Request) => { console.log("last handler!"); return new Response(request.method + " 404", { status: 404 }); },
//       ]
//     }
//     );
//   },

//   () => // 9
//   {
//     srv.serveFiles(".", { hostname: "acme-test-2.wille.io" });
//   },

//   () => // 10
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.ReverseProxyHandler("https://wille.io/"),
//         ]
//       }
//     );
//   },

//   () => // 11
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.RedirectHandler("https://wille.io"),
//         ]
//       }
//     );
//   },

//   () => // 12 (same behaviour as next example)
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.RedirectHandler("https://wille.io", { keepOriginalPath: true }),
//         ]
//       }
//     );
//   },

//   () => // 13 (same behaviour as previous example)
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.RedirectHandler((r: Request) => `https://wille.io${new URL(r.url).pathname}`),
//         ]
//       }
//     );
//   },

//   () => // 14
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.BasicAuthHandler("test", "test", "test",
//           {
//             handlers:
//             [
//               new srv.FileHandler("."),
//             ]
//           }),
//         ],
//       }
//     );
//   },

//   () => // 15
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.ForbiddenHandler(["/README.md", "/.vscode/"],
//           {
//             handlers:
//             [
//               new srv.FileHandler("."),
//             ]
//           }),
//         ],
//       }
//     );
//   },

//   () => // 16 (invalid path given)
//   {
//     new srv.Listener("0.0.0.0", 80,
//       {
//         handlers:
//         [
//           new srv.FileHandler("invalid"),
//         ],
//       }
//     );
//   },
// ]


// const testId = parseInt(Deno.args.at(0)||"0");
// if (testId >= tests.length)
// {
//   console.error("select a test, as parameter, from 0 to " + (tests.length - 1));
//   Deno.exit(1);
// }
// else
// {
//   console.info("test #", testId);
//   tests[testId]();
// }

// console.info("ready");