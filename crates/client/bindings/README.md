# Generated JS/TS bindings

This directory is the **output target** for the WebAssembly bindings of the
`client` crate. It is populated by `wasm-pack`, not committed by hand:

```bash
# from the repository root
wasm-pack build crates/client --target web --out-dir bindings
```

That produces, in this directory:

- `client_bg.wasm` — the compiled WebAssembly module
- `client.js` — the JS loader / glue
- `client.d.ts` — TypeScript type declarations for the exported API
- `package.json` — an npm package manifest (`@snail-mail/client`)

`--target web` emits an ES module for the browser web client; use
`--target nodejs` (or `bundler`) for the Node/desktop consumers. The exported API
is defined in [`../bind.rs`](../bind.rs): `EmailAddress`, `ParsedMessage`,
`composeMessage`, `buildSmtpScript`, and `clientInfo`.

Generated artifacts are not checked in; run the command above as part of building
the SDK / clients.
