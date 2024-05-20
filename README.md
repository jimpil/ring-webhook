# ring-webhook

## What
A tiny Clojure library designed to assist with signature verification in (ring) webhook handlers.

## Where
FIXME: add clojar coords

## How

### Webhooks

#### wrap-raw-body [uri-pred]
The first thing you need is the raw bytes from the server's `InputStream`. 
In a typical Clojure ring-based api, you can find this stream under `:body`, 
however it is highly likely that it will have already been consumed (i.e. it will be empty)
by the time your endpoint middleware/handler sees it (by earlier content-negotiating/formatting/coercing middleware). 
For example, your api's clients may be sending JSON, but you're are actually receiving Clojure maps under `:body-params`.
It is important that you don't use those maps for signature-verification (e.g. by converting back to JSON)!
Instead, use this as your very first middleware, which will simply add a new key to the request map (`:body-raw`).
`uri-pred` takes the request's `:uri`, and decides whether the logic applies for it. For example, this could be
the *set* of all webhook paths.

#### wrap-with-signature-verification [opts]
With `:body-raw` available in the request-map, you're all set to do the actual signature verification.
Simply wrap your handler, with the middleware returned by this function. Options are:

- :mac-algo - the `Mac` algorithm to use (defaults to 'HmacSHA256')
- :secret   - a string or byte-array/sequence to use as the `SecretKeySpec` when signing (mandatory) 
- :sig-key  - the request header name where the provided signature will be located (mandatory)
- :sig-fn   - a 1-arg fn transforming the provided signature (defaults to `identity`) 
- :eq-fn    - a 2-arg fn to compare the provided VS calculated signatures (defaults to `=`)
- :hex-format - a `HexFormat` instance (defaults to `(HexFormat/of)`)

Returns the following (instead of calling the handler its wrapping) when signature doesn't match (or missing):

```clj
{:status  403
 :body    "Signature either wrong, or missing!"
 :headers {"Content-Type" "text/plain"}}
```
See `core_test.clj` for example usage.

### JWS tokens

#### jws-producer
Returns a function that takes arbitrary 'claims' (a map), 
and produces signed-JWT data (a map of 3 keys - :header, :claims, :signature).
In addition, the returned map's metadata will contain the full `:token`.

This function expects a `->json-bytes` fn as its first argument. 
If you have `jsonista` on your classpath, simply pass `write-value-as-bytes`,
otherwise you can always compose - e.g. `(comp (memfn ^String getBytes) clojure.data.json/write-str)`.

#### jws-reader
Not related to `java.io.Reader`, this is kind-of the opposite of `jws-producer`.
Returns a function that takes a JWS token (String), and returns it as a map, with 
some potentially useful metadata - `:token` (input arg) & `:verify` (signature 
verification predicate - takes the secret as its only arg).

## License

Copyright © 2024 Dimitrios Piliouras

This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0.

This Source Code may also be made available under the following Secondary
Licenses when the conditions for such availability set forth in the Eclipse
Public License, v. 2.0 are satisfied: GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or (at your
option) any later version, with the GNU Classpath Exception which is available
at https://www.gnu.org/software/classpath/license.html.
