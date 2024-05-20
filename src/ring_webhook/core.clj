(ns ring-webhook.core
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io InputStream]
           [java.nio.charset StandardCharsets]
           [java.util Base64 HexFormat]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(defn- with-raw
  [uri-pred {:keys [uri ^InputStream body content-length headers]
             :as req}]
  (if (uri-pred uri)
    (with-open [in body]
      (let [raw (if-some [n (or content-length
                                (some-> (get headers "content-length")
                                        parse-long))]
                  (.readNBytes in n)
                  (.readAllBytes in))]
        (assoc req
               :body-raw raw
               :body (io/input-stream raw))))
    req))

(defn hmac-fn
  [^String algo secret]
  (let [^bytes secret-bs (if (string? secret)
                           (.getBytes ^String secret StandardCharsets/UTF_8)
                           secret)
        skey     (SecretKeySpec. secret-bs algo) ;; thread-safe object
        ^Mac mac (-> algo
                     (Mac/getInstance)
                     (doto (.init skey)))]
    (fn ^bytes [^bytes data]
      (let [^Mac mac (.clone mac)] ;; non thread-safe object needs cloning!
        (.doFinal mac data)))))

(defn- signature-ok?
  [{:keys [^bytes body-raw headers]} sign eq? sig-fn k ^HexFormat hex-format]
  (some-> (get headers k)
          (sig-fn)
          (eq? (->> (sign body-raw)
                    (.formatHex hex-format)))))

(def wrong-signature-resp
  {:status  403
   :body    "Signature either wrong, or missing!"
   :headers {"Content-Type" "text/plain"}})

; ------------------------------PUBLIC API--------------------------------------------------------

(defn wrap-raw-body
  "Given a uri (per ring `:uri` key) predicate (e.g. a set), 
   returns middleware which conditionally enhances the request 
   with a new key (:body-raw). Useful for webhook endpoints that
   need to sign/verify the payload in order to verify its authenticity.
   Must be called fairly early in the middleware chain (if not first)."
  [uri-pred]
  (fn [handler]
    (fn
      ([req respond raise] (handler (with-raw uri-pred req) respond raise))
      ([req]               (handler (with-raw uri-pred req))))))

(defn wrap-with-signature-verification
  "Given at least a `:secret` (bytes/String) & `sig-key` (header to look for the provided signature),
   returns middleware that will perform payload signature verification before calling the handler.
   Must be called after `wrap-raw-body`, in order to get access to the `:body-raw` key. 
   Options may include: 
   - :mac-algo - the Mac algorithm to use (defaults to 'HmacSHA256')
   - :secret   - a string or byte-array/sequence to use as the SecretKeySpec when signing (mandatory) 
   - :sig-key  - the request header name where the provided signature will be located (mandatory)
   - :sig-fn   - a 1-arg fn transforming the provided signature (defaults to `identity`) 
   - :eq-fn    - a 2-arg fn to compare the provided VS calculated signatures (defaults to `=`)
   - :hex-format - a `HexFormat` instance (defaults to `(HexFormat/of)`)"
  [{:keys [mac-algo hex-format sig-key secret sig-fn eq-fn]
    :or {sig-fn     identity ;; e.g. `#(subs % 7)` for dropping a prefix like 'sha256='
         eq-fn      =
         mac-algo   "HmacSHA256"
         hex-format (HexFormat/of)}}]
  {:pre [(not-empty secret)
         (some? sig-key)]}
  (let [secret-bs (cond
                    (bytes? secret)      secret
                    (string? secret)     (.getBytes ^String secret)
                    (sequential? secret) (byte-array secret)
                    :else
                    (throw
                     (IllegalArgumentException.
                      (format "Invalid secret! Was expecting `String`, `byte[]`, or something `Sequential` - got %s instead!"
                              (type secret)))))
        sign (hmac-fn mac-algo secret-bs)]
    (fn [handler]
      (fn
        ([req]
         (if (signature-ok? req sign eq-fn sig-fn sig-key hex-format)
           (handler req)
           wrong-signature-resp))
        ([req respond raise]
         (if (signature-ok? req sign eq-fn sig-fn sig-key hex-format)
           (handler req respond raise)
           (respond wrong-signature-resp)))))))

(def ^:private algos
  {:hs256 {:jwt "HS256"
           :mac "HmacSHA256"}
   :hs384 {:jwt "HS384"
           :mac "HmacSHA384"}
   :hs512 {:jwt "HS512"
           :mac "HmacSHA512"}})

(defn- jwt->mac-algo
  [jwt-algo]
  (some
   (fn [[_ {:keys [jwt mac]}]]
     (when (= jwt-algo jwt)
       mac))
   algos))

(defn- jwt*
  [algo claims]
  {:header {:typ "JWT"
            :alg algo}
   :claims claims})

(defn jws-producer
  "Given a fn able to convert clj-data to JSON bytes, 
   an HMAC algorithm (:hs256,384,512), and a <secret> (a byte-array 
   or String whose length should be at least 256,384,512 / 8),
   returns a fn taking arbitrary <claims> (a map), converting them
   to proper JWT format, signing them, and returning the JWS data +
   the full `:token` in the metadata."
  [->json-bytes algo secret]
  {:pre [(contains? algos algo)]}
  (let [mac-algo (get-in algos [algo :mac])
        jwt-algo (get-in algos [algo :jwt])
        hmac     (hmac-fn mac-algo secret)
        encoder  (.withoutPadding (Base64/getUrlEncoder))]
    (fn sign-jwt [claims]
      (let [{:keys [header claims]
             :as jwt}  (jwt* jwt-algo claims)
            header-b64 (->> header ->json-bytes (.encodeToString encoder))
            claims-b64 (->> claims ->json-bytes (.encodeToString encoder))
            jwt-str    (str header-b64 \. claims-b64)
            signature  (->> (.getBytes jwt-str StandardCharsets/UTF_8)
                            hmac
                            (.encodeToString encoder))]
        (-> jwt
            (assoc :signature signature)
            (with-meta {:token (str jwt-str \. signature)}))))))

(defn jws-reader
  "Given a fn able to convert JSON bytes to clj-data, returns
   a function which 'reads' a JWS token (String) as a clj-map.
   The full `:token` is preserved in the metadata, alongside a
   `:verify` predicate, able to check the signature (given a secret)."
  [<-json-bytes]
  (let [encoder  (.withoutPadding (Base64/getUrlEncoder))
        decoder  (Base64/getUrlDecoder)]
    (fn [^String token]
      (let [[encoded-header encoded-claims signature] (str/split token #"\." 3)
            payload   (str encoded-header \. encoded-claims)
            header    (->> encoded-header (.decode decoder) <-json-bytes)
            claims    (->> encoded-claims (.decode decoder) <-json-bytes)
            algo      (:alg header)]
        (-> (jwt* algo claims)
            (assoc :header    header
                   :signature signature)
            (with-meta
              {:token  token
               :verify (fn [secret]
                         (when-some [hmac (some-> (jwt->mac-algo algo)
                                                  (hmac-fn secret))]
                           (->> (.getBytes payload StandardCharsets/UTF_8)
                                hmac
                                (.encodeToString encoder)
                                (= signature))))}))))))

(comment
  (require 'clojure.data.json)
  (def claims->jws
    (-> (comp (memfn ^String getBytes)
              clojure.data.json/write-str)
        (jws-producer :hs256 "Key-Must-Be-at-least-32-bytes-in-length!")))

  (def str->jws
    (jws-reader (comp #(clojure.data.json/read-str % :key-fn keyword)
                      #(String. ^bytes %))))


  (claims->jws {:admin true})
  (str->jws "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
  )
