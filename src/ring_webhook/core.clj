(ns ring-webhook.core
  (:require [clojure.java.io :as io])
  (:import  [java.io InputStream]
            [java.util HexFormat]
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

(defn- hmac-fn
  [^String algo ^bytes secret]
  (let [skey     (SecretKeySpec. secret algo) ;; thread-safe object
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
