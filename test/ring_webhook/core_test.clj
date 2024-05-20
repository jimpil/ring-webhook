(ns ring-webhook.core-test
  (:require [clojure.test :refer :all]
            [ring-webhook.core :refer :all]
            [clojure.java.io :as io]
            [clojure.data.json :as json]))

(deftest middleware-tests
  (testing "`wrap-with-signature-verification` requires `wrap-raw-body`"
    (let [handler    (constantly ::ok)
          middleware (comp
                      (wrap-raw-body (constantly true))
                      (wrap-with-signature-verification
                       {:secret  "super-secret"
                        :sig-key "x-signature"
                        :sig-fn  #(subs % 7)}))
          wrapped-handler (middleware handler)
          payload    "{\"foo\":\"some-message\"}"]

      (testing "Signature matching"
        (->> {:body    (io/input-stream (.getBytes payload))
              :headers {"x-signature" "sha256=a9d1efced768c3a2369c4005e437e2d5966350db4a443cb185f41c8d549353fa"}}
             (wrapped-handler)
             (= ::ok)
             is))

      (testing "Signature not matching"
        (->> {:body    (io/input-stream (.getBytes payload))
              :headers {"x-signature" "sha256=b9d1efced768c3a2369c4005e437e2d5966350db4a443cb185f41c8d549353fa"}}
             (wrapped-handler)
             (= wrong-signature-resp)
             is))

      (testing "Signature missing"
        (->> {:body    (io/input-stream (.getBytes payload))}
             (wrapped-handler)
             (= wrong-signature-resp)
             is)))))

(deftest jwt-signing-tests
  (let [->jws (-> (comp (memfn ^String getBytes)
                        json/write-str)
                  (jws-producer :hs256 "Key-Must-Be-at-least-32-bytes-in-length!"))]
    (is
     (->> {:admin true}
          ->jws
          :signature
          (= "oRvT0gzL1pGPzXUJDDfuS5ViCXu12CEoe6MykK1fkMc")))))
