(ns ring-webhook.core-test
  (:require [clojure.test :refer :all]
            [ring-webhook.core :refer :all]
            [clojure.java.io :as io]))

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
      (is (= ::ok (wrapped-handler {:body    (io/input-stream (.getBytes payload))
                                    :headers {"x-signature" "sha256=a9d1efced768c3a2369c4005e437e2d5966350db4a443cb185f41c8d549353fa"}}))))))
