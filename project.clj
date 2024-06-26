(defproject com.github.jimpil/ring-webhook "0.1.2-SNAPSHOT"
  :description "Ring middleware/utilities for working with webhooks & JWS tokens."
  :url "https://github.com/jimpil/ring-webhook"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.11.3"]]
  :repl-options {:init-ns ring-webhook.core}
  :profiles {:dev {:dependencies [[org.clojure/data.json "2.5.0"]]}}
  :release-tasks [["vcs" "assert-committed"]
                  ["change" "version" "leiningen.release/bump-version" "release"]
                  ["vcs" "commit"]
                  ["vcs" "tag" "--no-sign"]
                  ["deploy" ]
                  ["change" "version" "leiningen.release/bump-version"]
                  ["vcs" "commit"]
                  ;["vcs" "push"]
                  ]
  :deploy-repositories [["releases" :clojars]] ;; lein release :patch
  :signing {:gpg-key "jimpil1985@gmail.com"}
  )
