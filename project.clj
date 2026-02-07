(defproject jank-nrepl-server "0.1-SNAPSHOT"
  :license {:name "MPL 2.0"
            :url "https://www.mozilla.org/en-US/MPL/2.0/"}
  :dependencies []
  :plugins [[org.jank-lang/lein-jank "0.3"]]
  :middleware [leiningen.jank/middleware]
  :jank {:include-dirs ["cpp"]
         :library-dirs ["cpp"]
         :linked-libraries []}
  :main jank-nrepl-server.main
  :profiles {:debug {:jank {:optimization-level 0}}
             :release {:jank {:optimization-level 2}}})
