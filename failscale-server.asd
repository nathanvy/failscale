(asdf:defsystem "failscale-server"
  :description "Failscale Server"
  :author "Nathan Van Ymeren"
  :license "GPL3"
  :version "0.1.0"
  :serial t
  :depends-on (#:ningle #:clack #:woo #:lack #:shasht #:ironclad #:cl-base64 #:bordeaux-threads #:local-time)
  :components ((:file "src/package")
               (:file "src/util")
               (:file "src/state")
               (:file "src/lease")
               (:file "src/auth")
               (:file "src/web")
               (:file "src/main")))
