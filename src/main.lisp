(in-package #:failscale/server)

(defparameter *basedir* nil)

(defun start (&key
                (bind (or (cfg :bind) "127.0.0.1"))
                (port (or (cfg :port) 8080))
                (config-path (asdf:system-relative-pathname :failscale-server "etc/config.lisp"))
                (leases-path (asdf:system-relative-pathname :failscale-server "data/leases.json"))
                (authorized-path (asdf:system-relative-pathname :failscale-server "etc/authorized_keys")))
  (format t "~a~%" (dir-of config-path))
  (setf (gethash :config-path *config*) config-path)
  (load-config config-path)
  (setf *leases-path* leases-path)
  (load-authorized-keys authorized-path)
  (load-leases leases-path)
  (setf *app* (make-app))
  (format t "failscaled starting on ~a ~a~%" bind port)
  (setf *server* (clack:clackup *app* :server :woo :port port :address bind))
  (values))

(defun stop ()
  (when *server*
    (clack:stop *server*)
    (setf *server* nil)
    (format t "failscaled stopped~%")))
