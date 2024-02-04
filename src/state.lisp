(in-package #:failscale/server)

(defparameter *state-lock* (bt:make-lock "failscale-state"))

(defstruct node
  reg-pub-hex ;hex string key
  addr-v4 ;e.g. "10.13.37.12/32" or nil
  addr-v6 ;e.g. "fd85:1337:1337:1::1337/128" or whatever
  wg-pub-b64 ;string base64 X25519 pub
  endpoint ;"ip:port"
  keepalive ;int or nil
  last-seen ;local-time:timestamp
  recent-nonces ;list of hex nonces
  )

(defparameter *nodes* (make-hash-table :test #'equal))
(defparameter *authorized-keys* (make-hash-table :test #'equal))

(defparameter *config* (make-hash-table :test #'equal))
;; keys: :data-dir :authorized-path :cidr-v4 :cidr-v6 :dev-allow-unsigned?

(defun cfg (k) (gethash k *config*))

(defun load-config (path)
  (let* ((sexp (with-open-file (in path) (read in nil nil)))
         (table (make-hash-table :test #'eq)))
    (dolist (pair sexp)
      (setf (gethash (car pair) table) (cdr pair)))
    (setf *config* table)))

(defun reload-config ()
  (load-config (cfg :config-path))
  (load-authorized-keys)
  (load-leases))

(defun load-authorized-keys (path)
  (clrhash *authorized-keys*)
  (when (and path (probe-file path)))
  (with-open-file (in path)
    (loop for line = (read-line in nil nil)
          while line do
            (let* ((trimmed (string-trim '(#\Space #\Tab) line))
                   (ignored (or (zerop (length trimmed))
                                (char= (char trimmed 0) #\#))))
              (unless ignored
                (let* ((octs (cond
                               ((every (lambda (c) (or (digit-char-p c 16)
                                                       (find c "ABCDEFabcdef"))) trimmed)
                                (hex-to-octets trimmed))
                               (t (b64-to-octets trimmed))))
                       (hex (octets-to-hex octs)))
                  (setf (gethash hex *authorized-keys*) t))))))
  (hash-table-count *authorized-keys*))

(defparameter *leases-path* nil)

(defun load-leases (&optional (path (or *leases-path*
                                        (merge-pathnames #P"data/leases.json"))))
  (setf *leases-path* path)
  (ensure-directory (uiop:pathname-directory-pathname path))
  (let ((j (read-json-file path)))
    (when j
      (bt:with-lock-held (*state-lock*)
        (let ((cidr (gethash :cidr j))
              (v6 (gethash :v6_cidr j))
              (nodes (gethash :nodes j)))
          (when cidr (setf (gethash :cidr-v4 *config*) cidr))
          (when v6 (setf (gethash :cidr-v6 *config*) v6))
          (clrhash *nodes*)
          (maphash (lambda (reg hexrec)
                     (let* ((rec (coerce hexrec 'hash-table)))
                       (setf (gethash reg *nodes*)
                             (make-node :reg-pub-hex reg
                                        :addr-v4 (gethash :addr_v4 rec)
                                        :addr-v6 (gethash :addr_v6 rec)
                                        :wg-pub-b64 (gethash :wg_pub rec)
                                        :endpoint (gethash :endpoint rec)
                                        :keepalive (gethash :keepalive rec)
                                        :last-seen (let ((s (gethash :last_seen rec)))
                                                     (and s (parse-rfc3339 s)))
                                        :recent-nonces (coerce (gethash :nonce_window rec) 'list)))))
                   nodes))))))

(defun persist-leases ()
  (bt:with-lock-held (*state-lock*)
    (let ((out (make-hash-table :test #'equal)))
      (setf (gethash :cidr out) (cfg :cidr-v4))
      (setf (gethash :v6_cidr out) (cfg :cidr-v6))
      (let ((nodes (make-hash-table :test #'equal)))
        (maphash (lambda (k n)
                   (declare (ignore k))
                   (let ((rec (make-hash-table :test #'equal)))
                     (setf (gethash :addr_v4 rec) (node-addr-v4 n))
                     (setf (gethash :addr_v6 rec) (node-addr-v6 n))
                     (setf (gethash :wg_pub rec) (node-wg-pub-b64 n))
                     (setf (gethash :endpoint rec) (node-endpoint n))
                     (setf (gethash :keepalive rec) (node-keepalive n))
                     (setf (gethash :last_seen rec) (and (node-last-seen n)
                                                         (local-time:format-rfc3339-timestring nil (node-last-seen n) :timezone local-time:+utc-zone+)))
                     (setf (gethash :nonce_window rec) (coerce (node-recent-nonces n) 'vector))
                     (setf (gethash (node-reg-pub-hex n) nodes) rec)))
                 *nodes*)
        (setf (gethash :nodes out) nodes))
      (write-json-file *leases-path* out))))
