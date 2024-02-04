(in-package #:failscale/server)

;;;; Request authentication (Ed25519 + timestamp + nonce window)

(defparameter *nonce-window-size* 128)
(defparameter *clock-skew-seconds* 300) ; ±5 minutes

(defun push-nonce (node nonce-hex)
  (let ((lst (remove nonce-hex (node-recent-nonces node) :test #'string=)))
    (push nonce-hex lst)
    (setf (node-recent-nonces node) (subseq lst 0 (min (length lst) *nonce-window-size*))))
  t)

(defun nonce-seen-p (node nonce-hex)
  (find nonce-hex (node-recent-nonces node) :test #'string=))

;; in src/auth.lisp (or a shared place)
(defun request-body-bytes (env)
  "Return the request body as a (simple-array (unsigned-byte 8) (*)).
   Reads :raw-body stream if necessary."
  (let* ((raw (or (getf env :raw-body)
                  (getf env :clack.request/raw-body))) ; some stacks use this
         (len-raw (getf env :content-length))
         (len (cond ((integerp len-raw) len-raw)
                    ((and len-raw (stringp len-raw))
                     (handler-case (parse-integer len-raw :junk-allowed t)
                       (error () nil)))
                    (t nil))))
    (cond
      ((typep raw '(simple-array (unsigned-byte 8) (*))) raw)
      ((streamp raw)
       (labels ((read-all (s n)
                  (if (and n (plusp n))
                      (let ((buf (make-array n :element-type '(unsigned-byte 8))))
                        (read-sequence buf s) buf)
                      (let ((chunk-size 8192)
                            (chunks '())
                            (total 0))
                        (loop
                          with chunk = (make-array chunk-size :element-type '(unsigned-byte 8))
                          for nread = (read-sequence chunk s)
                          while (> nread 0) do
                            (push (subseq chunk 0 nread) chunks)
                            (incf total nread))
                        (let ((out (make-array total :element-type '(unsigned-byte 8))))
                          (loop with i = 0
                                for ch in (nreverse chunks) do
                                  (replace out ch :start1 i)
                                  (incf i (length ch)))
                          out)))))
         (read-all raw len)))
      ((stringp raw) (utf8-to-octets raw))
      (t (utf8-to-octets "")))))

(defun header (env name)
  "Return header NAME (string, case-insensitive) from the Clack/Lack env."
  (let* ((hs   (getf env :headers))
         (want (string-downcase name)))
    (when (hash-table-p hs)
      (or
       ;; common case: keys are lowercase strings
       (gethash want hs)
       ;; less common: exact key present (mixed case or different type)
       (gethash name hs)
       ;; slow path: normalize whatever the table uses
       (block found
         (maphash (lambda (k v)
                    (let ((kk (etypecase k
                                (string (string-downcase k))
                                (symbol (string-downcase (symbol-name k))))))
                      (when (string= kk want) (return-from found v))))
                  hs)
         nil)))))

(defun method-string (env) (string-upcase (symbol-name (getf env :request-method))))
(defun path-string (env) (or (getf env :path-info) "/"))

(defun make-sign-input (env body-octs)
  (let* ((meth (method-string env)) ;; lol meth
         (path (path-string env))
         (ts (header env "x-ed25519-time"))
         (nonce (or (header env "x-ed25519-nonce") ""))
         (h (sha256-hex body-octs)))
    (values meth path ts nonce (format nil "~A~%~A~%~A~%~A~%~A~%" meth path ts nonce h))))

(define-condition auth-error (error)
  ((message :initarg :message :reader auth-error-message))
  (:report (lambda (c s) (format s "Auth error: ~A" (auth-error-message c)))))

(defun verify-request (env)
  "Return REG-PUB-HEX on success or signal AUTH-ERROR."
  (let* ((dev-bypass (eq t (cfg :dev-allow-unsigned?)))
         (key-hex (or (header env "x-ed25519-key")
                      (error 'auth-error :message "Missing X-Ed25519-Key")))
         (sig-b64 (header env "x-ed25519-sig"))
         (ts-str  (header env "x-ed25519-time"))
         (nonce   (header env "x-ed25519-nonce")))
    (unless (gethash (string-downcase key-hex) *authorized-keys*)
      (error 'auth-error :message "Key not in authorized_keys"))
    (when dev-bypass
      (return-from verify-request (string-downcase key-hex)))
    (unless (and sig-b64 ts-str nonce)
      (error 'auth-error :message "Missing signature/timestamp/nonce headers"))
    (let* ((ts (parse-rfc3339 ts-str))
           (skew (and ts (seconds-between ts (local-time:now)))) )
      (unless (and ts skew (<= skew *clock-skew-seconds*))
        (error 'auth-error :message "Timestamp outside allowed skew")))
    (let* ((body (request-body-bytes env))
           (sig (b64-to-octets sig-b64))
           (pub (hex-to-octets key-hex))
           (n (or (gethash key-hex *nodes*)
                  (setf (gethash key-hex *nodes*) (make-node :reg-pub-hex key-hex))))
           (nonce-hex (string-downcase nonce)))
      (when (nonce-seen-p n nonce-hex)
        (error 'auth-error :message "Replay detected (nonce reused)"))
      (multiple-value-bind (meth path ts hdr sign-input)
          (make-sign-input env body)
        (declare (ignore meth path ts hdr))
        (let* ((the-key (ironclad:make-public-key :ed25519 :y pub))
               (msg (utf8-to-octets sign-input)))
          (unless (ironclad:verify-signature the-key msg sig)
            (error 'auth-error :message "Invalid signature"))))
      (bt:with-lock-held (*state-lock*)
        (push-nonce n nonce-hex)
        (setf (node-last-seen n) (local-time:now)))
      (persist-leases)
      key-hex)))
