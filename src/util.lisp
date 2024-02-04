(in-package #:failscale/server)

(defun dir-of (pathname)
  "Return the directory component of PATHNAME"
  (uiop:pathname-directory-pathname (truename pathname)))

(defun now-rfc3339 ()
  (local-time:format-rfc3339-timestring nil (local-time:now) :timezone local-time:+utc-zone+))

(defun parse-rfc3339 (s)
  (handler-case
      (local-time:parse-rfc3339-timestring s)
    (error () nil)))

(defun seconds-between (t2 t1)
  (when (and t1 t2)
    (abs (- (local-time:timestamp-to-unix t2)
            (local-time:timestamp-to-unix t1)))))

(defun utf8-to-octets (s)
  (sb-ext:string-to-octets s :external-format :utf-8))

(defun octets-to-utf8 (octs)
  (sb-ext:octets-to-string octs :external-format :utf-8))

(defun hex-to-octets (hex)
  (ironclad:hex-string-to-byte-array (string-downcase hex)))

(defun octets-to-hex (octs)
  (string-downcase (ironclad:byte-array-to-hex-string octs)))

(defun b64-to-octets (s)
  (cl-base64:base64-string-to-usb8-array s))

(defun octets-to-b64 (octs)
  (string-downcase (cl-base64:usb8-array-to-base64-string octs)))

(defun sha256-hex (octs)
  (octets-to-hex (ironclad:digest-sequence :sha256 octs)))

(defun getenv* (name &optional default)
  (or (uiop:getenv name) default))

(defun ensure-directory (path)
  (uiop:ensure-all-directories-exist (list path)))

(defun ingest-file-bytes (path)
  (with-open-file (in-file path :element-type '(unsigned-byte 8))
    (let* ((len (file-length in-file))
           (buf (make-array len :element-type '(unsigned-byte 8))))
      (read-sequence buf in-file)
      buf)))

(defun split-file-bytes (path octs)
  (with-open-file (out-file path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
    (write-sequence octs out-file)))

(defun write-json-file (path obj)
  (with-open-file (out-file path :direction :output :if-exists :supersede :if-does-not-exist :create)
    (shasht:write-json* obj :stream out-file :indent-string nil)))

(defun read-json-file (path)
  (when (probe-file path)
    (with-open-file (in-file path)
      (shasht:read-json in-file))))
