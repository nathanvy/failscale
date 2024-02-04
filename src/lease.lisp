(in-package #:failscale/server)

;;;; Simple IPv4 / CIDR allocator

(defun ipv4-to-u32 (s)
  (destructuring-bind (a b c d)
      (mapcar #'parse-integer (uiop:split-string s :separator '(#\.)))
    (+ (ash a 24) (ash b 16) (ash c 8) d)))

(defun u32-to-ipv4 (u)
  (format nil "~D.~D.~D.~D"
          (ldb (byte 8 24) u)
          (ldb (byte 8 16) u)
          (ldb (byte 8 8)  u)
          (ldb (byte 8 0)  u)))

(defun parse-cidr (cidr)
  (destructuring-bind (ip pfx)
      (uiop:split-string cidr :separator '(#\/))
    (let* ((n (ipv4-to-u32 ip))
           (bits (parse-integer pfx))
           (mask (ldb (byte 32 0) (ash #xFFFFFFFF (- 32 bits))))
           (net (logand n mask))
           (size (expt 2 (- 32 bits))))
      (values net size))))

(defun next-free-ipv4 (cidr)
  "Return dotted-quad (no /32) for next free host in CIDR, or NIL if full."
  (multiple-value-bind (net size) (parse-cidr cidr)
    (let ((used (make-hash-table :test #'eql)))
      ;; mark used IPs from current nodes
      (bordeaux-threads:with-lock-held (*state-lock*)
        (maphash
         (lambda (_ n)
           (declare (ignore _))
           (let ((addr (node-addr-v4 n)))
             (when addr
               (let* ((ip-str (car (uiop:split-string addr :separator '(#\/))))
                      (u32    (ignore-errors (ipv4-to-u32 ip-str))))
                 (when u32
                   (setf (gethash u32 used) t))))))
         *nodes*))
      ;; choose a sane host range: skip network (.0) and broadcast (last),
      ;; prefer to skip .1 (often gateway), but handle tiny subnets gracefully
      (let* ((host-min 2)                 ; skip .0 and .1
             (preferred-start 10)
             (start (min (max host-min preferred-start) (1- size)))
             (end   (1- size)))          ; exclude broadcast
        (loop for i from start below end
              for candidate = (+ net i)
              unless (gethash candidate used)
                do (return (u32-to-ipv4 candidate))
              finally (return nil))))))


(defun ensure-lease (reg-hex)
  (or (and (gethash reg-hex *nodes*) (node-addr-v4 (gethash reg-hex *nodes*)))
      (let ((ip (next-free-ipv4 (cfg :cidr-v4))))
        (unless ip
          (error "No free addresses in ~A" (cfg :cidr-v4)))
        (let* ((n (or (gethash reg-hex *nodes*)
                      (setf (gethash reg-hex *nodes*) (make-node :reg-pub-hex reg-hex))))
               (addr (format nil "~A/32" ip)))
          (bt:with-lock-held (*state-lock*)
            (setf (node-addr-v4 n) addr))
          (persist-leases)
          addr))))
