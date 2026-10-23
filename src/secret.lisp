;;;; secret.lisp -- where long-lived secret bytes live.
;;;;
;;;; A SECRET is a fixed-size byte buffer in natrium's gossamer memory -- memory the
;;;; collector never moves, so a copying collection cannot leave stale copies of it in
;;;; from-space -- owned by the SECRET object and zeroed by WIPE-SECRET.  The seed and
;;;; every derived private key live in secrets, and the arithmetic on them (PBKDF2,
;;;; BIP-32 tweaks, BIP-340 signing) runs in secp256k1-fast and natrium on fixed
;;;; buffers too: no private key ever becomes a Lisp integer.
;;;;
;;;;   SBCL   static vectors, outside the moving heap.  The whole process can
;;;;          additionally be locked into RAM with (wax::lock-process-memory), mlockall.
;;;;   modus  (hosted) gossamer's secret arena: mmap'd, mlock'd, kept out of core dumps
;;;;          and wiped in a forked child.  Bare metal has no backend yet: there
;;;;          SECRET-BACKEND answers :NONE and secret operations refuse to run.
;;;;
;;;; Not covered: secret values held for an instant in registers or stack slots.  A
;;;; stack scrub is a platform-level job.

(in-package #:wax)

(define-condition wax-error (error)
  ((code :initarg :code :reader wax-error-code)
   (message :initarg :message :reader wax-error-message))
  (:report (lambda (c s) (format s "wax ~a: ~a" (wax-error-code c) (wax-error-message c)))))

(defun %fail (code fmt &rest args)
  (error 'wax-error :code code :message (apply #'format nil fmt args)))

(defun secret-backend ()
  "How secrets are held: gossamer's backend (:SBCL-STATIC, :MODUS-ARENA, or :NONE where
there is no fixed memory yet -- a caller can refuse to run there)."
  (gossamer:fixed-backend))

(defstruct (secret (:constructor %make-secret (octets)))
  octets (wiped nil))

(defun make-secret (n)
  "A zeroed N-byte secret (a pooled fixed buffer)."
  (let ((b (gossamer:acquire :octets n)))
    (gossamer:own (%make-secret b) b)))

(defun secret-length (s) (if (secret-octets s) (length (secret-octets s)) 0))
(defun secret-wiped-p (s) (secret-wiped s))

(defun wipe-secret (s)
  "Zero S and return its buffer to the pool.  Idempotent.  S is unusable afterwards
(the buffer may next hold another secret)."
  (when (and s (secret-octets s))
    (gossamer:disown s)
    (gossamer:free (secret-octets s))
    (setf (secret-octets s) nil (secret-wiped s) t))
  nil)

(defun copy-into-secret (octets &key (start 0) end)
  "A new secret holding OCTETS[START,END).  The caller wipes OCTETS if it was secret."
  (let* ((end (or end (length octets)))
         (s (make-secret (- end start))))
    (replace (secret-octets s) octets :start2 start :end2 end)
    s))

(defmacro with-secret-octets ((var secret) &body body)
  "Run BODY with VAR bound to SECRET's buffer itself (not a copy).  BODY must not
retain or copy it."
  `(let ((,var (secret-octets ,secret)))
     (when (or (secret-wiped ,secret) (null ,var)) (%fail 3001 "use of a wiped secret"))
     ,@body))

(defun lock-process-memory ()
  "Lock all current and future pages of this process into RAM (mlockall), so secrets
are never written to swap.  Returns T on success; may fail without CAP_IPC_LOCK or
under a low RLIMIT_MEMLOCK."
  #+sbcl (ignore-errors (sb-posix:mlockall (logior sb-posix:mcl-current sb-posix:mcl-future)) t)
  #-sbcl nil)
