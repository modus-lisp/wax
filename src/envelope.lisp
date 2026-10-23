;;;; envelope.lisp -- authenticated requests over a transport that authenticates nothing.
;;;;
;;;; On a transport with no peer identity of its own (TCP, a relay, HTTP), every request
;;;; carries an ENVELOPE: a NIP-01 event of kind 27235 (NIP-42's client-auth kind), signed
;;;; by the caller's key, binding:
;;;;   ["method", M]       the method being called
;;;;   ["request", ID]     the request's id
;;;;   ["payload", HASH]   sha256 hex of the request's params JSON, exactly as sent
;;;;   ["keep", PUBKEY]    the signer the request is for (stops cross-signer replay)
;;;;   ["seq", N]          the caller's sequence number, a decimal integer
;;;; The caller's identity is the envelope's pubkey -- a key, never a bearer token: seeing
;;;; an envelope on the wire gives an attacker nothing to reuse.
;;;;
;;;; NO CLOCK.  created_at is whatever the caller wrote and is ignored.  Replay is stopped
;;;; by SEQ: per caller, an envelope is accepted only if its N is greater than the last N
;;;; accepted from that caller.  The caller may count however it likes (a stored counter,
;;;; or its own clock in microseconds -- its business, not ours).  Requests from one key
;;;; are therefore accepted in sequence order; a caller that sends concurrently must
;;;; serialize or use more than one key.  The high-water marks are the only state, one
;;;; integer per known caller, and a SEQUENCE-STORE with a PATH keeps them across
;;;; restarts -- without one, a restart forgets them and old envelopes replay.
;;;; (The scheme is n_signer's caller_token_identity plan, adapted.)

(in-package #:wax)

(defconstant +envelope-kind+ 27235)

(defun %ht (&rest kv)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kv by #'cddr do (setf (gethash k h) v))
    h))

(defun make-envelope (caller-key method request-id params-json keep-pubkey-hex seq &key (created-at 0))
  "An envelope event signed by CALLER-KEY (a secret) for one request.  SEQ must exceed
every SEQ this caller has sent this signer before.  CREATED-AT is informational only."
  (check-type seq (integer 0))
  (sign-event (%ht "created_at" created-at "kind" +envelope-kind+ "content" ""
                   "tags" (vector (vector "method" method) (vector "request" request-id)
                                  (vector "payload" (%hex (natrium:sha256 (%octets params-json))))
                                  (vector "keep" keep-pubkey-hex)
                                  (vector "seq" (princ-to-string seq))))
              caller-key))

(defstruct (sequence-store (:constructor %make-sequence-store))
  path (last (make-hash-table :test 'equal)))

(defun make-sequence-store (&optional path)
  "Per-caller high-water marks.  With PATH, they are loaded from and saved to that file
(one \"PUBKEY SEQ\" line per caller), so a restart does not reopen old envelopes."
  (let ((store (%make-sequence-store :path path)))
    (when (and path (probe-file path))
      (with-open-file (in path)
        (loop for line = (read-line in nil) while line
              do (let ((sp (position #\Space line)))
                   (when sp
                     (setf (gethash (subseq line 0 sp) (sequence-store-last store))
                           (parse-integer line :start (1+ sp))))))))
    store))

(defun %save-sequences (store)
  (let* ((path (sequence-store-path store))
         (tmp (concatenate 'string (namestring path) ".tmp")))
    (with-open-file (out tmp :direction :output :if-exists :supersede)
      (maphash (lambda (k v) (format out "~a ~d~%" k v)) (sequence-store-last store))
      (finish-output out))
    (rename-file tmp path)))

(defun %parse-seq (text)
  (unless (and (stringp text) (plusp (length text)) (<= (length text) 20) (every #'digit-char-p text))
    (%fail 4009 "envelope seq is not a decimal integer"))
  (parse-integer text))

(defun %tag (event name)
  (let ((hits (remove-if-not (lambda (tag) (and (>= (length tag) 2) (equal (elt tag 0) name)))
                             (coerce (gethash "tags" event) 'list))))
    (unless (= (length hits) 1) (%fail 4002 "envelope needs exactly one ~s tag" name))
    (elt (first hits) 1)))

(defun verify-envelope (envelope method request-id params-json keep-pubkey-hex store
                        &key (known (constantly t)))
  "Check ENVELOPE (a parsed event) for this request.  Returns the caller's pubkey hex,
or signals WAX-ERROR with the reason.  KNOWN says whether a pubkey is a caller this
signer serves; state is kept only for those.  Advances the caller's mark in STORE only
once everything else holds."
  (unless (hash-table-p envelope) (%fail 4001 "envelope missing or not an object"))
  (unless (eql (gethash "kind" envelope) +envelope-kind+) (%fail 4003 "envelope kind is not 27235"))
  (unless (verify-event envelope) (%fail 4004 "envelope signature does not verify"))
  (unless (equal (%tag envelope "method") method) (%fail 4005 "envelope is for another method"))
  (unless (equal (%tag envelope "request") request-id) (%fail 4006 "envelope is for another request"))
  (unless (equal (%tag envelope "payload") (%hex (natrium:sha256 (%octets params-json))))
    (%fail 4007 "envelope payload hash does not match the params"))
  (unless (equal (%tag envelope "keep") keep-pubkey-hex) (%fail 4008 "envelope is for another signer"))
  (let* ((caller (gethash "pubkey" envelope))
         (seq (%parse-seq (%tag envelope "seq")))
         (last (gethash caller (sequence-store-last store))))
    (unless (funcall known caller) (%fail 5001 "caller ~a is not served here" caller))
    (when (and last (<= seq last)) (%fail 4010 "envelope replayed or out of sequence"))
    (setf (gethash caller (sequence-store-last store)) seq)
    (when (sequence-store-path store) (%save-sequences store))
    caller))
