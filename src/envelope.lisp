;;;; envelope.lisp -- authenticated requests over a transport that authenticates nothing.
;;;;
;;;; On a transport with no peer identity of its own (TCP, a relay, HTTP), every request
;;;; carries an ENVELOPE: a NIP-01 event of kind 27235 (NIP-42's client-auth kind), signed
;;;; by the caller's key, binding:
;;;;   ["method", M]       the method being called
;;;;   ["request", ID]     the request's id
;;;;   ["payload", HASH]   sha256 hex of the request's params JSON, exactly as sent
;;;;   ["keep", PUBKEY]    the signer the request is for (stops cross-signer replay)
;;;; created_at must be within SKEW seconds of the signer's clock, and an envelope id is
;;;; accepted once.  The caller's identity is the envelope's pubkey -- a key, never a
;;;; bearer token: seeing an envelope on the wire gives an attacker nothing to reuse.
;;;; (The scheme is n_signer's caller_token_identity plan, adapted.)

(in-package #:wax)

(defconstant +envelope-kind+ 27235)

(defun %ht (&rest kv)
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kv by #'cddr do (setf (gethash k h) v))
    h))

(defun %unix-now () (- (get-universal-time) 2208988800))

(defun make-envelope (caller-key method request-id params-json keep-pubkey-hex &key (now (%unix-now)))
  "An envelope event signed by CALLER-KEY (a secret) for one request."
  (sign-event (%ht "created_at" now "kind" +envelope-kind+ "content" ""
                   "tags" (vector (vector "method" method) (vector "request" request-id)
                                  (vector "payload" (%hex (natrium:sha256 (%octets params-json))))
                                  (vector "keep" keep-pubkey-hex)))
              caller-key))

(defstruct (replay-cache (:constructor make-replay-cache (&optional (size 4096))))
  size (seen (make-hash-table :test 'equal)) (order '()))

(defun %remember (cache id)
  (setf (gethash id (replay-cache-seen cache)) t)
  (push id (replay-cache-order cache))
  (when (> (hash-table-count (replay-cache-seen cache)) (replay-cache-size cache))
    (let ((oldest (car (last (replay-cache-order cache)))))
      (setf (replay-cache-order cache) (butlast (replay-cache-order cache)))
      (remhash oldest (replay-cache-seen cache)))))

(defun %tag (event name)
  (let ((hits (remove-if-not (lambda (tag) (and (>= (length tag) 2) (equal (elt tag 0) name)))
                             (coerce (gethash "tags" event) 'list))))
    (unless (= (length hits) 1) (%fail 4002 "envelope needs exactly one ~s tag" name))
    (elt (first hits) 1)))

(defun verify-envelope (envelope method request-id params-json keep-pubkey-hex cache
                        &key (skew 30) (now (%unix-now)))
  "Check ENVELOPE (a parsed event) for this request.  Returns the caller's pubkey hex,
or signals WAX-ERROR with the reason.  Records the envelope in CACHE only once valid."
  (unless (hash-table-p envelope) (%fail 4001 "envelope missing or not an object"))
  (unless (eql (gethash "kind" envelope) +envelope-kind+) (%fail 4003 "envelope kind is not 27235"))
  (unless (verify-event envelope) (%fail 4004 "envelope signature does not verify"))
  (unless (equal (%tag envelope "method") method) (%fail 4005 "envelope is for another method"))
  (unless (equal (%tag envelope "request") request-id) (%fail 4006 "envelope is for another request"))
  (unless (equal (%tag envelope "payload") (%hex (natrium:sha256 (%octets params-json))))
    (%fail 4007 "envelope payload hash does not match the params"))
  (unless (equal (%tag envelope "keep") keep-pubkey-hex) (%fail 4008 "envelope is for another signer"))
  (let ((ts (gethash "created_at" envelope)))
    (unless (and (integerp ts) (<= (abs (- now ts)) skew)) (%fail 4009 "envelope is stale or from the future")))
  (when (gethash (gethash "id" envelope) (replay-cache-seen cache)) (%fail 4010 "envelope replayed"))
  (%remember cache (gethash "id" envelope))
  (gethash "pubkey" envelope))
