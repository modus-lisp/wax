;;;; bip32.lisp -- BIP-32 private derivation from a seed, into secrets.
;;;;
;;;; Only what a signer needs: the master key from a seed and CKD-priv down a path,
;;;; hardened or not (NIP-06 uses m/44'/1237'/<account>'/0/0, whose last two steps are
;;;; unhardened).  No xpub export: callers get public keys, never chain codes.
;;;; HMAC-SHA512 is natrium's; point multiplication is secp256k1-fast's constant-time
;;;; ct-mul-g.

(in-package #:wax)

(defconstant +hardened+ #x80000000)

(defun parse-path (path)
  "\"m/44'/1237'/0'/0/0\" -> (list of child indices, hardened ones with the high bit)."
  (let ((parts '()) (cur (make-string-output-stream)))
    (loop for ch across path
          do (if (char= ch #\/) (push (get-output-stream-string cur) parts) (write-char ch cur)))
    (push (get-output-stream-string cur) parts)
    (setf parts (nreverse parts))
    (unless (equal (first parts) "m") (%fail 1201 "path ~s must start with m/" path))
    (loop for p in (rest parts)
          collect (let* ((h (and (plusp (length p)) (member (char p (1- (length p))) '(#\' #\h #\H))))
                         (digits (if h (subseq p 0 (1- (length p))) p)))
                    (unless (and (plusp (length digits)) (every #'digit-char-p digits))
                      (%fail 1202 "bad path segment ~s in ~s" p path))
                    (let ((i (parse-integer digits)))
                      (unless (< i +hardened+) (%fail 1203 "path index ~a too large" i))
                      (if h (+ i +hardened+) i))))))

(defun %ser32 (i) (vector (ldb (byte 8 24) i) (ldb (byte 8 16) i) (ldb (byte 8 8) i) (ldb (byte 8 0) i)))

(defparameter +bitcoin-seed+ (%octets "Bitcoin seed"))

(defun master-from-seed (seed)
  "(values KEY-SECRET CHAIN-SECRET) for a SEED secret: HMAC-SHA512(\"Bitcoin seed\", seed)."
  (secp:secp-init)
  (gossamer:with-fixed-scratch ((i :octets 64))
    (with-secret-octets (s seed) (natrium:hmac-sha512-into +bitcoin-seed+ s i))
    (let ((k (copy-into-secret i :end 32)))
      (unless (with-secret-octets (kb k) (secp:seckey-valid-p kb))
        (wipe-secret k) (%fail 1204 "seed gives an invalid master key"))
      (values k (copy-into-secret i :start 32)))))

(defun %ckd-priv (key chain index)
  "Child (values KEY-SECRET CHAIN-SECRET) of KEY/CHAIN secrets at INDEX."
  (with-secret-octets (kb key)
    (with-secret-octets (cb chain)
      (gossamer:with-fixed-scratch ((i :octets 64) (zero :octets 1))
        (natrium:hmac-sha512-into cb (if (>= index +hardened+)
                                         (list zero kb (%ser32 index))
                                         (list (secp:seckey-compressed-pubkey kb) (%ser32 index)))
                                  i)
        (let ((child (make-secret 32)))
          (handler-case (with-secret-octets (ob child) (secp:seckey-tweak-add-into kb i ob))
            (error () (wipe-secret child) (%fail 1205 "invalid child at index ~a (use the next index)" index)))
          (values child (copy-into-secret i :start 32)))))))

(defun derive-private-key (seed path)
  "The private key at PATH under SEED (a secret), as a new 32-byte SECRET.  All
intermediate key and chain secrets are wiped."
  (multiple-value-bind (k c) (master-from-seed seed)
    (dolist (index (parse-path path) (progn (wipe-secret c) k))
      (multiple-value-bind (k2 c2) (unwind-protect (%ckd-priv k c index)
                                     (wipe-secret k) (wipe-secret c))
        (setf k k2 c c2)))))

(defun xonly-public-key (key)
  "The 32-byte x-only public key (Nostr pubkey) of a private KEY secret."
  (with-secret-octets (kb key) (sch:pubkey-xonly kb)))
