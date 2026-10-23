;;;; event.lisp -- NIP-01 events: canonical serialization, id, BIP-340 signature.
;;;;
;;;; Written here rather than taken from cl-nostr so the signer core does not pull in a
;;;; network client.  An event is a JSON object (EQUAL hash table) with "pubkey",
;;;; "created_at", "kind", "tags", "content", and after signing "id" and "sig".

(in-package #:wax)

(defun %hex (octets)
  (with-output-to-string (s) (loop for b across octets do (format s "~(~2,'0x~)" b))))

(defun %unhex (string)
  (unless (and (stringp string) (evenp (length string)) (every (lambda (c) (digit-char-p c 16)) string))
    (%fail 1301 "not hex: ~s" string))
  (let ((v (%u8 (/ (length string) 2))))
    (dotimes (i (length v) v)
      (setf (aref v i) (parse-integer string :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))

(defun %json-string (s out)
  "NIP-01 string escaping: \\\" \\\\ \\n \\r \\t \\b \\f escaped, everything else raw."
  (write-char #\" out)
  (loop for ch across s
        do (case ch
             (#\" (write-string "\\\"" out))
             (#\\ (write-string "\\\\" out))
             (#\Newline (write-string "\\n" out))
             (#\Return (write-string "\\r" out))
             (#\Tab (write-string "\\t" out))
             (#\Backspace (write-string "\\b" out))
             (#\Page (write-string "\\f" out))
             (t (write-char ch out))))
  (write-char #\" out))

(defun %field (event key)
  (multiple-value-bind (v present) (gethash key event)
    (unless present (%fail 1302 "event lacks ~s" key))
    v))

(defun serialize-event (event)
  "The NIP-01 id preimage: [0,pubkey,created_at,kind,tags,content] with no spaces."
  (with-output-to-string (out)
    (write-string "[0," out)
    (%json-string (%field event "pubkey") out)
    (format out ",~d,~d,[" (%field event "created_at") (%field event "kind"))
    (let ((first-tag t))
      (map nil (lambda (tag)
                 (unless first-tag (write-char #\, out))
                 (setf first-tag nil)
                 (write-char #\[ out)
                 (let ((first t))
                   (map nil (lambda (x)
                              (unless (stringp x) (%fail 1303 "tag element ~s is not a string" x))
                              (unless first (write-char #\, out))
                              (setf first nil)
                              (%json-string x out))
                        tag))
                 (write-char #\] out))
           (%field event "tags")))
    (write-string "]," out)
    (%json-string (%field event "content") out)
    (write-string "]" out)))

(defun event-id (event)
  (natrium:sha256 (%octets (serialize-event event))))

(defun sign-event (event key)
  "Fill in EVENT's pubkey, id and sig under the private KEY secret.  Returns EVENT."
  (secp:secp-init)
  (setf (gethash "pubkey" event) (%hex (xonly-public-key key)))
  (let ((id (event-id event)))
    (setf (gethash "id" event) (%hex id))
    (with-secret-octets (kb key)
      (setf (gethash "sig" event)
            (%hex (sch:schnorr-sign kb id (natrium:os-entropy 32)))))
    event))

(defun verify-event (event)
  "T iff EVENT's id is its serialization's hash and its sig verifies under its pubkey."
  (handler-case
      (let ((id (event-id event)))
        (and (equalp (%unhex (%field event "id")) id)
             (sch:schnorr-verify (%unhex (%field event "pubkey")) id (%unhex (%field event "sig")))))
    (error () nil)))
