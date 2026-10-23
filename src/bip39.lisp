;;;; bip39.lisp -- mnemonics and seeds.
;;;;
;;;; Entropy comes from natrium:os-entropy (modus hardware entropy where present, the
;;;; OS CSPRNG otherwise), never from CL:RANDOM.  The seed is PBKDF2-HMAC-SHA512 over
;;;; the mnemonic, written out here on natrium so it runs wherever natrium does, and
;;;; returned as a SECRET.

(in-package #:wax)

(defun %octets (string)
  "UTF-8 octets of STRING (NFKD normalisation is the caller's; ASCII mnemonics are exact)."
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for ch across string
          for c = (char-code ch)
          do (cond ((< c #x80) (vector-push-extend c out))
                   ((< c #x800) (vector-push-extend (logior #xC0 (ash c -6)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   ((< c #x10000) (vector-push-extend (logior #xE0 (ash c -12)) out)
                    (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                    (vector-push-extend (logior #x80 (logand c #x3F)) out))
                   (t (vector-push-extend (logior #xF0 (ash c -18)) out)
                      (vector-push-extend (logior #x80 (logand (ash c -12) #x3F)) out)
                      (vector-push-extend (logior #x80 (logand (ash c -6) #x3F)) out)
                      (vector-push-extend (logior #x80 (logand c #x3F)) out))))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun %u8 (n &optional (init 0)) (make-array n :element-type '(unsigned-byte 8) :initial-element init))

(defun %word-index (word)
  (or (position word *bip39-words* :test #'string=)
      (%fail 1101 "~s is not a BIP-39 word" word)))

(defun %split-words (mnemonic)
  (let ((words '()) (cur (make-string-output-stream)))
    (loop for ch across (string-downcase mnemonic)
          do (if (member ch '(#\Space #\Tab #\Newline #\Return))
                 (let ((w (get-output-stream-string cur))) (when (plusp (length w)) (push w words)))
                 (write-char ch cur)))
    (let ((w (get-output-stream-string cur))) (when (plusp (length w)) (push w words)))
    (nreverse words)))

(defun mnemonic-from-entropy (entropy)
  "The BIP-39 mnemonic for ENTROPY (16..32 bytes, a multiple of 4)."
  (let ((n (length entropy)))
    (unless (and (<= 16 n 32) (zerop (mod n 4))) (%fail 1102 "entropy must be 16..32 bytes, multiple of 4"))
    (let* ((cs-bits (/ (* n 8) 32))
           (hash (natrium:sha256 (coerce entropy '(simple-array (unsigned-byte 8) (*)))))
           (bits (+ (ash (loop with v = 0 for b across entropy do (setf v (logior (ash v 8) b)) finally (return v))
                         cs-bits)
                    (ash (aref hash 0) (- cs-bits 8))))
           (nwords (/ (+ (* n 8) cs-bits) 11)))
      (format nil "~{~a~^ ~}"
              (loop for i from (1- nwords) downto 0
                    collect (aref *bip39-words* (ldb (byte 11 (* 11 i)) bits)))))))

(defun validate-mnemonic (mnemonic)
  "T if MNEMONIC is a well-formed BIP-39 English mnemonic with a correct checksum."
  (handler-case
      (let* ((words (%split-words mnemonic))
             (nw (length words)))
        (and (member nw '(12 15 18 21 24))
             (let* ((total (* nw 11))
                    (cs-bits (/ total 33))
                    (ent-bits (- total cs-bits))
                    (bits (loop with v = 0 for w in words do (setf v (logior (ash v 11) (%word-index w))) finally (return v)))
                    (ent (ldb (byte ent-bits cs-bits) bits))
                    (entropy (let ((v (%u8 (/ ent-bits 8))))
                               (dotimes (i (length v) v)
                                 (setf (aref v i) (ldb (byte 8 (* 8 (- (length v) 1 i))) ent)))))
                    (hash (natrium:sha256 entropy)))
               (= (ldb (byte cs-bits 0) bits) (ash (aref hash 0) (- cs-bits 8))))))
    (wax-error () nil)))

(defun generate-mnemonic (&key (words 24))
  "A fresh mnemonic of WORDS words (12 or 24) from os-entropy."
  (let ((n (ecase words (12 16) (24 32))))
    (let ((e (natrium:os-entropy n)))
      (prog1 (mnemonic-from-entropy e) (fill e 0)))))

(defun %pbkdf2-hmac-sha512-into (password salt iterations out)
  "PBKDF2-HMAC-SHA512 into OUT (fixed): natrium's, with every intermediate in fixed memory."
  (natrium:pbkdf2-into :sha512 password salt iterations out))

(defun mnemonic->seed (mnemonic &optional (passphrase ""))
  "The 64-byte BIP-39 seed for MNEMONIC, as a SECRET.  Refuses an invalid mnemonic.
The mnemonic string is the caller's (it arrived from outside); the UTF-8 password
bytes are copied into fixed memory and the heap copy wiped at once."
  (unless (validate-mnemonic mnemonic) (%fail 1103 "invalid BIP-39 mnemonic (words or checksum)"))
  (let* ((norm (format nil "~{~a~^ ~}" (%split-words mnemonic)))
         (heap-pw (%octets norm))
         (pw (gossamer:pooled-copy heap-pw))
         (seed (make-secret 64)))
    (fill heap-pw 0)
    (unwind-protect
         (with-secret-octets (o seed)
           (%pbkdf2-hmac-sha512-into pw (%octets (concatenate 'string "mnemonic" passphrase)) 2048 o))
      (gossamer:free pw))
    seed))
