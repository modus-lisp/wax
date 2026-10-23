;;;; tests.lisp -- wax against published vectors, plus policy, envelope and handler checks.

(defpackage #:wax.tests
  (:use #:cl)
  (:export #:run))

(in-package #:wax.tests)

(defvar *pass* 0)
(defvar *fail* '())

(defmacro check (name form)
  `(if (ignore-errors ,form)
       (incf *pass*)
       (progn (push ,name *fail*) (format t "~&FAIL: ~a~%" ,name))))

(defun hex (v) (wax::%hex v))
(defun unhex (s) (wax::%unhex s))
(defun ht (&rest kv) (apply #'wax::%ht kv))
(defun err-code (resp) (let ((e (gethash "error" resp))) (and e (gethash "code" e))))

;;; BIP-39: Trezor vectors (passphrase "TREZOR").
(defparameter *bip39-vectors*
  '(("00000000000000000000000000000000"
     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
    ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
     "legal winner thank year wave sausage worth useful legal winner thank yellow"
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607")
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad")))

(defun test-bip39 ()
  (loop for (ent words seed) in *bip39-vectors*
        do (check (format nil "bip39 words ~a" (subseq ent 0 8)) (equal (wax:mnemonic-from-entropy (unhex ent)) words))
           (check (format nil "bip39 valid ~a" (subseq ent 0 8)) (wax:validate-mnemonic words))
           (check (format nil "bip39 seed ~a" (subseq ent 0 8))
                  (let ((s (wax:mnemonic->seed words "TREZOR")))
                    (wax:with-secret-octets (o s) (equal (hex o) seed)))))
  (check "bip39 bad checksum rejected"
         (not (wax:validate-mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")))
  (check "bip39 unknown word rejected" (not (wax:validate-mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzz")))
  (check "bip39 generate 24 words, valid"
         (let ((m (wax:generate-mnemonic))) (and (= 24 (length (wax::%split-words m))) (wax:validate-mnemonic m))))
  (check "bip39 two generations differ" (not (equal (wax:generate-mnemonic :words 12) (wax:generate-mnemonic :words 12)))))

;;; BIP-32 test vector 1.
(defparameter *bip32-v1*
  '(("m/0'" "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
    ("m/0'/1" "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
    ("m/0'/1/2'" "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca")
    ("m/0'/1/2'/2" "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4")
    ("m/0'/1/2'/2/1000000000" "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")))

(defun test-bip32 ()
  (let ((seed (wax:copy-into-secret (unhex "000102030405060708090a0b0c0d0e0f"))))
    (check "bip32 master key"
           (let ((k (wax:master-from-seed seed)))
             (wax:with-secret-octets (o k) (equal (hex o) "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"))))
    (loop for (path priv) in *bip32-v1*
          do (check (format nil "bip32 ~a" path)
                    (let ((k (wax:derive-private-key seed path)))
                      (prog1 (wax:with-secret-octets (o k) (equal (hex o) priv)) (wax:wipe-secret k))))))
  (check "path parse" (equal (wax:parse-path "m/44'/1237'/0'/0/0") (list (+ 44 #x80000000) (+ 1237 #x80000000) #x80000000 0 0)))
  (check "path without m rejected" (handler-case (progn (wax:parse-path "44'/0") nil) (wax:wax-error () t))))

;;; NIP-06 vectors.
(defparameter *nip06*
  '(("leader monkey parrot ring guide accident before fence cannon height naive bean"
     "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a"
     "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917")
    ("what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"
     "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add"
     "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573")))

(defun test-nip06 ()
  (loop for (m priv pub) in *nip06*
        do (let* ((seed (wax:mnemonic->seed m))
                  (k (wax:derive-private-key seed "m/44'/1237'/0'/0/0")))
             (check (format nil "nip06 priv ~a" (subseq pub 0 8)) (wax:with-secret-octets (o k) (equal (hex o) priv)))
             (check (format nil "nip06 pub ~a" (subseq pub 0 8)) (equal (hex (wax::xonly-public-key k)) pub))
             (wax:wipe-secret k) (wax:wipe-secret seed))))

(defun test-events ()
  (let* ((k (wax:copy-into-secret (unhex "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a")))
         (ev (wax:sign-event (ht "kind" 1 "created_at" 1700000000 "content" "hi \"there\"
line" "tags" (vector (vector "t" "wax"))) k)))
    (check "signed event verifies" (wax:verify-event ev))
    (check "pubkey is the key's" (equal (gethash "pubkey" ev) "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"))
    (check "serialization escapes" (search "hi \\\"there\\\"\\nline" (wax:serialize-event ev)))
    (setf (gethash "content" ev) "changed")
    (check "tampered event fails" (not (wax:verify-event ev)))))

(defparameter *m* "leader monkey parrot ring guide accident before fence cannon height naive bean")

(defun test-keep-and-handler ()
  (let ((keep (wax:open-keep *m*))
        (cache (wax:make-sequence-store))
        (seq 0)
        (keep-id (make-string 64 :initial-element #\a))
        (caller-key (wax:copy-into-secret (unhex "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add")))
        (caller-pub "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573"))
    (check "unhardened intermediate path refused"
           (handler-case (progn (wax:define-role keep "bad" "m/44'/1237'/0/0/0" :policy :auto) nil) (wax:wax-error () t)))
    (wax:define-role keep "main" "m/44'/1237'/0'/0/0" :policy :approve :callers (list "uid:1000" caller-pub))
    (wax:define-role keep "bot" "m/44'/1237'/5'/0'/0'" :policy :auto :callers (list caller-pub))
    (wax:define-role keep "locked" "m/44'/1237'/6'/0'/0'" :callers (list "uid:1000"))
    (flet ((req (method params &key caller envelope (id "1"))
             (let ((text (json-simple:stringify params)))
               (wax:handle-request keep (apply #'ht "id" id "method" method "params" text
                                               (and envelope (list "envelope" (funcall envelope method id text))))
                                   :transport-caller caller :keep-id keep-id :sequences cache)))
           (env (&key (method nil) (keep nil) (payload nil) (seq* nil))
             (lambda (m id text)
               (wax:make-envelope caller-key (or method m) id (or payload text) (or keep keep-id)
                                  (or seq* (incf seq))))))
      (let ((ev (ht "kind" 1 "created_at" 1700000000 "content" "x" "tags" #())))
        (check "role pubkey is NIP-06's"
               (equal (gethash "result" (req "get_public_key" (ht "role" "main") :caller "uid:1000"))
                      "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"))
        (check "approve role denied with no human" (eql 5003 (err-code (req "sign_event" (ht "role" "main" "event" ev) :caller "uid:1000"))))
        (let ((wax:*approve-fn* (lambda (caller role summary) (declare (ignore caller role)) (search "kind=1" summary))))
          (check "approve role signs when approved"
                 (wax:verify-event (gethash "result" (req "sign_event" (ht "role" "main" "event" ev) :caller "uid:1000")))))
        (let ((wax:*approve-fn* (constantly nil)))
          (check "approve role refused when the human says no"
                 (eql 5003 (err-code (req "sign_event" (ht "role" "main" "event" ev) :caller "uid:1000")))))
        (check "deny-policy role refuses" (eql 5002 (err-code (req "sign_event" (ht "role" "locked" "event" ev) :caller "uid:1000"))))
        (check "caller not listed refused" (eql 5001 (err-code (req "sign_event" (ht "role" "bot" "event" ev) :caller "uid:1000"))))
        (check "unknown role" (eql 2004 (err-code (req "get_public_key" (ht "role" "nope") :caller "uid:1000"))))
        ;; envelopes
        (let ((r (req "sign_event" (ht "role" "bot" "event" ev) :envelope (env) :id "e1")))
          (check "envelope-authenticated auto role signs" (wax:verify-event (gethash "result" r))))
        (let* ((params (ht "role" "bot" "event" ev)) (text (json-simple:stringify params))
               (e (wax:make-envelope caller-key "sign_event" "e2" text keep-id (incf seq) :created-at 1))
               (r1 (wax:handle-request keep (ht "id" "e2" "method" "sign_event" "params" text "envelope" e)
                                       :keep-id keep-id :sequences cache))
               (r2 (wax:handle-request keep (ht "id" "e2" "method" "sign_event" "params" text "envelope" e)
                                       :keep-id keep-id :sequences cache)))
          (check "first use of an envelope accepted, whatever its created_at" (gethash "result" r1))
          (check "replayed envelope refused" (eql 4010 (err-code r2))))
        (check "envelope with an old sequence number refused"
               (eql 4010 (err-code (req "sign_event" (ht "role" "bot" "event" ev) :envelope (env :seq* 1) :id "e3"))))
        (check "sequence numbers may skip"
               (gethash "result" (req "sign_event" (ht "role" "bot" "event" ev) :envelope (env :seq* (incf seq 1000)) :id "e3b")))
        (let* ((stranger (wax:copy-into-secret (unhex "0000000000000000000000000000000000000000000000000000000000000003")))
               (text (json-simple:stringify (ht)))
               (r (wax:handle-request keep (ht "id" "s1" "method" "ping" "params" text
                                               "envelope" (wax:make-envelope stranger "ping" "s1" text keep-id 1))
                                      :keep-id keep-id :sequences cache)))
          (check "unknown caller refused and not remembered"
                 (and (eql 5001 (err-code r)) (= 1 (hash-table-count (wax::sequence-store-last cache))))))
        (let* ((path (merge-pathnames (format nil "wax-seq-~d.txt" (random 1000000)) (uiop:temporary-directory)))
               (a (wax:make-sequence-store path))
               (text (json-simple:stringify (ht))))
          (unwind-protect
               (progn
                 (wax:handle-request keep (ht "id" "p1" "method" "ping" "params" text
                                              "envelope" (wax:make-envelope caller-key "ping" "p1" text keep-id 7))
                                     :keep-id keep-id :sequences a)
                 (let ((b (wax:make-sequence-store path)))
                   (check "sequence marks survive a restart"
                          (eql 4010 (err-code (wax:handle-request keep (ht "id" "p2" "method" "ping" "params" text
                                                                           "envelope" (wax:make-envelope caller-key "ping" "p2" text keep-id 7))
                                                                  :keep-id keep-id :sequences b))))))
            (ignore-errors (delete-file path))))
        (check "envelope for another method refused"
               (eql 4005 (err-code (req "sign_event" (ht "role" "bot" "event" ev) :envelope (env :method "ping") :id "e4"))))
        (check "envelope for another signer refused"
               (eql 4008 (err-code (req "sign_event" (ht "role" "bot" "event" ev) :envelope (env :keep (make-string 64 :initial-element #\b)) :id "e5"))))
        (check "params altered after signing refused"
               (eql 4007 (err-code (req "sign_event" (ht "role" "bot" "event" ev) :envelope (env :payload "{}") :id "e6"))))
        (check "unidentified caller refused" (eql 5001 (err-code (req "sign_event" (ht "role" "bot" "event" ev)))))
        (check "list_roles shows only the caller's roles"
               (= 2 (length (gethash "result" (req "list_roles" (ht) :caller "uid:1000")))))))
    ;; closing wipes the seed
    (let ((seed (wax::keep-seed keep)))
      (wax:close-keep keep)
      (check "close wipes the seed" (every #'zerop (wax::secret-octets seed)))
      (check "closed keep refuses" (eql 2001 (err-code (wax:handle-request keep (ht "id" "z" "method" "ping"))))))))

(defun test-heap ()
  "Measurement, not proof: after signing and a full GC, how many octet vectors on the
moving heap contain the role's private key bytes?"
  #+sbcl
  (let* ((priv (unhex "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a"))
         (keep (wax:open-keep *m*)))
    (wax:define-role keep "main" "m/44'/1237'/0'/0/0" :policy :auto :callers '("t"))
    (wax:handle-request keep (ht "id" "h" "method" "sign_event" "params"
                                 (json-simple:stringify (ht "role" "main" "event" (ht "kind" 1 "created_at" 1 "content" "" "tags" #()))))
                        :transport-caller "t")
    (wax:close-keep keep)
    (sb-ext:gc :full t)
    (let ((hits 0))
      (sb-vm:map-allocated-objects
       (lambda (obj type size)
         (declare (ignore type size))
         (when (and (typep obj '(simple-array (unsigned-byte 8) (*))) (not (eq obj priv))
                    (>= (length obj) 32) (search priv obj))
           (incf hits)))
       :dynamic)
      (format t "~&heap: ~d moving-heap octet vector~:p hold the role key after signing + GC~%" hits)
      (check "no moving-heap octet vector holds the role key" (zerop hits)))))

(defun run ()
  (setf *pass* 0 *fail* '())
  (test-bip39) (test-bip32) (test-nip06) (test-events) (test-keep-and-handler) (test-heap)
  (format t "~&wax: ~d passed, ~d failed~%" *pass* (length *fail*))
  (null *fail*))
