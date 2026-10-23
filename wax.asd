;;;; wax.asd -- a signer: one seed, many role keys, nothing signed without a policy.
;;;;
;;;; :wax        the signer core: secrets, BIP-39/BIP-32, roles and policy, NIP-01
;;;;             event signing, signed request envelopes, the request handler.
;;;;             Portable Common Lisp on natrium + secp256k1-fast; runs on SBCL and
;;;;             is written to run on modus (hosted and bare metal).
;;;; :wax/tests  offline tests against the published BIP-39/BIP-32/NIP-06 vectors.

(asdf:defsystem :wax
  :description "Signer: a BIP-39 seed held as a secret, role keys on hardened paths, per-role policy, authenticated requests."
  :author "ynniv"
  :license "MIT"
  :depends-on (:natrium :secp256k1-fast :json-simple (:feature :sbcl :sb-posix))
  :in-order-to ((test-op (test-op :wax/tests)))
  :serial t
  :components ((:module "src"
                :components ((:file "package")
                             (:file "secret")
                             (:file "bip39-wordlist")
                             (:file "bip39")
                             (:file "bip32")
                             (:file "event")
                             (:file "roles")
                             (:file "envelope")
                             (:file "handler")))))

(asdf:defsystem :wax/tests
  :description "Offline tests for wax."
  :license "MIT"
  :depends-on (:wax)
  :serial t
  :components ((:module "t" :components ((:file "tests"))))
  :perform (test-op (o c) (unless (uiop:symbol-call :wax.tests :run)
                            (error "wax tests failed"))))
