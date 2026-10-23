;;;; package.lisp

(defpackage #:wax
  (:use #:cl)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:sch #:secp256k1-fast.schnorr))
  (:export
   ;; secrets
   #:secret #:make-secret #:secret-length #:secret-wiped-p #:wipe-secret #:with-secret-octets
   #:secret-backend #:copy-into-secret
   ;; bip39 / bip32
   #:generate-mnemonic #:validate-mnemonic #:mnemonic->seed #:mnemonic-from-entropy
   #:parse-path #:derive-private-key #:master-from-seed
   ;; events
   #:event-id #:serialize-event #:sign-event #:verify-event
   ;; keep: the signer state
   #:keep #:open-keep #:close-keep #:keep-open-p
   #:define-role #:keep-roles #:role #:role-name #:role-path #:role-policy #:role-callers
   #:role-public-key #:role-npub-hex
   ;; envelopes
   #:make-envelope #:verify-envelope #:+envelope-kind+
   #:make-sequence-store #:sequence-store
   ;; handler
   #:handle-request #:*approve-fn*
   #:wax-error #:wax-error-code))
