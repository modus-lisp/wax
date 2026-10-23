;;;; roles.lisp -- the keep: an open seed and the roles derived from it.
;;;;
;;;; A KEEP holds the seed as a secret while open.  Each ROLE names a derivation path
;;;; and a policy:
;;;;   :deny     nothing is signed (the default for a role that names no policy)
;;;;   :approve  every request is put to *APPROVE-FN* (a human), and denied without it
;;;;   :auto     a request from an allowed caller is signed without asking
;;;; and CALLERS, the caller identities allowed to use it at all (e.g. a pubkey hex from
;;;; a verified envelope, or "uid:1000" from a kernel-attested socket).  NIL means none:
;;;; a role must name who may use it.
;;;;
;;;; Private keys are derived per request into a secret and wiped after use; only
;;;; public keys are cached.

(in-package #:wax)

(defstruct (role (:constructor %make-role))
  name path (policy :deny) callers (public-key nil) note)

(defstruct (keep (:constructor %make-keep))
  (seed nil) (roles '()) (lock nil))

(defun keep-open-p (keep) (and (keep-seed keep) (not (secret-wiped-p (keep-seed keep)))))

(defun open-keep (mnemonic &key (passphrase ""))
  "A keep holding the seed for MNEMONIC.  The mnemonic string itself is the caller's to
discard; the keep keeps only the seed, as a secret."
  (%make-keep :seed (mnemonic->seed mnemonic passphrase)))

(defun close-keep (keep)
  "Wipe the seed.  The keep can no longer sign."
  (wipe-secret (keep-seed keep))
  (setf (keep-seed keep) nil)
  keep)

(defun %need-open (keep) (unless (keep-open-p keep) (%fail 2001 "the keep is closed")))

(defun define-role (keep name path &key (policy :deny) callers note)
  "Add or replace role NAME on KEEP.  PATH must be fully hardened except NIP-06's
final 0/0 (m/44'/1237'/N'/0/0) -- a role on an unhardened intermediate path would let
anyone holding one child key and the parent's extended public key compute its siblings."
  (%need-open keep)
  (check-type name string)
  (unless (member policy '(:deny :approve :auto)) (%fail 2002 "unknown policy ~s" policy))
  (let ((idx (parse-path path)))
    (unless (or (every (lambda (i) (>= i +hardened+)) idx)
                (and (>= (length idx) 3)
                     (every (lambda (i) (>= i +hardened+)) (butlast idx 2))
                     (equal (last idx 2) '(0 0))))
      (%fail 2003 "path ~s must be all-hardened, or hardened down to a NIP-06 0/0 tail" path)))
  (let* ((key (derive-private-key (keep-seed keep) path))
         (pub (unwind-protect (xonly-public-key key) (wipe-secret key)))
         (role (%make-role :name name :path path :policy policy :callers callers
                           :public-key pub :note note)))
    (setf (keep-roles keep) (cons role (remove name (keep-roles keep) :key #'role-name :test #'string=)))
    role))

(defun find-role (keep name)
  (or (find name (keep-roles keep) :key #'role-name :test #'string=)
      (%fail 2004 "unknown role ~s" name)))

(defun role-npub-hex (role) (%hex (role-public-key role)))

(defun call-with-role-key (keep role fn)
  "Call FN with ROLE's private key secret, wiping it afterwards whatever happens."
  (%need-open keep)
  (let ((key (derive-private-key (keep-seed keep) (role-path role))))
    (unwind-protect
         (progn
           ;; The derivation must still give the public key the role was defined with.
           (unless (equalp (xonly-public-key key) (role-public-key role))
             (%fail 2005 "role ~a's key no longer matches its public key" (role-name role)))
           (funcall fn key))
      (wipe-secret key))))
