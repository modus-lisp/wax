;;;; handler.lisp -- one request in, one response out.  No I/O.
;;;;
;;;; A request is a JSON object:
;;;;   {"id": "...", "method": "...", "params": "<JSON text>", "envelope": {...}?}
;;;; PARAMS is carried as text so an envelope's payload hash covers exactly what was sent.
;;;; The caller's identity comes from the transport (TRANSPORT-CALLER, e.g. "uid:1000"
;;;; from SO_PEERCRED) or, when the transport attests nothing, from a verified envelope
;;;; (the caller's pubkey hex).  A transport identity and an envelope may not disagree:
;;;; when both are present, the envelope's key is the caller.
;;;;
;;;; Methods (named after NIP-46 where one exists):
;;;;   ping                         -> "pong"
;;;;   list_roles                   -> [{name, pubkey, policy}] for roles this caller may use
;;;;   get_public_key {role}        -> pubkey hex
;;;;   sign_event {role, event}     -> the signed event
;;;;
;;;; Authorization: the caller must be in the role's CALLERS; then the role's policy
;;;; decides (:deny / :approve via *APPROVE-FN* / :auto).

(in-package #:wax)

(defvar *approve-fn* nil
  "Function of (CALLER ROLE SUMMARY) returning true to approve one signature.  NIL means
no human is available, so :approve roles are denied.  On a board this is a button.")

(defun %summary (method role params)
  (let ((ev (gethash "event" params)))
    (format nil "~a role=~a~@[ kind=~a~]~@[ content=~s~]" method (role-name role)
            (and ev (gethash "kind" ev))
            (and ev (let ((c (gethash "content" ev)))
                      (and (stringp c) (if (> (length c) 80) (concatenate 'string (subseq c 0 80) "…") c)))))))

(defun %authorize (keep caller role-name method params)
  (let ((role (find-role keep role-name)))
    (unless (and caller (member caller (role-callers role) :test #'equal))
      (%fail 5001 "caller ~a may not use role ~a" (or caller "(unidentified)") role-name))
    (ecase (role-policy role)
      (:deny (%fail 5002 "role ~a is deny" role-name))
      (:auto role)
      (:approve
       (unless (and *approve-fn* (funcall *approve-fn* caller role (%summary method role params)))
         (%fail 5003 "not approved"))
       role))))

(defun %clean-event (ev)
  "A fresh event from the caller's: only kind, created_at, tags, content are taken."
  (unless (hash-table-p ev) (%fail 5101 "event must be an object"))
  (let ((kind (gethash "kind" ev)) (ts (gethash "created_at" ev))
        (tags (gethash "tags" ev)) (content (gethash "content" ev)))
    (unless (and (integerp kind) (<= 0 kind 65535)) (%fail 5102 "bad kind"))
    (unless (integerp ts) (%fail 5103 "bad created_at"))
    (unless (stringp content) (%fail 5104 "content must be a string"))
    (unless (and (vectorp tags) (every (lambda (tg) (and (vectorp tg) (every #'stringp tg))) tags))
      (%fail 5105 "tags must be an array of arrays of strings"))
    (%ht "kind" kind "created_at" ts "tags" tags "content" content)))

(defun %dispatch (keep caller method params)
  (flet ((role-arg () (or (gethash "role" params) (%fail 5106 "params need a role"))))
    (cond
      ((equal method "ping") "pong")
      ((equal method "list_roles")
       (coerce (loop for r in (keep-roles keep)
                     when (member caller (role-callers r) :test #'equal)
                       collect (%ht "name" (role-name r) "pubkey" (role-npub-hex r)
                                    "policy" (string-downcase (symbol-name (role-policy r)))))
               'vector))
      ((equal method "get_public_key")
       (let ((role (find-role keep (role-arg))))
         (unless (member caller (role-callers role) :test #'equal)
           (%fail 5001 "caller ~a may not use role ~a" caller (role-name role)))
         (role-npub-hex role)))
      ((equal method "sign_event")
       (let* ((role (%authorize keep caller (role-arg) method params))
              (ev (%clean-event (gethash "event" params))))
         (call-with-role-key keep role (lambda (key) (sign-event ev key)))))
      (t (%fail 5000 "unknown method ~s" method)))))

(defun %known-caller-p (keep caller)
  (some (lambda (r) (member caller (role-callers r) :test #'equal)) (keep-roles keep)))

(defun handle-request (keep request &key transport-caller keep-id sequences)
  "Process REQUEST (parsed JSON object).  Returns the response object; never signals
for a bad request -- errors become {\"error\": {code, message}}."
  (let ((id (and (hash-table-p request) (gethash "id" request))))
    (handler-case
        (progn
          (unless (hash-table-p request) (%fail 1001 "request must be an object"))
          (unless (keep-open-p keep) (%fail 2001 "the keep is closed"))
          (let* ((method (or (gethash "method" request) (%fail 1002 "request lacks method")))
                 (params-text (or (gethash "params" request) "{}"))
                 (params (handler-case (json-simple:parse params-text)
                           (error () (%fail 1003 "params are not JSON"))))
                 (envelope (gethash "envelope" request))
                 (caller (cond (envelope
                                (unless (and keep-id sequences)
                                  (%fail 1004 "this transport cannot check envelopes"))
                                (verify-envelope envelope method id params-text keep-id sequences
                                                 :known (lambda (c) (%known-caller-p keep c))))
                               (t transport-caller))))
            (unless (hash-table-p params) (%fail 1005 "params must be an object"))
            (%ht "id" id "result" (%dispatch keep caller method params))))
      (wax-error (e) (%ht "id" id "error" (%ht "code" (wax-error-code e) "message" (wax-error-message e))))
      (error (e) (%ht "id" id "error" (%ht "code" 1 "message" (princ-to-string e)))))))
