# wax

A signer: one BIP-39 seed, a key per role, and nothing signed without a policy.

wax holds a seed as a secret and derives role keys from it on hardened BIP-32 paths: your npub, a machine key, a payments key. It signs Nostr events for callers that a role allows, under that role's policy. It's deliberately small, with no network client and no parser for anything it didn't define, so the code that holds your seed stays auditable.

## Roles and policy

```lisp
(let ((keep (wax:open-keep mnemonic)))
  (wax:define-role keep "nostr" "m/44'/1237'/0'/0/0" :policy :approve :callers '("uid:1000"))
  (wax:define-role keep "witness" "m/44'/1237'/1'/0/0" :policy :auto :callers (list witness-pubkey))
  ...)
```

Each role has a policy:
- **`:deny`** signs nothing (the default).
- **`:approve`** puts every request to `*approve-fn*`, which is a human or a button on a board. Without one, requests are denied.
- **`:auto`** signs for an allowed caller without asking.

A role must name its callers. A caller is either a transport identity (`uid:1000` from a kernel-attested Unix socket) or a pubkey proven by a request envelope.

Private keys are derived per request and wiped after use; only public keys are cached.

## Requests

`handle-request` takes one JSON request and returns one response. There's no I/O in the core. The methods follow NIP-46's names: `ping`, `list_roles`, `get_public_key`, `sign_event`.

On a transport that authenticates nothing (TCP, a relay), each request carries an **envelope**: a kind-27235 event signed by the caller's key. It binds:
- the method;
- the request id;
- the SHA-256 of the exact params;
- the signer it's addressed to.

Each envelope is accepted once, within a skew window of the signer's own clock. Seeing an envelope on the wire gives an attacker nothing to reuse.

## Secrets

The seed and every derived key live in natrium's **gossamer** memory, which the collector never moves, so a collection leaves no stale copies. All arithmetic on them runs on fixed buffers too: PBKDF2, BIP-32 tweaks, BIP-340 signing.
- **SBCL:** static vectors. `lock-process-memory` adds mlockall.
- **modus (hosted):** gossamer's arena, which is locked, undumpable, and wiped on fork.

## Use

```lisp
(asdf:load-system :wax)
(asdf:test-system :wax)     ; BIP-39 / BIP-32 / NIP-06 vectors, heap-residue check
```

Depends on natrium, secp256k1-fast and json-simple.

## License

MIT
