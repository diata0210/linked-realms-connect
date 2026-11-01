# 0003 — Root seed, agent identity and wallet branches

Status: Proposed

## Context

Hub Connect needs one global Player Ed25519 identity and an independent Land identity. The agent is the local trust anchor: it owns private keys, Noise and structured signing; browser and game Node never receive key material. The separate Chain track needs a Player wallet and a Land reward wallet, without adding wallet setup or chain availability to free entry. Owners should back up one secret per identity.

## Decision

Each Player and Land has one OS-generated 32-byte root seed in restricted key-file version 2. The [frozen v1 spec](../../protocol/v1.md) derives the identity with SLIP-0010 Ed25519 at m/0'/0'. It freezes wallet profile A (BIP32 secp256k1) and profile B (SLIP-0010 Ed25519), both at m/1'/0', with deterministic vectors. Both consume the root bytes directly, with no mnemonic passphrase stretching. A later 24-word display only encodes the same entropy. Hub identities remain plain Ed25519 seeds with no wallet or derivation.

The identity-signed, end-to-end encrypted GREETING may carry an optional wallet address of at most 64 bytes. The Land agent verifies the signature and hands the address to Node; this claims a reward destination, not wallet-control proof or on-chain identity registration. No wallet address appears in public cards or Hub-readable control metadata. Chain traffic bypasses Hub tunnels.

Export/import is explicit CLI-only with restricted files and fingerprint confirmation. There is no local-API key export or arbitrary signing. Node can request only fixed-type reward transfers from the Land wallet, subject to owner-set per-transaction and per-UTC-day caps. The agent durably reserves caps before signing and fails closed on corruption or unknown outcome; rollback/restart cannot replenish a spent cap. Connect controls are signed; Noise game data is authenticated ciphertext without per-frame signatures. Profiles travel as original Player-signed bytes; stats and inventory remain per-Land in Node-owned SQLite.

## Alternatives considered

- Separate wallet seed: better compartmentalization, but two secrets to back up and restore; not the chosen owner model.
- Mnemonic passphrase stretching: changes the actual derivation input and makes the same 32-byte backup insufficient without another secret; rejected for v1.
- Plain Ed25519 identity seed for all roles: matches the earlier draft key-file version 1 but has no independent identity/wallet branches; version 1 is rejected, never silently reinterpreted.
- External wallet or on-chain binding: adds entry dependencies and public correlation; unnecessary for a claimant-selected reward destination.

## Consequences

A single root leak compromises BOTH identity and wallet. Hardened branches prevent public derivation of their relationship but do not compartmentalize root compromise. Unencrypted backup theft and same-user malware/administrator access remain risks. Go erasure is best effort. Node compromise still threatens door/game decisions and can spend up to the configured reward budgets, but cannot retrieve keys or request arbitrary signatures.

The key file stores only root and recomputable identity public key, never a separate wallet key. ACLs, restrictive creation, locking, fsync and safe replacement are required; Land identity and land.db need coordinated SQLite-safe backup. Lost Player roots require a new identity; recovery/device linking and passphrase encryption are deferred. Production derivation/parity and filesystem security remain implementation acceptance work, not claims established by this ADR.

## Not decided

C1 records the chain foundation and selects profile A (btcd-style UTXO/secp256k1, owner-recommended) or B (account-model/Ed25519) in proposed ADR 0004. Selection does not edit the frozen paths or vectors. C2/C3/C4 own address encoding, fixed transaction schemas, mining and chain integration. Testnet first and the separate mainnet gate remain Chain-track decisions. This ADR is proposed, not approval of a cryptographic implementation or a chain launch.
