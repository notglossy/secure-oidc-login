# Project instructions for automated PR reviews

This file is appended to the AI reviewers' system prompt on every run
(see `.github/scripts/ai_review.py`, `AI_INSTRUCTIONS_FILE`). It records
settled design decisions so review rounds do not re-litigate them. Keep
entries short and factual; delete them when the code they describe is gone.

## Review posture

- This is a security plugin (OIDC authentication). Fail-closed error
  handling, defense-in-depth, and layered gates that cover different
  deployment configurations (with and without a persistent object cache,
  with and without a `$wpdb` drop-in) are design goals, not bloat.
- WordPress options have no native TTL. Storage that expires must bring its
  own garbage collection.

## Settled decisions — do not re-flag

Decided on PR #93 (back-channel logout jti replay cache):

- The two-layer replay gate in `includes/class-oidc-client.php`
  (`wp_cache_add()` fast-path population + atomic `INSERT IGNORE` durable
  gate) is intentional. The cache layer serves persistent-object-cache
  deployments; the durable layer is the source of truth. Do not propose
  collapsing it to a single `get_option`/`update_option` check.
- `maybe_sweep_expired_jtis()` stays. Delete-on-read only removes an entry
  when the same jti is replayed; entries for jtis never re-submitted would
  otherwise accumulate forever. The sweep is bounded (`LIMIT 100`),
  probabilistic (~1%), and duck-typed for `$wpdb` drop-ins.
- The `$force` parameter on the sweep is a deliberate test seam:
  `random_int()` is an internal function that Patchwork cannot redefine, so
  the DB path cannot be tested deterministically without it.
- The duck-typed `$wpdb` guard (`is_object` + property/method checks instead
  of `instanceof wpdb`) supports HyperDB/LudicrousDB-style drop-ins that
  replace the global with a wrapper not extending `wpdb`.
- The `wpdb` stand-in class in `tests/bootstrap.php` exists to exercise the
  sweep's SQL path without a real database; patch coverage fails without it.
- `random_int()` wrapped in try/catch (fail-soft skip on CSPRNG failure) is
  preferred over `mt_rand()` for the sweep roll.
- `add_option()` is not an atomic insert gate: WordPress core implements it
  with `INSERT ... ON DUPLICATE KEY UPDATE` and treats a changed duplicate
  (affected rows = 2) as success. Atomic claims use `INSERT IGNORE` on the
  `option_name` unique key directly.
