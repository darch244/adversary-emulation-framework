# DISCLAIMER — Authorized Use Policy

This framework is **strictly a simulation and detection-validation platform**.
It is designed to be used **only in environments you own, operate, or have
explicit written authorization to test**.

## Acceptable Use

- Authorized penetration tests, red-team engagements, and purple-team exercises.
- Internal security research on systems you control.
- Detection engineering validation in lab / test environments.
- Educational and training purposes behind an isolated lab boundary.

## Unacceptable Use

- Any use against systems you do not own or lack explicit written authorization for.
- Any attempt to transition the safe, in-memory, synthetic simulation primitives
  into live weaponization against third-party or production assets.
- Circumvention of the framework's `--mock` / offline-only boundaries for
  real-world offensive activity.

## Scope Restrictions

All modules in this repository emit **synthetic, in-memory telemetry** only:

- Credential-access modules do **not** read real process memory; they produce
  structured metadata describing what a real access would look like.
- Persistence modules create **named, reversible, auto-rolled-back simulation**
  artifacts (test-named registry/log entries with cleanup routines).
- Network modules never perform real lateral movement; they emit emulation
  payload descriptors for detection validation.

## Liability

The author (Mostafa Ibrahim) and contributors are not liable for misuse of this
software. By using this framework you acknowledge that you are solely
responsible for ensuring all activity is authorized and compliant with
applicable laws and regulations.

**No system is to be touched without authorization. Full stop.**