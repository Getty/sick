# The SICK handbook

From nothing to an internal certificate authority that your machines trust,
that keeps every device and service supplied with certificates, and that you
can run for years – with what is in this repository.

The parts that do the work are other people's: [step-ca](https://smallstep.com/docs/step-ca/)
is the CA, the `step` command issues, acme.sh deploys to devices it has a
hook for, `openssl` checks. SICK is the device list and the run that ties
them together. This handbook is the path through all of it.

| Chapter | What you have afterwards |
|---|---|
| [1. Planning](01-planning.md) | names, networks, lifetimes, key types and who may get which certificate – written down before anything is made |
| [2. The CA](02-the-ca.md) | an offline root, a name-constrained intermediate in step-ca, a ceremony record, a restored backup, and the procedures to renew the intermediate and replace the root |
| [3. Clients trust the CA](03-clients.md) | every machine and program you care about trusts the root – and only the root –, checked against a fingerprint from a second channel, and you can take it back |
| 4. The first device | one device served with a certificate of your CA, renewed on a schedule (to come) |
| 5. All devices and services | devices through SICK, services through ACME (P6, P7, to come) |
| 6. Operations | timer, monitoring, alerts, inventory (P5, to come) |
| [7. Emergencies](07-emergencies.md) | what to do when a key is lost or exposed, the CA is down or compromised, a certificate expired, a device is locked out |

Conventions:

- Commands are shown with what they print. Names and addresses are neutral:
  `example.internal`, `192.0.2.0/24`, `198.51.100.0/24`.
- **Not tried** marks a step written from documentation that has not been
  walked through on the real thing. Everything else ran, and the chapter
  says where (a container test in `t/e2e/` or a lab run).
- **Recommendation** marks a choice that is yours. It comes with the reason
  and the setting that changes it. The [decision table](01-planning.md#decisions-that-are-yours)
  collects them.
- Each chapter ends with a test report: what was run, with which versions,
  what was expected, what was observed, and what it does not cover.
