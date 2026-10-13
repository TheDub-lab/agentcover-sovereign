# Licensing

`safety-protocol` is **open core**. The enforcement SDK is free (MIT); the
hostable service and the audit/evidence platform layer are source-available
under the Business Source License 1.1 (BSL).

This is deliberate: you can embed and run the guard for free, but you cannot
stand up a competing hosted version of the platform layer without a commercial
license from the Licensor.

## What is under which license

| Path | License | SPDX |
| --- | --- | --- |
| `src/safety_protocol/core.py` | MIT | `MIT` |
| `src/safety_protocol/protocol.py` | MIT | `MIT` |
| `src/safety_protocol/scope_linter.py` | MIT | `MIT` |
| `src/safety_protocol/payments.py` | MIT | `MIT` |
| `src/safety_protocol/real_wallet.py` | MIT | `MIT` |
| `src/safety_protocol/onchain_payment_verifier.py` | MIT | `MIT` |
| `src/safety_protocol/config.py` | MIT | `MIT` |
| `src/safety_protocol/cli.py` | MIT | `MIT` |
| `src/safety_protocol/data/**` | MIT | `MIT` |
| `src/safety_protocol/platform/**` | BSL 1.1 | `BUSL-1.1` |

Every source file carries an `SPDX-License-Identifier` header naming its
license. The header is authoritative for that file.

### MIT — the SDK (free)

The enforcement engine and everything you embed in your own agent:

- `core.py` — scope rules, action model, audit trail, monitor
- `protocol.py` — the enforcement layer and `BoundAgent`
- `scope_linter.py` — fail-closed rule linting
- `payments.py`, `real_wallet.py`, `onchain_payment_verifier.py` — the x402 /
  USDC spend guard
- `config.py` — user config -> protocol builder
- `cli.py` — `safety-guard init | check | lint | pay`

The `safety-protocol` wheel published on PyPI contains **only this MIT code**.

### BSL 1.1 — the platform layer (source-available)

`src/safety_protocol/platform/` — the hostable service and the logging /
evidence stack:

- `guard_service.py` — the HTTP guard service you host (including `GET /audit`)
- `onchain.py` — on-chain binding (ERC-5192 / ERC-8004 style)
- `onchain_audit.py` — on-chain audit + dual (on/off-chain) audit
- `insurance.py` — claims evidence + underwriter reporting
- `deployment.py` — the full reference deployment wiring the layers together

Under the BSL 1.1 Additional Use Grant you may self-host this for your own
agents and internal production use. You may **not** offer it to third parties
as a hosted or managed service whose primary purpose is to provide its
functionality. The license converts to Apache-2.0 on the Change Date
(2030-10-13).

See [`LICENSE-BSL`](LICENSE-BSL) for the full terms and parameters.

## Commercial licensing

To run a hosted / managed offering of the platform layer, or to use it outside
the Additional Use Grant, contact the Licensor for a commercial license:

**Michael / TheDub-lab** — `thislife1made@gmail.com`

## Notes

- The platform layer is **not** packaged in the published PyPI wheel, because
  BSL is not an SPDX-recognized license id and the wheel's metadata declares
  `MIT`. Distributing it as a separate install keeps the metadata accurate.
- Published versions **0.1.0 – 0.3.0** of `safety-protocol` were released wholly
  under MIT. That grant is irrevocable for those versions. The MIT/BSL split
  applies to this source tree and to future releases.
- Contributions: since the project is dual-licensed, contributions to the
  platform layer require a contributor license agreement so the Licensor can
  keep offering commercial licenses. Contributions to the MIT SDK do not.
