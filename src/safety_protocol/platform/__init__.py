# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Michael / TheDub-lab
"""
BSL platform layer — the hosted service, on-chain audit, and insurance
evidence stack.

Licensed under the Business Source License 1.1 (see LICENSE-BSL at the repo
root). You may use, copy, modify, and redistribute this code for any
non-production purpose and for production use that does not offer a
competing hosted/managed service to third parties, until the Change Date,
after which it converts to the Apache License, Version 2.0.

This package is intentionally NOT part of the ``safety-protocol`` wheel
published on PyPI. The wheel is the MIT SDK (enforcement engine + local
guard). This layer is distributed separately for self-hosting under BSL or
as a commercial license.
"""

from ..config import build_protocol_from_config
from .deployment import ReferenceDeployment
from .guard_service import GuardService
from .insurance import InsuranceInterface
from .onchain import OnChainBindingRegistry, OnChainBoundProtocol
from .onchain_audit import DualAudit, OnChainAudit

__all__ = [
    "GuardService",
    "build_protocol_from_config",
    "ReferenceDeployment",
    "InsuranceInterface",
    "OnChainBindingRegistry",
    "OnChainBoundProtocol",
    "OnChainAudit",
    "DualAudit",
]
