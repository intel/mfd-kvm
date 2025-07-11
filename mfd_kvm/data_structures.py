# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Data structures for MFD-KVM."""

from dataclasses import dataclass

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mfd_typing.mac_address import MACAddress


@dataclass
class VFDetail:
    """VF Details."""

    id: int  # noqa: A003
    mac_address: "MACAddress"
    spoofchk: bool
    trust: bool
