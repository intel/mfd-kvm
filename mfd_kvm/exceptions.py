# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Module for exceptions."""

from subprocess import CalledProcessError


class VirshNotAvailable(Exception):
    """Base Virsh exception."""


class KVMHypervisorException(Exception):
    """Handling module exception."""


class VirshException(CalledProcessError, KVMHypervisorException):
    """Handling virtualization tool module exception."""


class KVMHypervisorExecutionException(CalledProcessError, KVMHypervisorException):
    """Handling execution exceptions."""


class NotFoundInterfaceKVM(KVMHypervisorExecutionException):
    """Handle interface exceptions."""


class VMNotRunKVM(KVMHypervisorException):
    """Handle VM start exceptions."""


class VMMngIpNotAvailableKVM(KVMHypervisorException):
    """Handle VM management ip problems."""


class VFExceptionKVM(KVMHypervisorException):
    """Handle VF exceptions."""
