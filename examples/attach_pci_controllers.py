# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
import logging


from mfd_connect import RPyCConnection

from mfd_kvm import KVMHypervisor

logger = logging.getLogger()


def set_up_logger():
    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(name)s" ": %(asctime)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)


set_up_logger()

hv_connection = RPyCConnection(ip="10.10.10.10")

hv = KVMHypervisor(connection=hv_connection)

hv.attach_pci_controllers(
    name="vm_name",
    number_of_devices=64,
    first_bus=0x00,
    first_func=0x01,
    first_port=0x01,
    first_slot=0x0,
    first_chassis=1,
    first_index=12,
)
