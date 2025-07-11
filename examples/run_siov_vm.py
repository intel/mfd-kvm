# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
import logging
from pathlib import Path
from uuid import uuid4

from mfd_connect import RPyCConnection
from mfd_typing import PCIAddress

from mfd_kvm import KVMHypervisor, VMParams

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

ip_config = Path("example_network_data_config.conf")

vm_ip, vm_mac = hv.get_free_network_data(config_file=ip_config, count=1)[0]
vm_name_to_use = hv.get_name_from_ip(vm_ip)

mdev_uuid = uuid4()

vm_config_dict = {
    "name": vm_name_to_use,
    "cpu_count": 2,
    "is_uefi_mode": True,
    "memory": 2048,
    "os_variant": "rhel8.1",
    "mac_address": vm_mac,
}
vm_config = VMParams(**vm_config_dict)

hv.create_mdev(
    mdev_uuid=mdev_uuid,
    pci_address=PCIAddress(0, 0, 0, 0),
    file_to_save="/home/user/mdev.xml",
)
# run VM
vm_name = hv.create_vm(vm_config)
# create RPyC
vm_conn = RPyCConnection(ip=str(vm_ip), retry_timeout=360)
logger.debug(vm_conn.get_os_name())

logger.debug(vm_conn.execute_command("ip a"))

hv.shutdown_vm(vm_name)
hv.destroy_mdev(mdev_uuid)
