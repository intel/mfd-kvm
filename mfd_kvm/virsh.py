# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Module for managing VMs with virsh."""

import re
import logging
from time import sleep
from typing import Union, List, OrderedDict as OrderedDictType, Iterable, Dict
from mfd_common_libs import log_levels, add_logging_level, os_supported
from mfd_base_tool import ToolTemplate
from collections import OrderedDict
import xml.etree.ElementTree as ET

from ipaddress import IPv4Address

from mfd_kvm.exceptions import (
    VirshNotAvailable,
    VMNotRunKVM,
    VMMngIpNotAvailableKVM,
    VirshException,
)
from mfd_typing import OSName, MACAddress

logger = logging.getLogger(__name__)
add_logging_level(level_name="MODULE_DEBUG", level_value=log_levels.MODULE_DEBUG)

PERSISTENCE_MODES = {"config", "persistent", "current", ""}
VM_NET_TEMPLATE_DEST = "/usr/share/libvirt/networks/"
MAC_REGEX = "(([a-fA-F0-9]{2}[:|-]?){6})"


class VirshInterface(ToolTemplate):
    """Class implementation for virsh, a command line interface tool for managing guests and the hypervisor."""

    tool_executable_name = "virsh"

    __init__ = os_supported(OSName.LINUX)(ToolTemplate.__init__)

    def _get_tool_exec_factory(self) -> str:
        return self.tool_executable_name

    def check_if_available(self) -> None:
        """
        Check if tool is available in system.

        :raises VirshNotAvailable: when tool not available.
        """
        self._connection.execute_command(
            f"{self._tool_exec} -h",
            expected_return_codes={0},
            custom_exception=VirshNotAvailable,
        )

    def get_version(self) -> str:
        """
        Get version of tool.

        :return: Version of tool
        """
        version_out = self._connection.execute_command(f"{self._tool_exec} -v").stdout
        return version_out.strip()

    def execute_virsh_command(
        self,
        command: str,
        *,
        timeout: int = 120,
        expected_return_codes: Iterable = frozenset({0, 1}),
    ) -> (str, int):
        """
        Execute any command passed through command parameter with virsh.

        :param command: Command to execute using command line interface client tool.
        :param timeout: Maximum wait time for command to execute.
        :param expected_return_codes: Return codes to be considered acceptable
        :return: Command output for user to verify it.
        :raises: VirshException if command fails.
        """
        command = f"{self._tool_exec} {command}"
        output = self._connection.execute_command(
            command,
            timeout=timeout,
            expected_return_codes=expected_return_codes,
            custom_exception=VirshException,
        )
        return output.stdout, output.return_code

    def dump_xml_from_vm(self, host_name: str) -> Union[str, None]:
        """
        Output a guest's XML configuration file.

        :param host_name: Name of the host to get xml from.
        :return: string with xml content or None if fails.
        """
        command = f"dumpxml {host_name}"
        output, rc = self.execute_virsh_command(command)
        if rc != 0:
            logger.log(
                log_levels.MODULE_DEBUG,
                msg=f"Command {command} ended with code error: {rc}. Unable to fetch xml.",
            )
            return None
        logger.log(log_levels.MODULE_DEBUG, msg="XML dumped properly.")
        return output

    def detach_interface_from_vm(self, guest_name: str, mac: str) -> bool:
        """
        Detach a network interface from a guest.

        :param guest_name: guest to detach interface from.
        :param mac: mac of the interface.
        :return: True on success, False on fail.
        """
        command = f"detach-interface {guest_name} --type hostdev --mac {mac}"
        output, rc = self.execute_virsh_command(command)
        if rc != 0:
            logger.log(
                log_levels.MODULE_DEBUG,
                msg=f"Command {command} ended with code error: {rc}",
            )
            logger.info(msg=f"Output: {output}")
            return False
        logger.log(log_levels.MODULE_DEBUG, msg="Interface detached successfully.")
        return True

    def list_vms(self, all_vms: bool = True) -> List[OrderedDictType[str, str]]:
        """
        List virsh guests.

        :param all_vms: If true lists all VMs, even shutdown ones.
        :return: List of vm guests.
        """
        vm_list = []
        command = "list"
        if all_vms:
            command += " --all"
        output, rc = self.execute_virsh_command(command)
        if rc != 0:
            logger.log(
                log_levels.MODULE_DEBUG,
                msg=f"Command {command} ended with code error: {rc}.",
            )
        else:
            for match in re.finditer(r"(?P<id>[\d-]+) +(?P<name>\S+) +(?P<status>[\S ]+)", output):
                vm_list.append(
                    OrderedDict(
                        [
                            ("id", match.group("id")),
                            ("name", match.group("name")),
                            ("state", match.group("status").strip()),
                            ("mac", ""),
                        ]
                    )
                )
        return vm_list

    def get_mac_for_mng_vm_interface(self, guest_name: str) -> str:
        """
        Return MAC address of management interface for Virtual Machine.

        :param guest_name: Name of the virtual machine.
        :return: MAC address on success.
        :raises: VirshException if command fails or no match is found.
        """
        logger.log(
            log_levels.MODULE_DEBUG,
            msg=f"Read MAC address of management interface for VM: {guest_name}",
        )
        command = f"domiflist {guest_name}"
        output, _ = self.execute_virsh_command(command, expected_return_codes={0})

        match = re.search(MAC_REGEX, output)
        if match is not None:
            return match.group(1)
        raise VirshException

    def get_mng_ip_for_vm(self, mac: str, vm_id: str, tries: int = 300) -> Union[str, None]:
        """
        Get mng IP address for Virtual Machine.

        :param mac: MAC address of Virtual Machine management adapter.
        :param vm_id: ID of the VM.
        :param tries: tries to get IP address from VM.
        :return: None | mng IP for virtual machine.
        :raises VMNotRunKVM: when VM is still down after defined number of tries to get IP.
        :raises VMMngIpNotAvailableKVM: when VM is up but IP is unavailable.
        """
        logger.log(
            log_levels.MODULE_DEBUG,
            msg=f"Get management IP from QEMU agent which running on VM: {vm_id}",
        )
        command = f"domifaddr {vm_id} --source=agent"

        for it in range(1, tries + 1):
            sleep(1)  # Wait 1s between each attempt so VM has time to change states.
            output, rc = self.execute_virsh_command(command)
            if rc != 0:
                logger.log(
                    log_levels.MODULE_DEBUG,
                    msg=f"{it}/{tries} Getting management IP from QEMU agent failed",
                )
                if it == tries:  # last iteration
                    logger.log(
                        logging.WARNING,
                        msg="The most common problem is choosing the wrong VM boot option (uefi, legacy). "
                        "Please make sure that the choice is correct.",
                    )
                    raise VMNotRunKVM(f"VM was unable to boot after: {tries} retries!")
                continue

            regex = (
                rf"-\s+ipv\d\s+(?P<first_pattern_ip>(?:[0-9]{{1,3}}[\.]?){{4}})|"
                rf"{mac.lower()}\s+\w+\s+(?P<second_pattern_ip>(?:[0-9]{{1,3}}[\.]?){{4}})"
            )
            previous_line = ""
            for line in output.splitlines():
                match = re.search(regex, line)
                if match:
                    mac = mac.lower()
                    if mac in previous_line or mac in line.lower():
                        ip_first_pattern = match.group("first_pattern_ip")
                        ip_second_pattern = match.group("second_pattern_ip")
                        ip = ip_second_pattern if ip_first_pattern is None else ip_first_pattern
                        if IPv4Address(ip).is_link_local or IPv4Address(ip).is_loopback:
                            logger.log(
                                log_levels.MODULE_DEBUG,
                                msg=f"{it}/{tries} Found MNG IP: {ip} is local/loopback, trying again...",
                            )
                            continue
                        logger.log(
                            log_levels.MODULE_DEBUG,
                            msg=f"Mng IP: {ip} for MAC: {mac} found",
                        )
                        return ip
                previous_line = line.lower()
        raise VMMngIpNotAvailableKVM(f"VM is up but management IP is unavailable for MAC: {mac}!")

    def get_net_dhcp_leases(self, network: str = "default") -> str:
        """
        Return output of virsh net-dhcp-leases.

        :param network: Which network you want to get DHCP info of.
        :return: Output of the command.
        """
        logger.log(log_levels.MODULE_DEBUG, msg="Get net-dhcp-leases.")
        cmd_output, _ = self.execute_virsh_command(f"net-dhcp-leases {network}")
        return cmd_output

    def get_mng_ip_for_vm_using_dhcp(self, mac: "MACAddress", tries: int = 300) -> "IPv4Address":
        """
        Parse output of the virsh net-dhcp-leases to get ip address of specified MAC VM.

        :param mac: MAC used to specify VM.
        :param tries: How many attempts every 1s before giving up and raising VMMngIpNotAvailableKVM.
        :raises VMMngIpNotAvailableKVM: If function did not find correct ip.
        :return: IP address if found else raises VMMngIpNotAvailableKVM.
        """
        for i in range(tries):
            sleep(1)
            logger.info(f"Try({i}) to get VM IP address")
            try:
                dhcp_out = self.get_net_dhcp_leases()
                for line in dhcp_out.splitlines():
                    if str(mac).lower() in line.lower():
                        ip = line.split()[4].split("/")[0]
                        logger.debug(f"Found {ip} for {mac} address.")
                        return IPv4Address(ip)
            except VirshException:
                logger.debug("Could not get dhcp leases output.")

        raise VMMngIpNotAvailableKVM(f"VM is up but management IP is unavailable for MAC: {mac}!")

    def set_vcpus(self, vm_name: str, nr: int) -> None:
        """
        Change number of vCPUs.

        :param vm_name: name of VM
        :param nr: number of vCPUs
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg="Set number of vCPUs")
        command = f"setvcpus {vm_name} {nr} --config"
        self.execute_virsh_command(command, expected_return_codes={0})

    def set_vcpus_max_limit(self, vm_name: str, nr: int) -> None:
        """
        Change number of vCPUs.

        :param vm_name: name of VM
        :param nr: number of vCPUs
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg="Set maximum number of vCPUs")
        command = f"setvcpus {vm_name} {nr} --maximum --config"
        self.execute_virsh_command(command, expected_return_codes={0})

    def create_vm_network(self, xml_file: str) -> bool:
        """
        Create network for VM.

        :param xml_file: Name of template file.
        :return: True on success False on fail.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Create network from {xml_file}")
        command = f"net-create {VM_NET_TEMPLATE_DEST}{xml_file}"
        output, rc = self.execute_virsh_command(command)
        if rc != 0:
            logger.log(
                log_levels.MODULE_DEBUG,
                msg=f"Command {command} ended with code error: {rc}",
            )
            logger.info(msg=f"Output: {output}")
            return False
        return True

    def destroy_vm_network(self, net: str) -> bool:
        """
        Destroy VM network.

        :param net: Network name to destroy.
        :return: True on success False on fail.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Destroy network {net}")
        command = f"net-destroy {net}"
        output, rc = self.execute_virsh_command(command)
        if rc != 0:
            logger.log(
                log_levels.MODULE_DEBUG,
                msg=f"Command {command} ended with code error: {rc}",
            )
            logger.info(msg=f"Output: {output}")
            return False
        return True

    def get_vm_networks(self) -> list[str]:
        """
        Get what net networks exist on host.

        :return: List of networks.
        """
        logger.log(log_levels.MODULE_DEBUG, msg="List net networks.")
        output, rc = self.execute_virsh_command("net-list")
        if rc != 0:
            logger.log(
                log_levels.MODULE_DEBUG,
                msg=f"Command net-list ended with code error: {rc}",
            )
            logger.info(msg=f"Output: {output}")
            return []
        else:
            networks = []
            for line in output.splitlines()[2:]:
                networks.append(line.split()[0])
            return networks

    def attach_tap_interface_to_vm(
        self,
        vm_name: str,
        net: str,
        config: str = "live",
        interface_type: str = "network",
    ) -> bool:
        """
        Attach tap interface to VM.

        :param vm_name: Name of the VM.
        :param net: Network name to attach tap to.
        :param config: type of attachment
        :param interface_type: Interface type e.g. network / bridge.
        :return: True on success False on fail
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Attach tap interface to VM {vm_name}")
        cmd = (
            f"attach-interface --domain {vm_name} --type {interface_type} "
            f"--source {net} --model virtio --config --{config}"
        )
        output, rc = self.execute_virsh_command(cmd)
        if rc != 0:
            logger.log(
                log_levels.MODULE_DEBUG,
                msg=f"Command {cmd} ended with code error: {rc}",
            )
            logger.info(msg=f"Output: {output}")
            return False
        return True

    def get_vm_status(self, name: str) -> Dict[str, str]:
        """
        Get status of VM.

        :param name: Name of VM
        :return: Info about VM
        :raises: VirshException if command fails.
        """
        status = {}
        result, _ = self.execute_virsh_command(f"dominfo {name}", expected_return_codes={0})
        for line in result.splitlines():
            if ":" in line:
                # eg. Name : VM1
                data = line.split(":")
                if data:
                    # [0] = Name
                    # [1] = VM1
                    status[data[0]] = data[1].lstrip()
        return status

    def shutdown_gracefully_vm(self, name: str) -> None:
        """
        Gracefully shutdown VM.

        :param name: Name of VM
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Shutting down {name} VM.")
        self.execute_virsh_command(f"shutdown {name}", expected_return_codes={0})

    def reboot_vm(self, name: str) -> None:
        """
        Gracefully reboot VM.

        :param name: Name of VM
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Rebooting {name} VM.")
        self.execute_virsh_command(f"reboot {name}", expected_return_codes={0})

    def reset_vm(self, name: str) -> None:
        """
        Hard reset VM.

        :param name: Name of VM
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Resetting {name} VM.")
        self.execute_virsh_command(f"reset {name}", expected_return_codes={0})

    def shutdown_vm(self, name: str) -> None:
        """
        Hard shutdown VM.

        :param name: Name of VM
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Hard shutting down {name} VM.")
        self.execute_virsh_command(f"destroy {name}", expected_return_codes={0})

    def start_vm(self, name: str) -> None:
        """
        Start VM.

        :param name: Name of VM
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Starting {name} VM.")
        self.execute_virsh_command(f"start {name}", expected_return_codes={0})

    def delete_vm(self, name: str) -> None:
        """
        Delete VM. VM must be shutdown.

        :param name: Name of VM
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Deleting {name} VM.")
        self.execute_virsh_command(f"undefine --nvram {name}", expected_return_codes={0})

    def detach_device(self, *, name: str, device_config: str, status: str) -> None:
        """
        Detach device from VM via config xml of device.

        :param name: Name of VM
        :param device_config: Config file with VF
        :param status: Current VM status
        :raises: VirshException if command fails.
        """
        command = f"detach-device {name} --file {device_config}"
        if status == "shut off":
            self.execute_virsh_command(f"{command} --config", expected_return_codes={0})
        else:
            self.execute_virsh_command(command, expected_return_codes={0})

    def attach_device(self, name: str, device_config: str, status: str) -> None:
        """
        Attach device.

        :param name: Name of VM
        :param device_config: Config file with device
        :param status: Current VM status
        :raises: VirshException if command fails.
        """
        command = f"attach-device {name} --file {device_config}"
        if status == "shut off":
            self.execute_virsh_command(f"{command} --config", expected_return_codes={0})
        else:
            self.execute_virsh_command(command, expected_return_codes={0})

    def dump_xml(self, name: str) -> ET.ElementTree:
        """
        Dump xml.

        :param name: Name of VM
        :return: Parsed output from dumpxml command to xml.etree.ElementTree
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Dumping xml of {name}.")
        cmd_output, _ = self.execute_virsh_command(f"dumpxml --domain {name}", expected_return_codes={0})
        return ET.ElementTree(ET.fromstring(cmd_output))

    def define(self, xml_file: str) -> str:
        """
        Define VM using xml file.

        :param xml_file: Config file with VM
        :return: Command output for user to verify it.
        :raises: VirshException if command fails.
        """
        logger.log(log_levels.MODULE_DEBUG, msg=f"Creating VM using virsh define {xml_file}")
        cmd_output, _ = self.execute_virsh_command(command=f"define {xml_file}", expected_return_codes={0})
        return cmd_output
