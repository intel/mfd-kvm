# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Test Virsh."""

import textwrap
from collections import OrderedDict
from xml.dom.minidom import parseString, Document
import xml.etree.ElementTree as ET

import pytest
from mfd_common_libs import log_levels
from mfd_connect import RPyCConnection
from mfd_connect.base import ConnectionCompletedProcess
from mfd_typing import OSName, MACAddress
from ipaddress import IPv4Address

from mfd_kvm.exceptions import (
    VMNotRunKVM,
    VMMngIpNotAvailableKVM,
    VirshException,
)
from mfd_kvm.virsh import VirshInterface


class TestVirsh:
    class_under_test = VirshInterface
    VM_NAME = "vm_name"
    NET_NAME = "net_name"
    XML_FILENAME = "xml_name"
    VIRT_XML_IFACE = "/root/templates/iface.xml"
    MAC = "00:00:AA:BB:CC:00"
    VM_LIST = [
        OrderedDict([("id", "0"), ("name", "Domain-0"), ("state", "running"), ("mac", "")]),
        OrderedDict([("id", "1"), ("name", "Domain202"), ("state", "paused"), ("mac", "")]),
    ]

    @pytest.fixture()
    def virsh_fixture(self, mocker):
        mocker.patch(
            "mfd_kvm.VirshInterface.check_if_available",
            mocker.create_autospec(VirshInterface.check_if_available),
        )
        mocker.patch(
            "mfd_kvm.VirshInterface.get_version",
            mocker.create_autospec(VirshInterface.get_version, return_value="1.1"),
        )
        mocker.patch(
            "mfd_kvm.VirshInterface._get_tool_exec_factory",
            mocker.create_autospec(VirshInterface._get_tool_exec_factory, return_value="virsh"),
        )
        connection = mocker.create_autospec(RPyCConnection)
        connection.get_os_name.return_value = OSName.LINUX
        virsh = VirshInterface(connection=connection)

        return virsh

    def test_dump_xml_from_vm_pass(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="<xml><tag1>content</tag1></xml>"
        )

        parsed = parseString(virsh_fixture.dump_xml_from_vm(self.VM_NAME))
        assert isinstance(parsed, Document)
        assert "XML dumped properly." in caplog.text

    def test_dump_xml_from_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=1, stdout="Some kind of error"
        )
        assert virsh_fixture.dump_xml_from_vm(self.VM_NAME) is None
        assert "Unable to fetch xml." in caplog.text

    def test_list_vms_pass(self, virsh_fixture):
        listed_vms = """\
        Id Name                 State
        ----------------------------------
        0 Domain-0             running
        1 Domain202            paused
        """
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(listed_vms)
        )
        assert virsh_fixture.list_vms(True) == self.VM_LIST

    def test_list_vms_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=1, stdout="Some kind of error"
        )
        virsh_fixture.list_vms(True)
        assert "ended with code error" in caplog.text

    def test__mng_mac_for_guest_found_mac(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        out = """\
        Interface  Type       Source     Model       MAC
        -------------------------------------------------------
        vnet0      bridge     br0        rtl8139     aa:bb:cc:de:ed:be
        """
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(out)
        )
        assert virsh_fixture.get_mac_for_mng_vm_interface(self.VM_NAME) == "aa:bb:cc:de:ed:be"
        assert f"Read MAC address of management interface for VM: {self.VM_NAME}" in caplog.text

    def test_get_guest_mng_ip_qemu_agent_not_installed(self, virsh_fixture, caplog, mocker):
        mocker.patch("mfd_kvm.virsh.sleep")
        caplog.set_level(log_levels.MODULE_DEBUG)

        output = """\
        error: Failed to query for interfaces addresses
        error: argument unsupported: QEMU guest agent is not configured
        """
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=1, stdout=textwrap.dedent(output)
        )
        tries = 3

        with pytest.raises(VMNotRunKVM, match=f"VM was unable to boot after: {tries} retries!"):
            virsh_fixture.get_mng_ip_for_vm(mac=self.MAC, vm_id=self.VM_NAME, tries=tries)

        assert "Get management IP from QEMU agent which running on VM" in caplog.text
        assert "3/3 Getting management IP from QEMU agent failed" in caplog.text
        assert "choosing the wrong VM boot option (uefi, legacy)." in caplog.text

    def test_get_guest_mng_ip_found(self, virsh_fixture, caplog, mocker):
        mocker.patch("mfd_kvm.virsh.sleep")
        caplog.set_level(log_levels.MODULE_DEBUG)
        output = """\
        Name       MAC address          Protocol     Address
        -------------------------------------------------------------------------------
        vnet0      aa:bb:cc:dd:ee:ff    ipv4         10.11.12.13/24
        """
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        assert virsh_fixture.get_mng_ip_for_vm(mac="AA:BB:CC:DD:EE:FF", vm_id=self.VM_NAME) == "10.11.12.13"

        assert "Get management IP from QEMU agent which running on VM" in caplog.text
        assert "Mng IP: 10.11.12.13 for MAC: aa:bb:cc:dd:ee:ff found" in caplog.text

    def test_get_guest_mng_ip_not_found_localhost(self, virsh_fixture, caplog, mocker):
        mocker.patch("mfd_kvm.virsh.sleep")
        caplog.set_level(log_levels.MODULE_DEBUG)
        output = """\
        Name MAC address Protocol Address
        -------------------------------------------------------------------------------
        lo 00:00:00:00:00:00 ipv4 127.0.0.1/8
        - - ipv6 ::1/128
        ens3 AA:BB:CC:DD:EE:FF N/A N/A
        """
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        mac = "AA:BB:CC:DD:EE:FF"
        with pytest.raises(
            VMMngIpNotAvailableKVM,
            match=f"VM is up but management IP is unavailable for MAC: {mac}!",
        ):
            virsh_fixture.get_mng_ip_for_vm(mac=mac, vm_id=self.VM_NAME)
        assert "Get management IP from QEMU agent which running on VM" in caplog.text

    def test_get_guest_mng_ip_found_windows(self, virsh_fixture, caplog, mocker):
        mocker.patch("mfd_kvm.virsh.sleep")
        caplog.set_level(log_levels.MODULE_DEBUG)
        output = """\
         Name       MAC address          Protocol     Address
         -------------------------------------------------------------------------------
         Ethernet   aa:bb:cc:dd:ee:ff    ipv6         fe80::7c30:fd51:5e7d:bfcc%12/-1
         -          -                    ipv4         10.11.12.13/24
         Loopback Pseudo-Interface 1                      ipv6         ::1/-1
         -          -                    ipv4         127.0.0.1/-1
         isatap.site.company.com 00:00:00:00:00:00    ipv6         fe80::5efe:10.91.5.238%13/-1
         Teredo Tunneling Pseudo-Interface 00:00:00:00:00:00    ipv6         fe80::100:7f:fffe%14/-1
         """
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        assert virsh_fixture.get_mng_ip_for_vm(mac="AA:BB:CC:DD:EE:FF", vm_id=self.VM_NAME) == "10.11.12.13"
        assert "Get management IP from QEMU agent which running on VM" in caplog.text
        assert "Mng IP: 10.11.12.13 for MAC: aa:bb:cc:dd:ee:ff found" in caplog.text

    def test_get_guest_mng_ip_not_first_record(self, virsh_fixture, caplog, mocker):
        mocker.patch("mfd_kvm.virsh.sleep")
        caplog.set_level(log_levels.MODULE_DEBUG)
        output = """\
        Name       MAC address          Protocol     Address
        -------------------------------------------------------------------------------
        Ethernet Instance 0 2 aa:bb:cc:dd:ee:ff    ipv6         fe80::24d8:647:b3ef:4586%6/64
        -          -                    ipv4         1.1.1.10/8
        Ethernet   52:54:00:de:ad:be    ipv6         fe80::d1fd:d6c8:ac8a:5c2b%8/64
        -          -                    ipv4         10.10.10.10/16
        Loopback Pseudo-Interface 1                      ipv6         ::1/128
        -          -                    ipv4         127.0.0.1/8
        """
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        assert virsh_fixture.get_mng_ip_for_vm(mac="52:54:00:DE:AD:BE", vm_id=self.VM_NAME) == "10.10.10.10"
        assert "Get management IP from QEMU agent which running on VM" in caplog.text
        assert "Mng IP: 10.10.10.10 for MAC: 52:54:00:de:ad:be found" in caplog.text

    def test_get_guest_mng_ip_local_found_windows(self, virsh_fixture, caplog, mocker):
        mocker.patch("mfd_kvm.virsh.sleep")
        caplog.set_level(log_levels.MODULE_DEBUG)
        output = """\
        Name       MAC address          Protocol     Address
        -------------------------------------------------------------------------------
        Ethernet   52:54:00:5b:da:c4    ipv6         fe80::650c:361:4b6:28c1%2/64
        -          -                    ipv4         169.254.40.193/16
        Loopback   Pseudo-Interface 1   ipv6         ::1/128
        -          -                    ipv4         127.0.0.1/8
        """
        number_of_tries = 10
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        mac = "52:54:00:5b:da:c4"
        with pytest.raises(
            VMMngIpNotAvailableKVM,
            match=f"VM is up but management IP is unavailable for MAC: {mac}!",
        ):
            virsh_fixture.get_mng_ip_for_vm(mac=mac, vm_id=self.VM_NAME, tries=number_of_tries)

        assert "Get management IP from QEMU agent which running on VM" in caplog.text
        assert f"{number_of_tries}/{number_of_tries} Found MNG IP: 169.254.40.193 is local/loopback," in caplog.text

    def test_get_net_dhcp_leases(self, virsh_fixture):
        output = """\
        Expiry Time          MAC address        Protocol  IP address               Hostname        Client ID or DUID
        -------------------------------------------------------------------------------------------------------------------
        2023-02-10 16:22:22  52:54:00:22:22:22  ipv4      192.168.1.11/24         Host1
        2012-05-10 16:22:22  52:54:00:33:33:33  ipv4      192.168.1.12/24         host2"""
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        assert virsh_fixture.get_net_dhcp_leases() == textwrap.dedent(output)

    def test_get_mng_ip_for_vm_using_dhcp(self, virsh_fixture, mocker):
        mocker.patch("mfd_kvm.virsh.sleep")
        output = """\
        Expiry Time          MAC address        Protocol  IP address               Hostname        Client ID or DUID
        -------------------------------------------------------------------------------------------------------------------
        2023-02-10 16:22:22  52:54:00:22:22:22  ipv4      192.168.1.11/24         Host1
        2012-05-10 16:22:22  52:54:00:33:33:33  ipv4      192.168.1.12/24         host2"""
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        out_ip = virsh_fixture.get_mng_ip_for_vm_using_dhcp(mac=MACAddress("52:54:00:22:22:22"))
        assert out_ip == IPv4Address("192.168.1.11")

    def test_set_vcpus(self, virsh_fixture):
        virsh_fixture.set_vcpus(self.VM_NAME, 16)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh setvcpus {self.VM_NAME} 16 --config",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )

    def test_set_vcpus_max_limit(self, virsh_fixture):
        virsh_fixture.set_vcpus_max_limit(self.VM_NAME, 16)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh setvcpus {self.VM_NAME} 16 --maximum --config",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )

    def test_create_vm_network_pass(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        assert virsh_fixture.create_vm_network(self.XML_FILENAME) is True
        assert f"Create network from {self.XML_FILENAME}" in caplog.text

    def test_create_vm_network_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=1, stdout="Error"
        )
        assert virsh_fixture.create_vm_network(self.XML_FILENAME) is False
        assert f"Create network from {self.XML_FILENAME}" in caplog.text
        assert "ended with code error" in caplog.text

    def test_destroy_vm_network_pass(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        assert virsh_fixture.destroy_vm_network(self.NET_NAME) is True
        assert f"Destroy network {self.NET_NAME}" in caplog.text

    def test_destroy_vm_network_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=1, stdout="Error"
        )
        assert virsh_fixture.destroy_vm_network(self.NET_NAME) is False
        assert f"Destroy network {self.NET_NAME}" in caplog.text
        assert "ended with code error" in caplog.text

    def test_get_vm_networks(self, virsh_fixture):
        output = """\
        Name      State    Autostart   Persistent
        --------------------------------------------
        default   active   yes         yes
        magic_network   active   yes         yes"""
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        assert virsh_fixture.get_vm_networks() == ["default", "magic_network"]

    def test_get_vm_networks_no_networks(self, virsh_fixture):
        output = """\
        Name      State    Autostart   Persistent
        --------------------------------------------"""
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=textwrap.dedent(output)
        )
        assert virsh_fixture.get_vm_networks() == []

    def test_get_vm_networks_fails(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=1, stdout="error"
        )
        virsh_fixture.get_vm_networks()
        assert "Command net-list ended with code error:" in caplog.text

    def test_attach_tap_interface_to_vm_pass(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        assert virsh_fixture.attach_tap_interface_to_vm(self.VM_NAME, self.NET_NAME) is True
        assert f"Attach tap interface to VM {self.VM_NAME}" in caplog.text

    def test_attach_tap_interface_to_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=1, stdout="Error"
        )
        assert virsh_fixture.attach_tap_interface_to_vm(self.VM_NAME, self.NET_NAME) is False
        assert f"Attach tap interface to VM {self.VM_NAME}" in caplog.text
        assert "ended with code error" in caplog.text

    def test_get_vm_status(self, virsh_fixture):
        expected_status = {
            "Id": "1",
            "Name": "foo-055-045",
            "UUID": "d08c195c-bddb-4fbb-b7aa-0fa10a96c5b1",
            "OS Type": "hvm",
            "State": "running",
            "CPU(s)": "2",
            "CPU time": "109.8s",
            "Max memory": "2097152 KiB",
            "Used memory": "2097152 KiB",
            "Persistent": "yes",
            "Autostart": "disable",
            "Managed save": "no",
            "Security model": "none",
            "Security DOI": "0",
        }
        output = textwrap.dedent(
            """\
        Id:             1
        Name:           foo-055-045
        UUID:           d08c195c-bddb-4fbb-b7aa-0fa10a96c5b1
        OS Type:        hvm
        State:          running
        CPU(s):         2
        CPU time:       109.8s
        Max memory:     2097152 KiB
        Used memory:    2097152 KiB
        Persistent:     yes
        Autostart:      disable
        Managed save:   no
        Security model: none
        Security DOI:   0"""
        )
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout=output, return_code=0
        )
        assert virsh_fixture.get_vm_status("foo-055-045") == expected_status

    def test_get_vm_status_error(self, virsh_fixture):
        error_msg = textwrap.dedent(
            """\
        error: failed to get domain 'foo-055-04'
        error: Domain not found: no domain with matching name 'foo-055-04'"""
        )
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, error_msg)
        with pytest.raises(VirshException):
            virsh_fixture.get_vm_status("foo-055-04")

    def test_shutdown_gracefully_vm(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.shutdown_gracefully_vm(self.VM_NAME)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh shutdown {self.VM_NAME}",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )
        assert f"Shutting down {self.VM_NAME}" in caplog.text

    def test_shutdown_gracefully_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "SomeVirshError")
        with pytest.raises(VirshException):
            virsh_fixture.shutdown_gracefully_vm(self.VM_NAME)
        assert f"Shutting down {self.VM_NAME}" in caplog.text

    def test_reboot_vm(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.reboot_vm(self.VM_NAME)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh reboot {self.VM_NAME}",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )
        assert f"Rebooting {self.VM_NAME}" in caplog.text

    def test_reboot_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "SomeVirshError")
        with pytest.raises(VirshException):
            virsh_fixture.reboot_vm(self.VM_NAME)
        assert f"Rebooting {self.VM_NAME}" in caplog.text

    def test_reset_vm(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.reset_vm(self.VM_NAME)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh reset {self.VM_NAME}",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )
        assert f"Resetting {self.VM_NAME}" in caplog.text

    def test_reset_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "SomeVirshError")
        with pytest.raises(VirshException):
            virsh_fixture.reset_vm(self.VM_NAME)
        assert f"Resetting {self.VM_NAME}" in caplog.text

    def test_shutdown_vm(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.shutdown_vm(self.VM_NAME)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh destroy {self.VM_NAME}",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )
        assert f"Hard shutting down {self.VM_NAME}" in caplog.text

    def test_shutdown_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "SomeVirshError")
        with pytest.raises(VirshException):
            virsh_fixture.shutdown_vm(self.VM_NAME)
        assert f"Hard shutting down {self.VM_NAME}" in caplog.text

    def test_start_vm(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.start_vm(self.VM_NAME)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh start {self.VM_NAME}",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )
        assert f"Starting {self.VM_NAME}" in caplog.text

    def test_start_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "SomeVirshError")
        with pytest.raises(VirshException):
            virsh_fixture.start_vm(self.VM_NAME)
        assert f"Starting {self.VM_NAME}" in caplog.text

    def test_delete_vm(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.delete_vm(self.VM_NAME)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            f"virsh undefine --nvram {self.VM_NAME}",
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )
        assert f"Deleting {self.VM_NAME}" in caplog.text

    def test_delete_vm_fail(self, virsh_fixture, caplog):
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "SomeVirshError")
        with pytest.raises(VirshException):
            virsh_fixture.delete_vm(self.VM_NAME)
        assert f"Deleting {self.VM_NAME}" in caplog.text

    @pytest.mark.parametrize("state", ["shut off", "running"])
    def test_detach_device(self, virsh_fixture, caplog, state):
        dev_path = "/path/path2"
        command = f"virsh detach-device {self.VM_NAME} --file {dev_path}"
        if state != "running":
            command += " --config"
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.detach_device(name=self.VM_NAME, device_config=dev_path, status=state)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            command,
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )

    def test_detach_device_fail(self, virsh_fixture, caplog):
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "VirshError")
        with pytest.raises(VirshException):
            virsh_fixture.detach_device(name=self.VM_NAME, device_config="/path/path2", status="running")

    @pytest.mark.parametrize("state", ["shut off", "running"])
    def test_attach_device(self, virsh_fixture, caplog, state):
        dev_path = "/path/path2"
        command = f"virsh attach-device {self.VM_NAME} --file {dev_path}"
        if state != "running":
            command += " --config"
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout="OK"
        )
        virsh_fixture.attach_device(name=self.VM_NAME, device_config=dev_path, status=state)
        virsh_fixture._connection.execute_command.assert_called_once_with(
            command,
            custom_exception=VirshException,
            expected_return_codes={0},
            timeout=120,
        )

    def test_attach_device_fail(self, virsh_fixture, caplog):
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, "VirshError")
        with pytest.raises(VirshException):
            virsh_fixture.attach_device(name=self.VM_NAME, device_config="/path/path2", status="running")

    def test_dump_xml(self, virsh_fixture, caplog):
        output = textwrap.dedent(
            """\
        <domain type='kvm' id='1'>
            <interface type='hostdev' managed='yes'>
                <mac address='aa:bb:cc:de:ed:be'/>
                <driver name='vfio'/>
                <source>
                    <address type='pci' domain='0x0000' bus='0x5e' slot='0x11' function='0x1'/>
                </source>
                <link state='up'/>
                <alias name='hostdev1'/>
                <address type='pci' domain='0x0000' bus='0x00' slot='0x08' function='0x0'/>
            </interface>
        </domain>"""
        )
        caplog.set_level(log_levels.MODULE_DEBUG)
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", return_code=0, stdout=output
        )
        assert isinstance(virsh_fixture.dump_xml(self.VM_NAME), ET.ElementTree)
        assert f"Dumping xml of {self.VM_NAME}." in caplog.text

    def test_define(self, virsh_fixture):
        xml_file = "vm.xml"
        output = textwrap.dedent(
            """\
            Domain KVM_VM_0 defined from /tmp/KVM_VM_0.xml"""
        )
        virsh_fixture._connection.execute_command.return_value = ConnectionCompletedProcess(
            args="", stdout=output, return_code=0
        )
        assert virsh_fixture.define(xml_file) == output

    def test_define_fail(self, virsh_fixture):
        xml_file = "vm.xml"
        error_msg = textwrap.dedent(
            """\
        error: Failed to define domain from /tmp/KVM_VM_0.xml
        error: Failed to open file '/tmp/KVM_VM_01.xml': No such file or directory"""
        )
        virsh_fixture._connection.execute_command.side_effect = VirshException(1, error_msg)
        with pytest.raises(VirshException):
            virsh_fixture.define(xml_file)
