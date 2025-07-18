> [!IMPORTANT] 
> This project is under development. All source code and features on the main branch are for the purpose of testing or evaluation and not production ready.

# MFD KVM
Module for managing KVM hypervisors, enabling VM creation, control, and network device management.

## Structures
`VMParams` is dataclass for handling configuration of future VM.

Params:

* `name`: Name of VM, default `vm`
* `is_uefi_mode`: Determine UEFI Boot mode, default `True`, otherwise BIOS mode
* `cpu_count`: Count of CPUs, default `2`
* `memory`: Memory value in MB, default `1024`
* `mac_address`: Mac address of main adapter, default `00:00:00:00:00:00`
* `machine`: Emulation machine, eg. pc or q35, chipset, default `pc`
* `bridge_name`: Name of bridge interface, default `br0`
* `clone_disk`: Determine whether disk image should be copied or not, default `True`
* `threads`: Determine number of threads, If value is omitted, the rest will be autofilled preferring sockets over cores over threads.
* `disk`: Disk of VM, default, disk will be not created, size of disk(in GB) or path
* `target_hd_clone_disk`: Target location for disk images clones
* `os_variant`: Future OS, for optimization VM by HV
* `boot_order`: Order for booting process (in qemu format, eg. 'network,hdd') [docs](https://www.systutorials.com/docs/linux/man/1-virt-install/)
* `clone_timeout`: Optional timeout for cloning disk image
* `graphics`: Specifies the graphical display configuration. Default '--graphics none' will be set. Check --graphics in virt-install for available options.
* `cpu`: CPU model and CPU features exposed to the guest
* `osinfo_detect`: Whether virt-install should attempt OS detection.
* `osinfo_require`: If `True`, virt-install will raise error if no OS detected. In 2022 fatal error was added - more info [virt-install man](https://github.com/virt-manager/virt-manager/blob/main/man/virt-install.rst#--os-variant---osinfo)
* `add_pci_controller`: When set this option and is_uefi_mode to true then pci controllers will be added to the VM, by default set to False
* `vm_xml_file`: When set VM is created using 'virsh define vm_xml_file', used when virt-install is not available

IP / MAC configs:

Config require `[kvm]` header and IP with MAC separated by space
eg.
```
[kvm]
10.10.10.10 AA:BB:CC:DD:EE:FF
```
___
`KVMHypervisor` is a class handling general KVM hypervisor tasks.
___
`VirshInterface` is a mfd_tool expansion created to handle virsh commands.
## Usage

Params:

We can create `VMParams` as arguments:

```python
VMParams(name='our_name', cpu_count=8) # etc
``` 

We can create `VMParams` from dictionary:
```python
vm_config_dict = {'name': 'our_name',
                  'cpu_count': 2,
                  'is_uefi_mode': False,
                  'memory': 2048,
                  'disk': 2,
                  'os_variant': 'rhel8.1'}
vm_config = VMParams(**vm_config_dict)
```
___
`KVMHypervisor` require only connection from `mfd-connect`
```python
hv_connection = RPyCConnection(ip='10.10.10.10')

hv = KVMHypervisor(connection=hv_connection)
```
___
`VirshInterface` require only connection from `mfd-connect`
```python
virsh_connection = RPyCConnection(ip='10.10.10.10')

VirshInterface(connection=virsh_connection)
```


## Methods
`KVMHypervisor` methods:
* `get_name_from_ip(ip: IPAddress, prefix: str) -> str` - returns generated name from IP and prefix(default `foo`), eg. `foo-010-130` for `10.10.10.130`
* `get_free_network_data(configconfig_file: Path, count: int) -> List[Tuple[IPAddress, MACAddress]]` - returns list of given count free IP,MAC tuples for future usage.
* `create_vm(params: VMParams) -> str` - starts VM with given params, returns name of vm.
* `create_vm_from_xml(params: VMParams) -> str` - starts VM defined using predefined xml file, returns name of vm.
* `define_vm(xml_file: str) -> None` - defines VM using predefined xml file.
* `create_multiple_vms(count: int = 2, params: VMParams, config, prefix: str) -> -> List[Tuple[str, IPAddress]]` - starts multiple vms with the same configuration, returns list of tuples (name, IP) of vm.
* `get_list_of_vms() -> List[str]` - Returns list of vm names on hypervisor.
* `get_vm_status(name: str) -> Dict[str, str]` - returns details of vm as dictionary.
* `shutdown_gracefully_vm(name: str)` - Gracefully shutdown VM by calling virtualization tool.
* `reboot_vm(name: str) -> None` - Gracefully reboot VM by calling virtualization tool.
* `reset_vm(name: str) -> None` - Gard reset VM by calling virtualization tool.
* `shutdown_vm(name: str) -> None` - Gard shutdown VM by calling virtualization tool.
* `start_vm(name: str) -> None` - Start VM by calling virtualization tool.
* `delete_vm(name: str) -> None` - Delete VM by calling virtualization tool.
* `wait_for_vm_state(name: str, state: str, timeout: int = 60) -> bool` - Wait for supplemented VM state
* `wait_for_vm_down(vm_id: str, timeout: int = 120) -> bool` - Wait for VM to be in shutdown state
* `wait_for_vm_up(name: str, timeout: int = 120) -> bool` Wait for VM to be in running state
* `stop_all_vms(force: bool = False) -> bool` - Force or gracefully shutdown all VMs
* `start_all_vms() -> bool` - Start all VMs
* `get_vfs_id_for_pf(interface: str) -> List[int]` - get list of VFs id for interface PF using /sys/class/net/interface_name
* `get_pci_address_for_vf(interface: str, vf_id: int) -> PCIAddress` - Get pci address of VF using /sys/class/net/interface_name
* `get_pci_address_for_vf_by_pci(pf_pci_address: PCIAddress, vf_id: int) -> PCIAddress` - Get pci address of VF using /sys/bus/pci/devices/pci_address.
* `is_vf_attached(self, *, interface: str, vf_id: int) -> bool` - determine whether VF interface is attached to a VM (pci passthrough) or not.
* `set_number_of_vfs_for_pf(interface: str, vfs_count: int, check: bool, timeout: int = 60)` - Assign VFs for PF (interface) using /sys/class/net/interface_name/device/sriov_numvfs.
* `check_number_of_vfs(interface: str, vfs_count: int)` - Check if number of vfs is correct using /sys/class/net/interface_name.
* `prepare_vf_xml(template_path: str/Path, file_to_save: str, pci_address: PCIAddress) -> Union[str, Path]` - create VF configuration from template via PCIAddress
* `detach_vf(name: str, vf_config: str)` - Detach VF using path to a config file.
* `detach_device(name: str, device_config: str)` - Detach device using path to a config file
* `attach_vf(name: str, vf_config: str)` - attach VF config as file to VM.
* `attach_agent(name: str, agent_config_file: str)` - attach agent to VM.
* `attach_device(name: str, device_config: str)` - attach device config as file to VM.
* `clone_vm_hdd_image(self, *, path_to_source_image: Union[str, Path], new_name: str, timeout: int=1000)` - clone hdd image with new name with timeout and returns path for cloned image
* `create_mdev(mdev_uuid: Union[str, "UUID"], pci_address: "PCIAddress", template_path: Union[Path, str], file_to_save: str)` - create mediated device and generate XML file for mdev
* `destroy_mdev(mdev_uuid: Union[str, "UUID"])` - destroy mediated device
* `get_hdd_path(name: str) -> Path` -  get path of used disk image
* `dump_xml(name: str) -> ET.ElementTree:` dump xml
* `get_pci_for_host_vf_and_vm_vf(name: str) -> List[Tuple[PCIAddress, PCIAddress]]:` - get PCIs for Host VF and correlated VM VF
* `get_pci_addresses_of_vfs(interface: str) -> List[PCIAddress]` - Get pci address of all VFs created on host using /sys/class/net/interface_name.
* `get_pci_addresses_of_vfs_by_pci(pci_address: PCIAddress) -> List[PCIAddress]` - Get pci address of all VFs created on host using /sys/bus/pci/devices/pci_address.
* `get_vf_id_from_pci(interface: str, pci: PCIAddress) -> int` - Get ID of VF with the given PCI address on specific PF PCI address using /sys/class/net/interface_name.
* `get_vf_id_by_pci(pf_pci_address: PCIAddress, vf_pci_address: PCIAddress) -> int:` - Get ID of VF with the given PCI address on specific PF PCI address using /sys/bus/pci/devices/pci_address.
* `get_vfs_details_from_interface(interface_name: str) -> List[VFDetail]` - get list of VFDetail objects
* `get_vf_id_from_mac_address(interface_name: str, mac_address: MACAddress) -> int` - get VF ID based on provided PF interface name and MAC Address
* `create_bridge(bridge_name: str) -> None` - add new bridge to the system
* `delete_bridge(bridge_name: str) -> None` - delete bridge from the system
* `add_interface_to_bridge(bridge_name: str, interface: str) -> None` - aonnect interface to bridge
* `detach_interfaces(vm_names_list: List[str]) -> None` - detach interfaces from given VMs
* `get_dynamic_ram(vm_number: int, vm_min_ram: int = 2000, vm_max_ram: Optional[int] = 10000, reserved_memory: Optional = 10000) -> int` - get calculated RAM per vm based on available memory and vm number
* `get_mdev_details(name: str) -> List[Tuple[PCIAddress, PCIAddress]]` - get UUID of MDEV and correlated VM VF
* `get_pci_address_of_mdev_pf(mdev_uuid: Union[str, "UUID"]) -> PCIAddress` - get PCI address of mediated device PF
* `get_all_mdev_uuids(self) -> List[str]` - get all MDEV UUIDs
* `attach_pci_controllers(name: str, number_of_devices: int, first_index: int, first_chassis: int, first_port: hex, first_bus: hex,
   first_slot: hex, first_func: hex) -> None` - attach PCI Controller to VM, number of devices is pointed out by `number_of_devices` variable
* `dump_xml_from_vm(host_name: str) -> Union[str, None]` - Dumps XML config from specified host in str format
* `detach_interface_from_vm(guest_name: str, mac: str) -> bool` - Detach an interface from guest using specified MAC address
* `list_vms(all_vms: bool = True) -> List[OrderedDictType[str, str]]` - List VMs as a list of dictionaries with Status, Name, ID
* `get_mac_for_mng_vm_interface(guest_name: str) -> str` - Get management interface MAC address
* `get_mng_ip_for_vm(mac: str, vm_id: str, tries: int = 300) -> str` - Get management interface IP address using MAC and VM ID
* `get_guest_mng_ip(vm_id: str, timeout: int = 300) -> str` - Get guest management interface IP.
* `set_vcpus(self, vm_name: str, nr: int) -> None` - Set VM processors to specified value
* `set_vcpus_max_limit(vm_name: str, nr: int) -> None` - Change maximum possible vCPU setting.
* `create_vm_network(xml_file: str) -> bool` - Create VM network using XML file config
* `destroy_vm_network(net: str) -> bool` - Destroy VM network using XML file config
* `attach_tap_interface_to_vm(vm_name: str, net: str, config: str = "live", interface_type: str = "network") -> bool` - Attach tap device to VM
* `attach_interface(guest_name: str, pci_address: PCIAddress) -> None` - Attach interface specified by PCI address by automatically creating XML config and attaching it to a VM
* `detach_interface(guest_name: str, pci_address: PCIAddress) -> None`- Detach interface specified by PCI address by automatically creating XML config and detaching it from a VM
* `set_vcpus_max_limit(vm_name: str, nr: int) -> None` - Change maximum possible vCPU setting.

`VirshInterface` methods:
* `_get_tool_exec_factory() -> str` - Returns virsh tool name.
* `check_if_available() -> None` - Checks if virsh is available on the platform otherwise returns `VirshNotAvailable` exception.
* `get_version() -> str` - Returns virsh version.
* `execute_virsh_command(command: str, *, timeout: int = 120, expected_return_codes: Iterable = frozenset({0, 1})) -> (str, int)` - Base function to execute any virsh commands. Returns function output and rc code. In case of errors returns custom VirshException
* `dump_xml_from_vm(host_name: str) -> Union[str, None]` - Returns VM XML configuration file or None if not found. 
* `detach_interface_from_vm(guest_name: str, mac: str) -> bool` - Detach network interface from VM using specified MAC. Returns True if no errors happened else False.
* `list_vms(all_vms: bool = True) -> List[OrderedDictType[str, str]]` - List VMs as a dictionary with VM: id, name, state and mac. Lists only running VMs unless specified.
* `get_mac_for_mng_vm_interface(guest_name: str) -> str` - Using domiflist find and return MAC address of management interface of VM.
* `get_mng_ip_for_vm(mac: str, vm_id: str, tries: int = 300) -> Union[str, None]:` - Using quemu agent try to find non-local, non loopback management ip address of VM.
* `get_net_dhcp_leases(network="default"):` - Return output of virsh net-dhcp-leases
* `get_mng_ip_for_vm_using_dhcp(mac: "MACAddress", tries: int = 300) -> Union[IPv4Address, None]:`
* `set_vcpus(vm_name: str, nr: int) -> None:` - Change vCPU number of the VM.
* `set_vcpus_max_limit(vm_name: str, nr: int) -> None` - Change maximum possible vCPU setting.
* `create_vm_network(xml_file: str) -> bool:` - Using supplemented XML template create VM network. Returns true on success False on fail.
* `destroy_vm_network(net: str) -> bool:` - Using network name destroy VM network. Returns true on success False on fail.
* `get_vm_networks() -> list[str]:` - Get what net networks exist on host.
* `attach_tap_interface_to_vm(vm_name: str, net: str, config: str = "live", interface_type: str = "network") -> bool:` - Attach tap interface to specified VM. Accepted interface types: .ridge, network. Returns true on success False on fail.
* `get_vm_status(name: str) -> Dict[str, str]` - Using virsh dominfo return dictionary of VM Status, ID, Name
* `shutdown_gracefully_vm(name: str) -> None:` - Shutdown VM using virsh shutdown.
* `reboot_vm(name: str) -> None:` - Reboot VM using virsh reboot.
* `reset_vm(name: str) -> None:` - Hard reset VM using virsh reset.
* `shutdown_vm(name: str) -> None:` - Hard shutdown VM using virsh destroy.
* `start_vm(name: str) -> None` - Start VM using virsh start.
* `delete_vm(name: str) -> None` - Delete VM by using virsh undefine.
* `detach_device(*, name: str, device_config: str, status: str) -> None` - Detach device from VM using passed XML config.
* `attach_device(name: str, device_config: str, status: str) -> None` - Attach device to VM using passed XML as a config.
* `dump_xml(name: str) -> ET.ElementTree` - Dump VM XML config and return it as a ElementTree XML.
* `define(xml_file: str) -> str` - Define VM using xml file. Returns command output for user to verify it.

## VFDetail

Structure representing basic details about VFs: 
- VF ID
- MAC Address 
- Spoof check setting
- Trust setting

```python
@dataclass
class VFDetail:
    """VF Details."""

    id: int  # noqa: A003
    mac_address: "MACAddress"
    spoofchk: bool
    trust: bool
```

## OS supported:
* LINUX

## Issue reporting

If you encounter any bugs or have suggestions for improvements, you're welcome to contribute directly or open an issue [here](https://github.com/intel/mfd-kvm/issues).