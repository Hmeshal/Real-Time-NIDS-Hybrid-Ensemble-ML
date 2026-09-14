# PNETLab Platform Setup and Image Workflow

This document explains the platform-level workflow used to build and operate the PNETLab environment for the NIDS project. It covers installing PNETLab in VMware, remote administration with PuTTY/OpenSSH and WinSCP, importing the project lab, adding QEMU images, building a Linux node from an ISO installer, converting existing virtual disks, and starting nodes inside PNETLab.

> **Important distinction:** PNETLab itself is normally distributed as a VMware/virtualization appliance (`.ova`) and imported into VMware. It is **not normally converted to an ISO**. ISO files are used as installer media for guest operating systems that run *inside* PNETLab. When a guest is installed, its persistent disk is normally stored as a QEMU/QCOW2 image.

## 1. Tools Used

The project workflow can be reproduced with the following tools:

- **VMware Workstation / VMware Player** — runs the PNETLab virtual appliance.
- **Web browser** — opens the PNETLab GUI using the PNETLab VM IP address.
- **PuTTY** or the Windows `ssh` command — opens an SSH shell to the PNETLab server.
- **WinSCP** — transfers `.unl`, `.iso`, `.qcow2`, `.vmdk`, and other files using SFTP/SCP.
- **qemu-img** — creates and converts QEMU virtual disks on the PNETLab server.
- **PNETLab fixpermissions** — corrects ownership and permissions after manually copying labs or images.

## 2. Installing PNETLab in VMware

### 2.1 Download the PNETLab appliance

Download the current PNETLab appliance from the official PNETLab download page. The normal package is an **OVA appliance**.

### 2.2 Import the OVA into VMware

In VMware Workstation/Player:

1. Open VMware.
2. Choose **File > Open** (or **Open a Virtual Machine**).
3. Select the downloaded PNETLab `.ova` file.
4. Choose the VM name and storage location.
5. Import the appliance.

### 2.3 Enable nested virtualization

PNETLab runs QEMU virtual machines inside the PNETLab VM, so hardware-assisted virtualization must be exposed to it.

1. Power off the PNETLab VM.
2. Open **VM Settings > Processors**.
3. Enable the option equivalent to:
   - `Virtualize Intel VT-x/EPT`, or
   - `Virtualize AMD-V/RVI`.
4. Also make sure CPU virtualization is enabled in the host computer BIOS/UEFI.

If nested virtualization is not available, QEMU nodes may fail to start or immediately stop.

### 2.4 VM networking

A NAT or Bridged VMware adapter can be used. The main requirement is that the Windows host can reach the PNETLab management IP.

After booting PNETLab, complete its initial console setup and note its management IP address.

Typical management access is then:

```text
Browser -> https://<PNETLab-IP> or http://<PNETLab-IP>
SSH     -> root@<PNETLab-IP>
SFTP    -> root@<PNETLab-IP>
```

The exact login mode can differ between PNETLab versions. In this project, administrative shell access is used whenever files need to be copied or QEMU images need to be prepared.

## 3. PuTTY / SSH Access

### PuTTY

1. Open PuTTY.
2. Enter the PNETLab management IP.
3. Port: `22`.
4. Connection type: `SSH`.
5. Connect and log in with the PNETLab administrative account.

### Windows built-in SSH

From PowerShell or Command Prompt:

```bash
ssh root@<PNETLab-IP>
```

SSH is used for tasks such as:

```bash
ls /opt/unetlab/labs
ls /opt/unetlab/addons/qemu
qemu-img info <disk>
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

## 4. WinSCP / SFTP File Transfer

WinSCP is useful when copying large image files from Windows to the PNETLab VM.

Create a new WinSCP session:

```text
File protocol: SFTP
Host name:     <PNETLab-IP>
Port:          22
User:          root / administrative SSH user
```

Important PNETLab paths used by this project:

```text
/opt/unetlab/labs/                 Lab .unl files
/opt/unetlab/addons/qemu/          QEMU image folders
/opt/unetlab/tmp/                  Temporary running-node overlays
```

After manually uploading files, run:

```bash
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

This is an important final step because a correctly named image may still fail if its permissions are wrong.

## 5. Importing This Project Lab

The repository contains:

```text
pnetlab/lab/NIDS_Protected_LAN_CLEAN_ZONES.unl
```

Copy it to the PNETLab server:

```bash
cp NIDS_Protected_LAN_CLEAN_ZONES.unl /opt/unetlab/labs/
```

or upload it with WinSCP directly into:

```text
/opt/unetlab/labs/
```

Then run:

```bash
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

Open the PNETLab web interface and load the imported lab.

If a node displays **INVALID** for its image, the topology has been imported successfully but the matching device image is not installed on that PNETLab server yet.

## 6. Image Names Required by This Lab

The final `.unl` references these images/templates:

```text
OVS-SW01       pnetlab/openvswitch-ids:latest
IDS Sensor     linux-ubuntu-24.04-nids
WEB-SRV01      linux-ubuntu-server-24.04
CLIENT01       linux-ubuntu-mate-20.04
Attacker 1     linux-kali-2025.4
Attacker 2     linux-kali-2025.4
Attacker 3     linux-kali-2025.4
Attack Switch  viosl2-15.2.4.55e
```

The folder/template names must match what the `.unl` expects, or the node must be edited in the GUI to select an available equivalent image.

## 7. Building a Linux QEMU Node from an ISO

This is the workflow used for the Ubuntu Server target.

### 7.1 Create the QEMU image folder

Example:

```bash
mkdir -p /opt/unetlab/addons/qemu/linux-ubuntu-server-24.04
cd /opt/unetlab/addons/qemu/linux-ubuntu-server-24.04
```

### 7.2 Upload the installer ISO

Using WinSCP, upload the Ubuntu installer ISO into the image folder and name it:

```text
cdrom.iso
```

### 7.3 Create the persistent virtual disk

Example 12 GB QCOW2 disk:

```bash
qemu-img create -f qcow2 virtioa.qcow2 12G
```

Check it:

```bash
qemu-img info virtioa.qcow2
```

### 7.4 Fix permissions

```bash
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

### 7.5 Create and boot the node in PNETLab

1. In the web GUI, add a Linux/QEMU node that uses the image folder.
2. Start the node.
3. Open its console.
4. The VM should boot from `cdrom.iso`.
5. Install the operating system normally onto `virtioa.qcow2`.
6. Shut the guest down cleanly when installation finishes.

### 7.6 Save the installed state

PNETLab creates a writable overlay for a running QEMU node. The preferred method on supported versions is the GUI **Node Commit** function.

During this project's server build, the temporary overlay was identified under a path similar to:

```text
/opt/unetlab/tmp/<lab-id>/<node-id>/virtioa.qcow2
```

After verifying that the overlay had the expected backing file, it was committed into the base disk using `qemu-img commit`.

**Do not blindly copy a commit command between labs.** Verify the exact temporary path and backing file first:

```bash
qemu-img info /opt/unetlab/tmp/<lab-id>/<node-id>/virtioa.qcow2
```

Only then perform the intended commit or use the PNETLab Node Commit feature.

### 7.7 Remove installer media after installation

Once the VM boots successfully from its installed disk, disable the installer ISO. One simple method is to rename it:

```bash
mv cdrom.iso cdrom.iso.bak
```

Boot the node again and verify it starts from `virtioa.qcow2`. After verification, the backup installer can be removed if it is no longer required.

## 8. Converting an Existing VM Disk for PNETLab

A virtual machine does not normally need to be converted to an ISO. If you already have a VMware virtual disk, convert the **VMDK disk to QCOW2**.

Example:

```bash
qemu-img convert -p -f vmdk -O qcow2 source.vmdk virtioa.qcow2
```

Then place `virtioa.qcow2` inside the appropriate folder under:

```text
/opt/unetlab/addons/qemu/<image-folder>/
```

and run:

```bash
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

If the source is an `.ova`, an OVA is essentially an appliance archive containing files such as an OVF descriptor and one or more VMDK disks. Extract it first, identify the correct VMDK, then convert that disk to QCOW2.

Example extraction:

```bash
tar -xvf appliance.ova
```

Then convert the relevant `.vmdk` with `qemu-img convert`.

## 9. Starting Operating Systems Inside PNETLab

After the required image exists:

1. Open the lab in the browser.
2. Right-click a node and choose **Start**, or use **Start All Nodes**.
3. Wait for the node state to turn active.
4. Open the console by clicking/double-clicking the node.
5. Use HTML console or the native console method available on the workstation.

For this project, start order is not strict, but a practical order is:

```text
1. Attack-SW
2. OVS-SW01
3. WEB-SRV01
4. CLIENT01
5. IDS-SENSOR
6. Attackers
```

Then verify connectivity and start the IDS application.

## 10. Common Node-Start Problems

### Node starts and immediately stops

Check:

- image exists and is not marked INVALID;
- VMware nested virtualization is enabled;
- host BIOS/UEFI virtualization is enabled;
- image folder/file names match the expected PNETLab template;
- file permissions have been fixed.

Run:

```bash
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

### Image does not appear in the node image list

Check the directory name and expected file names under:

```bash
ls -lah /opt/unetlab/addons/qemu/
```

Then fix permissions and refresh the PNETLab browser.

### Lab imports but devices are INVALID

The `.unl` topology is present, but the exact referenced images are missing. Install the images listed in Section 6 or edit each node to use a compatible installed image.

## 11. Project-Specific Startup Checklist

After PNETLab itself is ready:

```text
[ ] Open NIDS_Protected_LAN_CLEAN_ZONES
[ ] All required images are valid
[ ] Start switches and hosts
[ ] Verify WEB-SRV01 = 10.20.20.10/24
[ ] Verify CLIENT01 = 10.20.20.20/24
[ ] Verify attackers = .5 / .6 / .7
[ ] Verify IDS ens3 has no IP and is UP/promiscuous
[ ] Verify OVS bridge br0 and ids-mirror
[ ] Verify CLIENT01 -> WEB-SRV01 ping/curl
[ ] Start app.py
[ ] Start sniffer.py ens3
[ ] Generate benign/attack traffic
[ ] Check sniffer output and dashboard
```

For project-specific node configuration, continue with `NODE_SETUP.md`. For OVS mirroring, see `OVS_SETUP.md`. For the validation commands and observed results, see `TESTING.md`.
