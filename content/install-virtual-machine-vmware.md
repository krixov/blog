---
title: "Guide to Installing Virtual Machines with VMware Workstation/Fusion"
date: "2020-02-07"
excerpt: "How to install a virtual machine in VMware."
featured: "/images/cai-dat-may-ao-vm-ware/featured.png"
tags:
  - "Trick"
---

## **Guide to Installing Virtual Machines with VMware Workstation/Fusion**

### **1. Introduction**
Kali Linux is a Debian-based operating system designed for security testing and information security research. To run Kali Linux without affecting your main system, you can use virtualization software such as **VMware Workstation**, **VMware Fusion**, or **VirtualBox**.

![image](https://hackmd.io/_uploads/S1h55GQKJe.png)

This article guides you through installing **Windows 11** and **Kali Linux** on **VMware Workstation/Fusion**.

---

### **2. Install the Virtualization Software**
Before installing Kali Linux, you need a suitable virtualization tool. Below are the steps to download and install **VMware Workstation/Fusion**.

#### **2.1. For Windows and Linux (x86_64)**

##### **Download VMware Workstation Pro**
- Visit the download page:
  Link: [VMware Workstation Pro](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Workstation%20Pro)
- To download, you need a Broadcom account:
  1. Click the **triangle** icon in the top-right corner of the website.
  2. Select **Register** and follow the instructions to create an account.
- After registering, sign in to your Broadcom account.
- Return to the download page, pick the latest version, and click **Download**.

![image](https://hackmd.io/_uploads/SyGMnz7F1x.png)

- Check **"I agree to the Terms and Conditions"** before downloading.
- Run the installer and follow the prompts to complete the installation.

---

#### **2.2. For macOS (Intel and Apple Silicon) - Similar Steps**

##### **Download VMware Fusion**
- Visit the download page:
  Link: [VMware Fusion](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Fusion)
- Register a Broadcom account as above.
- After signing in, choose the latest **VMware Fusion** version and click **Download**.
- Check **"I agree to the Terms and Conditions"** before downloading.
- Open the `.dmg` file and drag **VMware Fusion** into **Applications** to install.
- Open the app and grant permissions if macOS asks.

---

#### **2.3. For Windows ARM64**
Currently, VMware does not officially support **Windows ARM64**. You can use **Hyper-V** instead.

##### **Check Whether Your System Supports Hyper-V**
Open **PowerShell** as Administrator and run:

```powershell
systeminfo | Select-String "Hyper-V Requirements"
```

If lines like "Virtualization Enabled In Firmware" and "Data Execution Prevention Available" show "No", your PC is not supported or needs to be enabled in UEFI.

##### **Install Hyper-V**
If your system supports Hyper-V, run:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
add-windowsfeature rsat-hyper-v-tools
```

Restart your computer after finishing.

---

### **3. Create a Windows 11 Virtual Machine**
Do not reuse an old VM to avoid errors. Install Windows 11 from scratch.

#### **Download Windows 11 Evaluation**
- **For x86_64**: [Windows 11 Enterprise Evaluation](https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise)
- **For ARM64 (Apple Silicon, Windows ARM)**: [Windows 11 IoT Enterprise LTSC](https://www.microsoft.com/evalcenter/evaluate-windows-11-iot-enterprise-ltsc)

- **Windows 11 ISO**: https://www.microsoft.com/en-us/software-download/windows11

Fill out the required information to download.

---

### **4. Install Kali Linux on VMware Workstation**
After installing VMware Workstation/Fusion:

1. **Download the Kali Linux ISO**
   - Visit the official site:
     Link: [Download Kali Linux](https://www.kali.org/get-kali/)

![image](https://hackmd.io/_uploads/B1DUuGmYyg.png)

![image](https://hackmd.io/_uploads/SJV6dfQtJe.png)

2. **Extract the virtual machine**
   - The VM is in 7z format, so you need [7z](https://www.7-zip.org/download.html) to extract it (on Linux, extract is usually available).

![image](https://hackmd.io/_uploads/HkHXYGQKyl.png)

3. **Open the VM**
   - Open **VMware Workstation/Fusion** and choose "Create a New Virtual Machine".

![image](https://hackmd.io/_uploads/ByJTtGmtkx.png)

![image](https://hackmd.io/_uploads/rkLeqfmY1g.png)

4. **Run the virtual machine**

![image](https://hackmd.io/_uploads/HkaMcGXF1g.png)

Click `Start up this...` to boot the VM. The default credentials are `kali` / `kali`.

---

### **5. Conclusion**
You have completed installing **Windows 11** or **Kali Linux** on **VMware Workstation/Fusion**. From here, you can start using Kali Linux for security testing or research.

Note: If you run into issues during installation, check the official documentation for **Kali Linux** and **VMware** for more help.
