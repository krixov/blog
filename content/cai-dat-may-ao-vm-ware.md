---
title: "Hướng Dẫn Cài Đặt máy ảo sử dụng VMware Workstation/Fusion"
date: "2020-02-07"
excerpt: "Cách cài đặt máy ảo trong VMware!"
featured: "/images/cai-dat-may-ao-vm-ware/featured.png"
tags:
  - "Trick"
---

## **Hướng Dẫn Cài Đặt máy ảo sử dụng VMware Workstation/Fusion**

### **1. Giới Thiệu**  
Kali Linux là một hệ điều hành dựa trên Debian, được thiết kế cho kiểm thử bảo mật và nghiên cứu an toàn thông tin. Để chạy Kali Linux mà không ảnh hưởng đến hệ thống chính, bạn có thể sử dụng các trình ảo hóa như **VMware Workstation**, **VMware Fusion**, hoặc **VirtualBox**.  

![image](https://hackmd.io/_uploads/S1h55GQKJe.png)


Bài viết này hướng dẫn cài đặt **Windows 11** và **Kali Linux** trên **VMware Workstation/Fusion**.  

---

### **2. Cài Đặt Trình Ảo Hóa**  
Trước khi cài Kali Linux, bạn cần cài đặt một trình ảo hóa phù hợp. Dưới đây là các bước tải xuống và cài đặt **VMware Workstation/Fusion**.

#### **2.1. Đối với Windows và Linux (x86_64)**  

##### **Tải Xuống VMware Workstation Pro**  
- Truy cập đường dẫn tải xuống:  
  🔗 [VMware Workstation Pro](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Workstation%20Pro)
- Để tải về, bạn cần đăng ký tài khoản Broadcom:
  1. Nhấn vào biểu tượng **tam giác** ở góc trên bên phải của trang web.
  2. Chọn **Register** và làm theo hướng dẫn để tạo tài khoản.
- Sau khi đăng ký, đăng nhập vào tài khoản Broadcom.
- Lại nhấn vào link trang tải xuống, chọn phiên bản mới nhất và nhấn **Download**.

![image](https://hackmd.io/_uploads/SyGMnz7F1x.png)


- Đánh dấu vào tùy chọn **"I agree to the Terms and Conditions"** trước khi tải về.
- Chạy trình cài đặt và làm theo hướng dẫn để hoàn tất cài đặt.

---

#### **2.2. Đối với macOS (Intel & Apple Silicon) - Tương tự**  

##### **Tải Xuống VMware Fusion**  
- Truy cập đường dẫn tải xuống:  
  🔗 [VMware Fusion](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Fusion)
- Đăng ký tài khoản Broadcom tương tự như trên.
- Sau khi đăng nhập, chọn phiên bản **VMware Fusion** mới nhất và nhấn **Download**.
- Đánh dấu vào tùy chọn **"I agree to the Terms and Conditions"** trước khi tải về.
- Mở file `.dmg`, kéo biểu tượng **VMware Fusion** vào thư mục **Applications** để cài đặt.
- Mở ứng dụng và cấp quyền nếu macOS yêu cầu.

---

#### **2.3. Đối với Windows ARM64**  
Hiện tại, VMware chưa hỗ trợ chính thức trên **Windows ARM64**. Bạn có thể sử dụng **Hyper-V** thay thế.

##### **Kiểm Tra Hệ Thống Có Hỗ Trợ Hyper-V Không?**  
Mở **PowerShell** với quyền Administrator và chạy lệnh:

```powershell
systeminfo | Select-String "Hyper-V Requirements"
```

Nếu các dòng như "Virtualization Enabled In Firmware" và "Data Execution Prevention Available" có giá trị "No", thì PC của bạn không hỗ trợ hoặc cần bật trong UEFI.

##### **Cài Đặt Hyper-V**  
Nếu hệ thống hỗ trợ Hyper-V, chạy lệnh sau để cài đặt:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
add-windowsfeature rsat-hyper-v-tools
```

Khởi động lại máy tính sau khi hoàn tất.

---

### **3. Tạo Máy Ảo Windows 11**  
Không sử dụng lại VM cũ để tránh lỗi. Hãy cài đặt Windows 11 từ đầu.

#### **Tải Windows 11 Evaluation**  
- **Đối với x86_64**: [Windows 11 Enterprise Evaluation](https://www.microsoft.com/evalcenter/evaluate-windows-11-enterprise)
- **Đối với ARM64 (Apple Silicon, Windows ARM)**: [Windows 11 IoT Enterprise LTSC](https://www.microsoft.com/evalcenter/evaluate-windows-11-iot-enterprise-ltsc)
  
- **ISO Windows 11**: https://www.microsoft.com/en-us/software-download/windows11

Nhập thông tin theo yêu cầu để tải về.

---

### **4. Cài Đặt Kali Linux Trên VMware Workstation**  
Sau khi cài đặt xong VMware Workstation/Fusion:

1. **Tải Kali Linux ISO**  
   - Truy cập trang chính thức:  
     🔗 [Tải Kali Linux](https://www.kali.org/get-kali/)
   
![image](https://hackmd.io/_uploads/B1DUuGmYyg.png)

![image](https://hackmd.io/_uploads/SJV6dfQtJe.png)

2. **Giải nén máy ảo**
   - Do máy ảo ở dạng 7z nên cần có [7z](https://www.7-zip.org/download.html) để giải nén (nếu sử dụng Linux thì có sẵn option extract)

![image](https://hackmd.io/_uploads/HkHXYGQKyl.png)

3. **Mở Máy Ảo**  
   - Mở **VMware Workstation/Fusion** và chọn "Create a New Virtual Machine".

![image](https://hackmd.io/_uploads/ByJTtGmtkx.png)

![image](https://hackmd.io/_uploads/rkLeqfmY1g.png)

4. **Chạy máy ảo**

![image](https://hackmd.io/_uploads/HkaMcGXF1g.png)

Bấm `Start up this...` để khởi chạy máy ảo. Mật khẩu mặc định là `kali` - `kali`

---

### **5. Kết Luận**  
Bạn đã hoàn tất việc cài đặt **Windows 11** hay **Kali Linux trên VMware Workstation/Fusion**. Từ đây, bạn có thể bắt đầu sử dụng Kali Linux để kiểm thử bảo mật hoặc nghiên cứu an toàn thông tin.

💡 Nếu có vấn đề trong quá trình cài đặt, hãy kiểm tra tài liệu chính thức của **Kali Linux** và **VMware** để được hỗ trợ thêm.
