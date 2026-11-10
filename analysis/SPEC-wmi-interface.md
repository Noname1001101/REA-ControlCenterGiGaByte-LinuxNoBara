# Đặc Tả Giao Diện WMI CLEVO / Insyde Trên Linux (SPEC-wmi-interface)
## Dự án: REA Control Center GiGaByte Linux NoBara
**Giai đoạn 4 — Nhiệm vụ 3 (Task 3)**  
**Người thực hiện:** Worker 3  
**Ngày lập đặc tả:** 2026-11-10  
**Đối tượng khảo sát:** Gói mã nguồn và nhị phân tại `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed`  
**Cơ sở kiểm chứng:** Dữ liệu phân tích tĩnh IL bytecode 100% đã được kiểm chứng độc lập tại 3 tài liệu:
- `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\analysis\findings.md`
- `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\analysis\verification-worker.md` (Worker 1: 61 mã lệnh)
- `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\analysis\verification-remaining.md` (Worker 2: 56 mã lệnh)

---

## 1. Kiến Trúc Giao Tiếp Phần Cứng Chuẩn Trên Linux (Yêu cầu 1)

### 1.1. Tuyên bố nguyên tắc an toàn nhân Linux
- **TUYỆT ĐỐI KHÔNG SỬ DỤNG `acpi_call`:** 
  Dự án nghiêm cấm việc tích hợp, phụ thuộc hoặc khuyến nghị người dùng cài đặt module ngoài `acpi_call` (chẳng hạn `acpi_call-dkms`). Lý do kỹ thuật: `acpi_call` cho phép user-space tùy tiện đánh giá các phương thức ACPI mà không qua cơ chế kiểm soát kiểu dữ liệu và thẩm quyền của Linux ACPI Subsystem, dễ gây lỗi phân trang bộ nhớ kernel (kernel panic), treo bộ điều khiển nhúng (Embedded Controller - EC), hoặc làm hỏng phần cứng nguồn/quạt khi truyền sai cấu trúc buffer.
- **KHÔNG YÊU CẦU CÀI ĐẶT THÊM KERNEL MODULE NGOÀI:**
  Giải pháp phần mềm trên Linux (NoBara / Fedora / Ubuntu / Arch) phải hướng tới việc tương tác thông qua các giao diện tiêu chuẩn đã có sẵn trong nhân Linux chính dòng (upstream Linux kernel standard subsystems).

### 1.2. Hiện trạng và Thách thức Giao diện Linux WMI/ACPI
Trên các bo mạch Clevo / Gigabyte tương thích, firmware BIOS ACPI phơi bày giao diện điều khiển qua thiết bị chuẩn `PNP0C14` với không gian WMI nguồn trên Windows là `root\WMI` (khối đối tượng phương thức `CLEVO_GET` với `InstanceName='ACPI\PNP0C14\0_0'` và khối sự kiện `CLEVO_EVENT`). Tuy nhiên, việc ánh xạ và tương tác trên Linux cần được nhìn nhận chính xác theo 3 điểm kỹ thuật cốt lõi sau:

1. **Giao diện user-space trên Linux cần kernel driver trung gian (CẦN KIỂM CHỨNG thực tế trên Linux):**
   - User-space trên Linux **không thể gọi trực tiếp** hàm nội bộ kernel `wmi_evaluate_method(guid, instance, method_id, in_buf, out_buf)`.
   - Các giao diện ký tự tiềm năng dạng `/dev/wmi/*` (nếu có được tạo bởi subsystem WMI của kernel) rất hạn chế và thường không cung cấp cơ chế thực thi phương thức WMI tùy ý an toàn cho user-space thông thường.
   - Theo kiến trúc chuẩn của Linux, tầng user-space thường cần một **kernel platform driver** đứng giữa (ví dụ: driver nền tảng WMI cho Clevo/Gigabyte) để tương tác với ACPI WMI, sau đó phơi bày các thuộc tính chuẩn hóa ra user-space thông qua các hệ thống con tiêu chuẩn: `sysfs` (`/sys/devices/platform/...`), `hwmon` (nhiệt độ `temp*_input`, điều khiển quạt `pwm*`, `fan*_input`), `leds` (`/sys/class/leds/`), và `platform_profile` (hồ sơ hiệu năng ACPI/nền tảng). Khả năng giao tiếp trực tiếp từ user-space hay bắt buộc phải qua kernel driver **CẦN ĐƯỢC KIỂM CHỨNG thực tế trên môi trường Linux**.

2. **Phân biệt mã lệnh `cmd` trong C# với WMI Method ID trong ACPI DSDT/BMOF:**
   - Mã lệnh `cmd` (từ `0` đến `255`) được phân tích trong `DCHUService.exe` (lớp `HotkeyService.Talk2Wmi::ExecuteWMI`) thực chất **chỉ là chỉ số nhánh `switch` nội bộ của ứng dụng C# trên Windows**, dùng để chọn tên chuỗi phương thức WMI tương ứng (ví dụ: `cmd = 2` gọi chuỗi `"GetCPUtemp"`, `cmd = 104` gọi chuỗi `"SetFanDuty"`).
   - Mã `cmd` này **KHÔNG PHẢI là WMI Method ID** trong bảng mô tả nhị phân ACPI DSDT hay BMOF (`.bmf`).
   - Trên Linux, WMI Subsystem định danh phương thức bằng Method ID dạng số nguyên (Method ID `1, 2, 3...`) được định nghĩa trong khối MOF nhị phân (`_WDG` buffer của ACPI). Muốn biết Method ID thực sự tương ứng với từng hàm (`GetCPUtemp`, `SetFanDuty`...), bắt buộc phải trích xuất và giải mã BMOF thực tế từ firmware ACPI của máy Gigabyte G5 GE.

3. **Mâu thuẫn kiến trúc tiềm ẩn với nguyên tắc "không cài kernel module ngoài":**
   - Nếu nhân Linux chuẩn trên Nobara / Fedora hiện tại **chưa có sẵn driver** tích hợp sẵn để nhận diện thiết bị `PNP0C14` của bo mạch Gigabyte G5 GE và ánh xạ đầy đủ các hàm phương thức của `CLEVO_GET`, thì việc điều khiển quạt, đèn phím và hiệu năng hoàn toàn từ user-space mà không có driver sẽ gặp trở ngại lớn.
   - Điều này phát sinh **mâu thuẫn trực tiếp với nguyên tắc "không cài đặt thêm kernel module ngoài (no out-of-tree DKMS)"** đã nêu tại Mục 1.1.
   - **Chính sách xử lý:** Điểm mâu thuẫn kiến trúc này hiện được **ĐỂ MỞ**, chờ kết quả trích xuất ACPI tables (`/sys/firmware/acpi/tables/DSDT`, `BMOF`) và kiểm tra thực tế các interface sysfs/wmi sẵn có trên môi trường boot Live USB Nobara trước khi đưa ra quyết định kỹ thuật cuối cùng.

---

## 2. Cơ Sở Phân Loại Nhóm Mức A (Chỉ Đọc — Rủi Ro Thấp, Chưa Xác Minh Phía BIOS) (Yêu cầu 4)

Các mã lệnh được xếp vào **Mức A (CHỈ ĐỌC)** trong bản đặc tả này được đánh giá là **rủi ro thấp, chưa xác minh phía BIOS** (vì phân tích IL bytecode chỉ chứng minh được phía tiến trình `DCHUService.exe` gọi `ExecMethod` với 0 tham số đầu vào, nhưng hoàn toàn chưa chứng minh được mã AML trong DSDT hoặc mã SMM ngầm trong BIOS không gây ra tác dụng phụ hay thay đổi trạng thái phần cứng) dựa trên các bằng chứng kỹ thuật đã được phân tích và kiểm chứng chéo trực tiếp ở mức **IL bytecode** (CIL Instruction Anchors) trong `DCHUService.exe` và `ControlCenter30.exe`:

1. **Bản chất lời gọi hàm trong `HotkeyService.Talk2Wmi` (`DCHUService.exe`):**
   - Không đơn thuần dựa trên tiền tố tên gọi `Get...`, mà vì mã bytecode IL chứng minh toàn bộ các nhánh này đều gọi qua phương thức **`Talk2Wmi::ExecMethod`** (`Token: 0x06000010`) hoặc **`Talk2Wmi::ExecMethod2`** (`Token: 0x06000011`).
   - Tại `IL_0000` đến `IL_0010` của `ExecMethod`: mã máy gọi trực tiếp `this.classInstance.InvokeMethod(strMethodName, null, null)` với **tham số vào là `null`** (0 tham số đầu vào, không tạo `inParams`).
   - Kết quả chỉ được đọc một chiều từ thuộc tính `outParams["Data"]` đưa vào biến trả về. Tuy nhiên, tác động thực tế bên dưới tầng ACPI AML/SMM của BIOS vẫn chưa được phân tích (chưa dịch ngược DSDT).
2. **Cơ chế đọc bộ đệm snapshot tĩnh `Package1` (`Talk2Wmi::InitHotkey` `0x06000002`):**
   - Phương thức WMI `"Package1"` trả về mảng tĩnh `byte[256]` phản ánh snapshot hiện thời của phần cứng.
   - Các thuộc tính phần cứng được trích xuất thông qua hàm tính toán bộ nhớ thuần túy: `ConvertArrayToData(int32 index, int32 length)` (`0x06000003`), hoàn toàn là thao tác tính toán trên bộ nhớ RAM của tiến trình, không gửi tham số tác động phần cứng.
3. **Cơ chế đọc trong `ControlCenter30.exe` / `InsydeDCHU.dll`:**
   - Các wrapper `0x060000c8` / `0x060000c9` bọc quanh `GetDCHU_Data_Integer` (`0x060000c1`) chỉ truyền con trỏ biến nhận `int32& outVal`.
   - Các wrapper `0x060000cc` / `0x060000cf` bọc quanh `GetDCHU_Data_Buffer` (`0x060000c3`) cấp phát mảng 256 byte và nhận dữ liệu từ driver, không gửi tham số ghi xuống phần cứng.

---

## 3. Phân Loại 4 Mức Rủi Ro A, B0, C, D (Yêu cầu 2, 3, 5)

| Mức Rủi Ro | Phân Loại | Định Nghĩa & Chính Sách Ứng Xử Trên Linux | Phạm Vi Áp Dụng |
| :--- | :--- | :--- | :--- |
| **MỨC A** | **CHỈ ĐỌC (READ-ONLY)** | **Rủi ro thấp, chưa xác minh phía BIOS.** (Phía IL gọi `ExecMethod` 0 tham số vào, nhưng chưa chứng minh AML/SMM phía BIOS không có tác dụng phụ). Được phép gọi tuần hoàn định kỳ (polling) để thu thập dữ liệu giám sát hệ thống sau khi đã kiểm tra an toàn. | Thuộc 3 mục tiêu: Quạt, Đèn bàn phím, Chế độ hiệu năng & cờ hệ thống liên quan. |
| **MỨC B0** | **CHƯA ĐƯỢC GHI (PROVISIONAL / NOT YET WRITABLE)** | **Tạm thời cấm ghi.** Bao gồm cả 8 mã lệnh ghi mục tiêu (cmd = 30, 104, 105, 39, 77, 103, 29, 79). Đã xác minh tên hàm WMI và kiểu dữ liệu `UInt32` từ `InvokeMethod`, nhưng chi tiết cấu trúc giá trị tham số (bitmask, thang đo) chưa được xác minh. **Quy tắc chuyển cấp:** Chỉ được nâng từ Mức B0 lên Mức B sau khi cấu trúc tham số đã được xác minh bằng phân tích sâu (disassembly/decompile) hoặc kiểm chứng đọc lại (readback) xác nhận trên Windows. | Thuộc 3 mục tiêu: Quạt (cmd=30, 104, 105), Đèn bàn phím (cmd=39, 77, 103), Hiệu năng (cmd=29, 79). |
| **MỨC C** | **NGUY HIỂM / CẤM DÙNG (DANGEROUS / FORBIDDEN)** | **Tuyệt đối cấm thực thi.** Nguy cơ gây mất ổn định nguồn điện, quá nhiệt, hỏng hóc vật lý, sập nguồn, vi phạm bảo mật hệ điều hành hoặc chứa tham số chưa rõ nguồn gốc. | H2RAM, ép xung/điện áp PL1/PL2/Core/VR (19 hàm page=6), AppSettings, cmd=121, SetDCHU_DataEx (cmd=4), các lệnh nhạy cảm và IPC Process. |
| **MỨC D** | **NGOÀI PHẠM VI (OUT OF SCOPE)** | **Bỏ qua / Không triển khai.** Các tính năng thiết bị ngoại vi không nằm trong 3 mục tiêu trọng tâm của dự án (Quạt, Đèn bàn phím, Hiệu năng). | WLAN, Bluetooth, Camera, Touchpad, Airplane, Pin, Sensor, ODD, RFID, GPS, Barcode, RTC, S3/S4, No-op... |

---

## 4. Danh Mục Chi Tiết MỨC A — CHỈ ĐỌC (Rủi Ro Thấp, Chưa Xác Minh Phía BIOS)

Tất cả các lệnh dưới đây được phân loại **rủi ro thấp, chưa xác minh phía BIOS**, đọc dữ liệu một chiều từ user-space qua `ExecMethod` (0 tham số ghi) hoặc trích xuất từ bộ đệm `Package1` / `GetDCHU_Data_*` (chưa xác minh liệu mã AML/SMM trong firmware BIOS có tác dụng phụ ngầm hay không).

> **Ghi chú về mức độ kiểm chứng trong bảng Mức A:**  
> - **`[ĐÃ XÁC MINH TỪ IL]`**: Chỉ áp dụng cho các thuộc tính quan sát thấy trực tiếp trong mã IL bytecode (lời gọi `ExecMethod`, chuỗi tên phương thức, kiểu nhận từ `outParams["Data"]`, offset trong `Package1`, hoặc các phép toán bitmask cụ thể như bit 23 của cmd 16/122, 12 bit đầu của cmd 70, bit 29 của cmd 122).  
> - **`[GIẢ THUYẾT]`**: Áp dụng cho mọi thông tin suy diễn từ ngữ nghĩa tên gọi chưa có bằng chứng toán học/thao tác bit trong IL (như đơn vị °C, %, RPM, cấu trúc bitmask nội bộ, hoặc diễn giải chức năng cảm biến).

### 4.1. Nhóm Quạt & Nhiệt Độ (Fan & Thermal Telemetry)

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Kiểu Trả Về & Định Dạng Dữ Liệu | Chức Năng Giám Sát | Nguồn Bằng Chứng Kỹ Thuật (Assembly / Token / IL / Chuỗi) |
| :--- | :--- | :--- | :--- | :--- |
| **`2`** (`0x02`) | `GetCPUtemp` | `UInt32` `[ĐÃ XÁC MINH TỪ IL: ExecMethod lấy outParams["Data"]]`; Đơn vị: `°C` `[GIẢ THUYẾT]` | Nhiệt độ nhân CPU (Digital Thermal Sensor / PECI) `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12B1`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000b27` (`"GetCPUtemp"`). |
| **`3`** (`0x03`) | `GetCPUtempThermalIC` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Đơn vị: `°C` `[GIẢ THUYẾT]` | Nhiệt độ CPU đo từ cảm biến IC nhiệt phần cứng `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12C3`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000b3d` (`"GetCPUtempThermalIC"`). |
| **`4`** (`0x04`) | `GetCPUFANState` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Cấu trúc Bitmask/State `[GIẢ THUYẾT]` | Trạng thái hoạt động hiện tại của quạt CPU `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12D5`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000b65` (`"GetCPUFANState"`). |
| **`12`** (`0x0C`) | `GetVGA1temp` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Đơn vị: `°C` `[GIẢ THUYẾT]` | Nhiệt độ GPU rời 1 (NVIDIA dGPU Thermal Sensor) `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1365`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000c4d` (`"GetVGA1temp"`). |
| **`13`** (`0x0D`) | `GetVGA1tempThermalIC` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Đơn vị: `°C` `[GIẢ THUYẾT]`. *(Trong `ControlCenter30.exe`, gọi `GetDCHU_Data_Buffer(13)` lấy `buf[15] & 0x0F` `[ĐÃ XÁC MINH TỪ IL]`; ý nghĩa của `buf[15] & 0x0F`: `[GIẢ THUYẾT]`)* | Nhiệt độ GPU rời 1 đo từ cảm biến IC nhiệt phần cứng `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1377`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000c65` (`"GetVGA1tempThermalIC"`). |
| **`14`** (`0x0E`) | `GetVGA2temp` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Đơn vị: `°C` `[GIẢ THUYẾT]` | Nhiệt độ GPU 2 (nếu máy trang bị GPU phụ) `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1389`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000c8f` (`"GetVGA2temp"`). |
| **`15`** (`0x0F`) | `GetVGA2tempThermalIC` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Đơn vị: `°C` `[GIẢ THUYẾT]` | Nhiệt độ GPU 2 đo từ cảm biến IC nhiệt phần cứng `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_139B`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000ca7` (`"GetVGA2tempThermalIC"`). |
| **`17`** (`0x11`) | `GetCPUFANControl` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Trích xuất từ bộ đệm `Package1` tại `offset=48, len=1` `[ĐÃ XÁC MINH TỪ IL: InitHotkey @ IL_0223]`. Trong `ControlCenter30.exe`, đọc `buf[2]` và `buf[3]` từ `GetDCHU_Data_Buffer(17)` `[ĐÃ XÁC MINH TỪ IL]`. Cấu trúc ý nghĩa byte cờ (Auto / Manual / Duty): `[GIẢ THUYẾT]` | Cờ chế độ điều khiển quạt CPU (Auto / Manual / Duty) `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_13BF`), nạp chuỗi `0x70000273`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0223` trích byte tại `offset=48, len=1`, hoặc gọi `ExecMethod2` @ `IL_0433`).<br>- `ControlCenter30.exe`: gọi `GetDCHU_Data_Buffer(17)` đọc `buf[2]` và `buf[3]`. |
| **`53`** (`0x35`) | `GetCPUFANDuty` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Thang đo đơn vị (0 - 100 hoặc 0 - 255): `[GIẢ THUYẾT]` | Tốc độ quạt CPU hiện tại (Duty Cycle %) `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_15CE`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000ffd` (`"GetCPUFANDuty"`). |
| **`54`** (`0x36`) | `GetVGA1FANDuty` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Thang đo đơn vị (0 - 100 hoặc 0 - 255): `[GIẢ THUYẾT]` | Tốc độ quạt GPU 1 hiện tại (Duty Cycle %) `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_15E0`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001019` (`"GetVGA1FANDuty"`). |
| **`55`** (`0x37`) | `GetVGA2FANDuty` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Thang đo đơn vị (0 - 100 hoặc 0 - 255): `[GIẢ THUYẾT]` | Tốc độ quạt GPU 2 hiện tại (Duty Cycle %) `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_15F2`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001037` (`"GetVGA2FANDuty"`). |
| **`56`** (`0x38`) | `GetFANCount` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Giá trị biểu thị số lượng quạt vật lý: `[GIẢ THUYẾT]` | Số lượng quạt vật lý được hỗ trợ bởi hệ thống `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1604`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001055` (`"GetFANCount"`). |
| **`97`** (`0x61`) | `GetFanStatus` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Cấu trúc Bitmask trạng thái: `[GIẢ THUYẾT]` | Trạng thái tổng quát của hệ thống tản nhiệt EC `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_18C4`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000132d` (`"GetFanStatus"`). |
| **`99`** (`0x63`) | `Fan1Info` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Ý nghĩa thông số cấu hình Fan 1: `[GIẢ THUYẾT]` | Thông tin định danh / đặc tính phần cứng Quạt 1 `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_18E8`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000135b` (`"Fan1Info"`). |
| **`100`** (`0x64`) | `Fan2Info` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Ý nghĩa thông số cấu hình Fan 2: `[GIẢ THUYẾT]` | Thông tin định danh / đặc tính phần cứng Quạt 2 `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_18FA`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000136d` (`"Fan2Info"`). |
| **`110`** (`0x6E`) | `Fan3Info` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Ý nghĩa thông số Fan 3: `[GIẢ THUYẾT]` | Thông tin định danh / đặc tính phần cứng Quạt 3 `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_199D`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000143f` (`"Fan3Info"`). |
| **`111`** (`0x6F`) | `Fan4Info` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Ý nghĩa thông số Fan 4: `[GIẢ THUYẾT]` | Thông tin định danh / đặc tính phần cứng Quạt 4 `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_19AF`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001451` (`"Fan4Info"`). |
| **`112`** (`0x70`) | `GetFan12RPM` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Cấu trúc bit `[Fan2_RPM << 16] | Fan1_RPM` và đơn vị RPM: `[GIẢ THUYẾT]` (suy luận từ tên hàm, chưa thấy mã bit-shift trong IL `DCHUService.exe`) | Tốc độ vòng quay thực tế (RPM) của Quạt 1 & 2 `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_19C1`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001463` (`"GetFan12RPM"`). |
| **`113`** (`0x71`) | `GetFan34RPM` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Cấu trúc bit `[Fan4_RPM << 16] | Fan3_RPM` và đơn vị RPM: `[GIẢ THUYẾT]` | Tốc độ vòng quay thực tế (RPM) của Quạt 3 & 4 `[GIẢ THUYẾT]` | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_19D3`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000147b` (`"GetFan34RPM"`). |

### 4.2. Nhóm Đèn Bàn Phím & LED (Keyboard LED Telemetry)

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Kiểu Trả Về & Định Dạng Dữ Liệu | Chức Năng Giám Sát | Nguồn Bằng Chứng Kỹ Thuật (Assembly / Token / IL / Chuỗi) |
| :--- | :--- | :--- | :--- | :--- |
| **`61`** (`0x3D`) | `GetWhiteLedKB` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Trích xuất từ bộ đệm `Package1` tại `offset=98, len=1` `[ĐÃ XÁC MINH TỪ IL: InitHotkey @ IL_0313]`. Định dạng giá trị (0 = Tắt, 1 = Bật, hoặc mức sáng): `[GIẢ THUYẾT]` | Trạng thái bật/tắt đèn bàn phím đơn sắc trắng `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1644`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000295`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0313` trích byte tại `offset=98, len=1`, hoặc gọi `ExecMethod2` @ `IL_0464`).<br>- `ControlCenter30.exe`: `#vQb.#f8b` @ `IL_0055`. |
| **`68`** (`0x44`) | `GetVolumeLED` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Trích xuất từ bộ đệm `Package1` tại `offset=106, len=1` `[ĐÃ XÁC MINH TỪ IL: InitHotkey @ IL_02A8]`. Cấu trúc bit cờ trạng thái LED: `[GIẢ THUYẾT]` | Trạng thái hiển thị đèn LED dải âm lượng / Lightbar `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_16C2`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700002d5`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02A8` trích byte tại `offset=106, len=1`, hoặc gọi `ExecMethod2` @ `IL_049E`). |

### 4.3. Nhóm Hiệu Năng & Cờ Hệ Thống Liên Quan (Performance & System Feature Telemetry)

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Kiểu Trả Về & Định Dạng Dữ Liệu | Chức Năng Giám Sát | Nguồn Bằng Chứng Kỹ Thuật (Assembly / Token / IL / Chuỗi) |
| :--- | :--- | :--- | :--- | :--- |
| **`16`** (`0x10`) | `GetCPUPerformance` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Kiểm tra Bit 23 là cờ kích hoạt `(val >> 23) & 1` trong `ControlCenter30.exe` (`0x06000062` @ `IL_0012`) `[ĐÃ XÁC MINH TỪ IL]`. Ý nghĩa chế độ hiệu năng CPU: `[GIẢ THUYẾT]` | Chế độ hiệu năng CPU hiện hành từ EC/BIOS `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_13AD`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000cd1`.<br>- `ControlCenter30.exe`: `0x06000062` @ `IL_0012` gọi `0x060000c9(16)`, kiểm tra bit 23 `(val >> 23) & 1` để gán `field_0x04000081`. |
| **`70`** (`0x46`) | `GetAP` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Trích xuất từ bộ đệm `Package1` tại `offset=107, len=16` `[ĐÃ XÁC MINH TỪ IL: InitHotkey @ IL_02CA]`. Kiểm tra 12 bit đầu từ bit 0 đến bit 11 trong `ControlCenter30.exe` (`0x06000054` @ `IL_0011`) `[ĐÃ XÁC MINH TỪ IL]`. Ý nghĩa chức năng của từng bit trong 12 bit AP features: `[GIẢ THUYẾT]` | Đọc danh mục tính năng phần cứng hỗ trợ (AP features bitmask) `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_16E6`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700002d9`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02CA` trích `offset=107, len=16`, hoặc gọi `ExecMethod2` @ `IL_03C8`).<br>- `ControlCenter30.exe`: `0x06000054` @ `IL_0011` gọi `0x060000c9(70)` kiểm tra 12 bit từ bit 0 đến bit 11. |
| **`82`** (`0x52`) | `BIOS_special_feature_list` | `UInt32` / Trích xuất từ bộ đệm `Package1` tại `offset=138, len=16` `[ĐÃ XÁC MINH TỪ IL: InitHotkey @ IL_02ED]`. Danh sách các tính năng đặc biệt của BIOS: `[GIẢ THUYẾT]` | Danh sách các tính năng đặc biệt được hỗ trợ bởi BIOS `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_17BE`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700001dd`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02ED` trích `offset=138, len=16`, hoặc gọi `ExecMethod2` @ `IL_03DC`).<br>- `ControlCenter30.exe`: `#vQb.#e9b` @ `IL_0055`. |
| **`84`** (`0x54`) | `Aero` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Trích xuất từ bộ đệm `Package1` tại `offset=155, len=1` `[ĐÃ XÁC MINH TỪ IL: InitHotkey @ IL_0335]`. Ý nghĩa cờ Aero/Display: `[GIẢ THUYẾT]` | Trạng thái cấu hình Aero / giao diện hiển thị `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_17E2`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700002ef`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0335` trích byte tại `offset=155, len=1`, hoặc gọi `ExecMethod2` @ `IL_04CD`).<br>- `ControlCenter30.exe`: `#vQb.#f9b` @ `IL_0055`. |
| **`122`** (`0x7A`) | `BiosSpecialFeature` | `UInt32` `[ĐÃ XÁC MINH TỪ IL]`; Kiểm tra bit 29 `(val & 0x20000000)` trong `InitHotkey` @ `IL_008A` để quyết định đọc `Package1` `[ĐÃ XÁC MINH TỪ IL]`; Kiểm tra bit 23 `(val & 0x800000)` trong `ControlCenter30.exe` (`0x0600005b` @ `IL_0006`, `0x06000062` @ `IL_0004`) `[ĐÃ XÁC MINH TỪ IL]`. Ý nghĩa cụ thể của các bit còn lại: `[GIẢ THUYẾT]` | Cờ tính năng BIOS đặc thù (Nhánh nhận diện giao thức Clevo WMI) `[GIẢ THUYẾT]` | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1A8A`), nạp chuỗi `0x70000171`.<br>- Khởi tạo: `Talk2Wmi::InitHotkey` (`0x06000002` @ `IL_008A` gọi `ExecMethod2`, kiểm tra bit 29 `(val & 0x20000000)` để quyết định đọc `Package1`).<br>- `ControlCenter30.exe`: `0x0600005b` @ `IL_0006` và `0x06000062` @ `IL_0004` kiểm tra bit 23 `(val & 0x800000)`. |

---

## 5. Danh Mục Chi Tiết MỨC B0 — CHƯA ĐƯỢC GHI (Provisional / Not Yet Writable)

> **QUY TẮC AN TOÀN CHUYỂN CẤP (B0 -> B):**  
> Toàn bộ **8 mã lệnh ghi mục tiêu** dưới đây (thuộc 3 mục tiêu trọng tâm: Quạt, Đèn bàn phím, Chế độ hiệu năng) bị chuyển phân loại sang mức **`B0 — CHƯA ĐƯỢC GHI`**.  
> **Quy tắc bắt buộc:** Các lệnh này **CHỈ ĐƯỢC PHÉP NÂNG TỪ B0 LÊN B (được phép ghi)** sau khi cấu trúc tham số chi tiết (từng byte, thang đo giá trị hợp lệ, quy tắc bitmask) đã được xác minh rõ ràng bằng phân tích sâu (disassembly/decompile các module chuyên trách `FanSpeedSetting.exe`, `LedKeyboardSetting.exe`, `FnKey.exe` bằng REA) hoặc kiểm chứng đọc lại (readback verification) xác nhận trực tiếp trên Windows.  
> Toàn bộ các giá trị tham số suy đoán trước đây (như `0 = Auto, 1 = Manual`, `[FanIndex << 8] | DutyValue`, mã màu RGB hay số thứ tự profile `0..3`) đã bị **LOẠI BỎ HOÀN TOÀN** khỏi đặc tả do không có bằng chứng IL trực tiếp trong `DCHUService.exe`. Cột cấu trúc tham số chỉ giữ lại kiểu dữ liệu `UInt32` (đã xác minh từ lệnh `Convert.ToUInt32(strData)` gán vào `inParams["Data"]` trong `InvokeMethod` / `InvokeMethod2`).

### 5.1. Bảng 8 Mã Lệnh Ghi Mức B0

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Cơ Chế Gọi & Kiểu Tham Số WMI | Mục Tiêu Điều Khiển | Cấu Trúc Tham Số Đầu Vào (`inParams["Data"]`) | Nguồn Bằng Chứng Kỹ Thuật |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`30`** (`0x1E`) | **`SetCPUFANControl`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Quạt:** Chuyển đổi chế độ quạt CPU | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích FanSpeedSetting.exe / FnKey.exe bằng REA]`. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1455`), nạp chuỗi `0x70000dbd` (`"SetCPUFANControl"`). |
| **`104`** (`0x68`) | **`SetFanDuty`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Quạt:** Thiết lập mức Duty Cycle cho quạt | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích FanSpeedSetting.exe / FnKey.exe bằng REA]`. *(Bắt buộc tuân thủ Quy tắc an toàn ghi quạt tại Mục 7)*. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_191F`), nạp chuỗi `0x7000137f` (`"SetFanDuty"`). |
| **`105`** (`0x69`) | **`SetFanAutoDuty`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Quạt:** Trả quạt về chế độ điều khiển tự động của EC | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích FanSpeedSetting.exe / FnKey.exe bằng REA]`. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1932`), nạp chuỗi `0x70001395` (`"SetFanAutoDuty"`). |
| **`39`** (`0x27`) | **`SetWhiteLedKB`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Đèn phím:** Bật/tắt hoặc chỉnh sáng đèn bàn phím trắng | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích LedKeyboardSetting.exe / FnKey.exe bằng REA]`. | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_14C7`), nạp chuỗi `0x70000e4b`.<br>- `ControlCenter30.exe`: `#vQb.#h9b` @ `IL_00EA`. |
| **`77`** (`0x4D`) | **`SetColorKey`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Đèn phím:** Thiết lập hiệu ứng / cấu hình màu bàn phím | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích LedKeyboardSetting.exe / FnKey.exe bằng REA]`. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1761`), nạp chuỗi `0x70001133` (`"SetColorKey"`). |
| **`103`** (`0x67`) | **`SetKBLED`** | Ghi 1 tham số (`InvokeMethod` / `InvokeMethod2`) | **Đèn phím:** Thiết lập trạng thái LED bàn phím tổng thể | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích LedKeyboardSetting.exe / FnKey.exe bằng REA]`. | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_190C`), nạp chuỗi `0x70000499`.<br>- Tự đổi màu: `Talk2Wmi::ExecuteAutoColorWmi` (`0x0600000c` @ `IL_0016`).<br>- `ControlCenter30.exe`: `#vQb.#i9b` @ `IL_00C4`. |
| **`29`** (`0x1D`) | **`SetCPUPerformance`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Hiệu năng:** Thiết lập chế độ hiệu năng phần cứng CPU | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích FanSpeedSetting.exe / FnKey.exe bằng REA]`. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1442`), nạp chuỗi `0x70000d99` (`"SetCPUPerformance"`). |
| **`79`** (`0x4F`) | **`SetEnergyStar`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Hiệu năng:** Bật/tắt chế độ tiết kiệm năng lượng EnergyStar | `UInt32` `[ĐÃ XÁC MINH TỪ IL: Convert.ToUInt32]`; `[CHƯA BIẾT chi tiết byte/giá trị, cần phân tích FanSpeedSetting.exe / FnKey.exe bằng REA]`. | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1787`), nạp chuỗi `0x7000115f`.<br>- `ControlCenter30.exe`: `#vQb.#l9b` @ `IL_0107`. |

---

### 5.2. Hai Đường Điều Khiển Tiềm Năng Của Đèn Bàn Phím (WMI vs USB/HID)

Kết quả phân tích tĩnh bằng công cụ REA đối với các gói ứng dụng điều khiển đèn bàn phím trong `findings.md` cho thấy hệ sinh thái phần mềm Clevo/Gigabyte tồn tại **hai kiến trúc điều khiển LED bàn phím song song**:

1. **Đường 1: ACPI WMI thông qua `DCHUService.exe` (và `InsydeDCHU.dll`):**
   - **Bằng chứng REA `[ĐÃ XÁC MINH]`:**
     - `DCHUService.exe`: Lớp `HotkeyService.Talk2Wmi::ExecuteWMI` chứa các mã lệnh `cmd = 39` (`SetWhiteLedKB`), `cmd = 77` (`SetColorKey`), `cmd = 103` (`SetKBLED`), `cmd = 61` (`GetWhiteLedKB`), `cmd = 68` (`GetVolumeLED`). Phương thức `ExecuteAutoColorWmi` (`0x0600000c`) gọi `InvokeMethod2` với `cmd = 103` (`SetKBLED`).
     - `ControlCenter30.exe`: gọi P/Invoke `InsydeDCHU.dll!SetDCHU_Data` tại `#vQb.#h9b` (`cmd = 39`), `#vQb.#i9b` (`cmd = 103`).
     - `LedKeyboardSetting.exe` (SHA-256: `2b50e58e64ac30c4aca16be554665c539c31a3ff9312c51815e3f24194211570`, REA Evidence ID: `ev_8078598e5c659e672d53b5fd6d4430bfeb3e7c3779fcf30d06340bad8b6aaf94`) khai báo P/Invoke trực tiếp tới `InsydeDCHU.dll` (`0x06000064`..`0x06000069`, `0x0600022e`..`0x0600022f` gồm `GetDCHU_Data_Integer`, `SetDCHU_Data`, `SetDCHU_DataEx`, `GetDCHU_Data_Buffer`, `ReadAppSettings`, `WriteAppSettings`).

2. **Đường 2: USB / HID Device thông qua các thư viện Per-Key chuyên dụng:**
   - **Bằng chứng REA `[ĐÃ XÁC MINH]`:**
     - `LedKeyboardSetting.exe`: Ngoài `InsydeDCHU.dll`, ứng dụng này còn P/Invoke trực tiếp hàng loạt thư viện chuyên dụng cho điều khiển LED qua bus thiết bị ngoại vi:
       - **`perkey_api.dll`**: các hàm `InitPerkeyIo`, `SetLEDStatus`, `GetLedData` (`0x060000c9`..`0x060000cb` và `0x06000290`..`0x06000292`).
       - **`LineLEDAPI.dll`**: các hàm `InitLineLEDIo`, `SetLightBarData62` (`0x06000230`..`0x06000231`).
       - **`DataAddress.dll`**: hàm `DataAddress` (`0x0600014f`).
     - `FnKey.exe` (SHA-256 xác minh trong `findings.md`, REA Evidence ID: `ev_1c6bc314ae6790a10b497943c7691f0d98397aee0afed7e03e9c12cccf459499`):
       - P/Invoke thư viện **`\Device_HID\perkey\HID_Device.dll`** gồm các hàm giao tiếp trực tiếp qua giao diện HID: `Init_HIDdevice`, `WriteData`, `ReadData` (tại `0x0600060d`..`0x0600060f`), đồng thời kết hợp gọi `InsydeDCHU.dll` để xử lý các phím tắt Fn điều chỉnh độ sáng/màu LED bàn phím.

3. **Hiện trạng đánh giá trên Gigabyte G5 GE: `[CHƯA BIẾT]`**
   - **`[CHƯA BIẾT]`** Trên phần cứng cụ thể của máy Gigabyte G5 GE (bo mạch Clevo tương thích), đường nào là đường điều khiển chính của bàn phím:
     - Liệu máy sử dụng hoàn toàn qua **ACPI WMI** (`cmd = 39 / 77 / 103`)?
     - Hay sử dụng chip vi điều khiển LED độc lập giao tiếp qua **USB/HID** (ví dụ vendor ID / product ID của bộ điều khiển bàn phím ITE/Clevo HID Device)?
     - Hay là cơ chế **kết hợp cả hai** (ví dụ: WMI đảm nhiệm bật/tắt nguồn và độ sáng tổng thể, còn USB/HID đảm nhiệm truyền bảng mã màu RGB / hiệu ứng từng phím)?
   - **Kết luận:** Bắt buộc giữ nguyên trạng thái `[CHƯA BIẾT]` và phải kiểm tra thực tế các thiết bị USB (`lsusb`, `/dev/usb/hiddev*`) và WMI trên Linux live USB trước khi tiến hành viết code module điều khiển đèn bàn phím.

---

## 6. Danh Mục MỨC C — NGUY HIỂM / CẤM SỬ DỤNG (Yêu cầu 3)

> [!CAUTION]
> **CẢNH BÁO NGUY HIỂM:** Toàn bộ các mã lệnh và phương thức trong Mức C bị **CẤM TUYỆT ĐỐI** trên Linux. Bất kỳ hành vi gọi nào xuống các hàm này có thể gây hỏng hóc vĩnh viễn bo mạch chủ, cháy VRM CPU/GPU, mất ổn định nguồn hoặc mở ra lỗ hổng thực thi mã tùy tiện.

### 6.1. Chi tiết các nhóm lệnh Mức C

| Nhóm Chức Năng | Tên Mã Lệnh / Tên Hàm | Mã `cmd` / Token | Lý Do Cấm / Nguy Cơ Phần Cứng | Nguồn Bằng Chứng Kỹ Thuật |
| :--- | :--- | :--- | :--- | :--- |
| **Thao tác H2RAM (Host to RAM)** | `SetH2RAMIndex` + `GetH2RAMData`<br>`GetH2RAMData`<br>`SetH2RAMIndex` + `WritetH2RAM` | `cmd = 107`<br>`cmd = 115`<br>`cmd = 117` | Cho phép can thiệp ghi/đọc thô trực tiếp vào không gian RAM nội bộ của chip Embedded Controller (EC). Ghi sai offset sẽ làm crash vi điều khiển EC, mất kiểm soát nguồn và quạt tản nhiệt. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI`<br>- `107`: @ `IL_1958`..`IL_1967` (chuỗi `0x700013d7`, `0x700013f3`)<br>- `115`: @ `IL_19E5` (chuỗi `0x700013f3`)<br>- `117`: @ `IL_1A0A`..`IL_1A39` (chuỗi `0x700013d7`, `0x700014ad`). |
| **Ép xung, Điện áp, Giới hạn Công suất (PL1/PL2, VR Limit, Core Ratio)** | Toàn bộ **19 hàm** `Read/WriteAppSettings` tại `page = 6` trong `DCHUService.DCHU` | `Token: 0x06000035` đến `0x06000047` | Điều chỉnh trực tiếp PL1/PL2 (Power Limit 1 & 2), thời gian PL, điện áp Core/Graphics, bù điện áp (Voltage Offset), chế độ điều áp VR và hệ số nhân Core Ratio của CPU. Nguy cơ gây cháy nổ linh kiện, thoái hóa silicon, sập nguồn đột ngột. | `DCHUService.exe`: Lớp `DCHUService.DCHU` (`TypeDef 0x02000003`):<br>- `0x06000035` (`GetPowerLimit1CurrentValue`, p=6, off=33)<br>- `0x06000036` (`GetPowerLimitTimeValue`, p=6, off=41)<br>- `0x06000037` (`GetPowerLimit2CurrentValue`, p=6, off=37)<br>- `0x06000038` (`GetCPUVRAuto`, p=6, off=74)<br>- `0x06000039` (`GetCPUVRCurrentValue`, p=6, off=49)<br>- `0x0600003a` (`GetCPUVoltageOffset`, p=6, off=61)<br>- `0x0600003b` (`GetGraphicsVoltage`, p=6, off=69)<br>- `0x0600003c` (`GetOverrideCurrentValue`, p=6, off=65)<br>- `0x0600003d` (`GetCPUCoreRatioCurrentValue`, p=6, off=53..60, 75..76)<br>- `0x0600003e` (`GetCPUVoltageMode`, p=6, off=73)<br>- `0x0600003f` (`SetCPUVoltageMode`, p=6, off=73)<br>- `0x06000040` (`SetCoreRatio`, p=6, off=53..60, 75..76)<br>- `0x06000041` (`SetIsSavedFlag`, p=6, off=32)<br>- `0x06000042` (`SetPowerLimit1CurrentValue`, p=6, off=33)<br>- `0x06000043` (`SetPowerLimitTimeCurrentValue`, p=6, off=41)<br>- `0x06000044` (`SetPowerLimit2CurrentValue`, p=6, off=37)<br>- `0x06000045` (`SetCPUVR`, p=6, off=49)<br>- `0x06000046` (`SetCoreVoltage`, p=6, off=61)<br>- `0x06000047` (`SetGraphicsVoltage`, p=6, off=69). |
| **Ghi đè cấu hình nội bộ AppSettings** | Mọi lệnh `ReadAppSettings` và `WriteAppSettings` trong `ControlCenter30.exe` | `0x060000c4`<br>`0x060000c5` | Ghi đè vào vùng cấu hình chia sẻ/Registry giả lập không thuộc Linux. Có thể gây xung đột trạng thái giữa các dịch vụ. | `ControlCenter30.exe`: `TypeDef 0x0200003a` (`0x060000cd`, `0x060000ce`) gọi 67 lần tại các trang `page=0, 1, 4, 6`. |
| **Hàm điều khiển hệ thống chưa rõ nghĩa: `cmd = 121`** | **`SystemControlFunction`** (cùng mọi sub-command: `subCmd = 1, 25, 45`) | **`cmd = 121`** (`0x79`) | **Ý nghĩa: CHƯA BIẾT.** Thiếu bằng chứng chuỗi tường minh. Byte thứ 4 đóng vai trò subCmd ghi đè thanh ghi phần cứng thô. Bắt buộc xếp vào Mức C, tuyệt đối không gán nhãn quạt/đèn/hiệu năng. | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1A7A`, chuỗi `0x700014f1`).<br>- `ControlCenter30.exe`: `0x060000ca` gọi tại `0x06000226` (`subCmd=1`), `0x060001f6`/`0x060001fb`/`0x0600020d` (`subCmd=25`), `0x06000210`/`0x06000211` (`subCmd=45`). |
| **Kênh gói mở rộng chưa rõ nghĩa: `SetDCHU_DataEx(cmd = 4)`** | Mọi sub-command của `SetDCHU_DataEx(cmd = 4)` (`inBuf[0] = 7, 8, 21, 22, 24, 25, 26, 30, 31`) | **`cmd = 4`** (`SetDCHU_DataEx`) | **Ý nghĩa: CHƯA BIẾT.** Dù `cmd=4` trong WMI là `GetCPUFANState`, nhưng khi gọi qua `SetDCHU_DataEx` nó là kênh ghi gói dữ liệu 256-byte xuống ACPI. Toàn bộ 9 subCmd chưa được xác minh rõ ràng về tác động phần cứng. Cấm sử dụng. | `ControlCenter30.exe`: Wrapper `0x060000c7` bọc P/Invoke `0x060000c6`, gọi tại 12 vị trí (`0x06000061`, `0x06000206`, `0x06000207`, `0x06000210`, `0x06000211`, `0x06000215`, `0x06000216`, `0x0600021a`, `0x0600021e`, `0x06000222`). |
| **Lệnh chế độ nhà máy (Factory Mode)** | `SetFactoryMode` | `cmd = 71` (`0x47`) | Thiết lập bo mạch về chế độ nhà máy (Factory Test/Burn-in Mode), có thể xóa dữ liệu calibration hoặc vô hiệu hóa cơ chế bảo vệ phần cứng. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_16F8`, chuỗi `0x700010cb`). |
| **Lệnh can thiệp GPIO & Phần cứng sâu** | `SetGPIO12`<br>`SetOS`<br>`SetNVIDIA`<br>`SetECResumerTimer`<br>`TalkECVolume`<br>`TalkECTime`<br>`TalkBIOS3G` | `cmd = 38`<br>`cmd = 85`<br>`cmd = 86`<br>`cmd = 106`<br>`cmd = 116`<br>`cmd = 118`<br>`cmd = 120` | Can thiệp trực tiếp chân GPIO vật lý (`GPIO12`), thay đổi cờ đăng ký hệ điều hành trong BIOS (`SetOS`), can thiệp công tắc nguồn chip GPU (`SetNVIDIA`), ghi đè bộ đếm đánh thức EC, can thiệp âm lượng và xung nhịp thời gian ở tầng vi điều khiển EC. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d`):<br>- `38`: @ `IL_14B4` (chuỗi `0x70000e37`)<br>- `85`: @ `IL_17F4` (chuỗi `0x70001243`)<br>- `86`: @ `IL_1807` (chuỗi `0x70001251`)<br>- `106`: @ `IL_1945` (chuỗi `0x700013b3`)<br>- `116`: @ `IL_19F7` (chuỗi `0x70001493`)<br>- `118`: @ `IL_1A4B` (chuỗi `0x700014c5`)<br>- `120`: @ `IL_1A6A` (chuỗi `0x700014db`). |
| **IPC Thực thi Tiến trình & Bypass UAC** | Khởi chạy tiến trình hệ điều hành qua IPC EventLog | `cmd = 252`<br>`cmd = 253`<br>`cmd = 254`<br>`cmd = 255` | Lỗ hổng bảo mật nghiêm trọng. Cho phép thực thi tiến trình tùy ý với quyền bypass UAC hoặc chạy tiến trình độc lập ngoài tầm kiểm soát của ứng dụng. Hoàn toàn không phù hợp trên kiến trúc Linux POSIX. | `DCHUService.exe`: `DCHUService.Service1::inlog_EntryWritten` (`0x0600005f`):<br>- `252`: @ `IL_02BF` gọi `StartProcessAndBypassUACAsExplorerSessionId` (`0x0600006a`)<br>- `253`: @ `IL_00BA` gọi `LaunchFnKeyFromCMD` (`0x06000062`), `LaunchAppFromCMD` (`0x06000063`)<br>- `254`: @ `IL_009E` gọi `StartProcessAndByPassUAC` (`0x0600006b`)<br>- `255`: @ `IL_0082` gọi `Service1::ExecuteProcess` (`0x0600006d`) và `Talk2Wmi::ExecuteProcess` (`0x06000012` @ `IL_1AA5`). |

---

## 7. Yêu Cầu An Toàn Bắt Buộc Khi Ghi Quạt (Yêu cầu 6)

Đối với các lệnh điều khiển quạt thuộc Mức B0 (sau khi đã được nâng cấp lên Mức B):
- **`cmd = 30` (`SetCPUFANControl`)**
- **`cmd = 104` (`SetFanDuty`)**
- **`cmd = 105` (`SetFanAutoDuty`)**

Bản đặc tả quy định phần mềm triển khai trên Linux **BẮT BUỘC** phải tuân thủ nghiêm ngặt các nguyên tắc sau trong thiết kế mã nguồn và dịch vụ:

### 7.1. (a) Quy tắc tiền điều kiện đọc nhiệt độ (Mandatory Pre-read Telemetry)
- Phần mềm **CHỈ ĐƯỢC PHÉP** gửi lệnh ghi tốc độ quạt (`cmd = 104` hoặc `cmd = 30`) sau khi đã đọc thành công nhiệt độ hiện tại từ các cảm biến nhiệt phần cứng tương ứng:
  - CPU: `cmd = 2` (`GetCPUtemp`) hoặc `cmd = 3` (`GetCPUtempThermalIC`).
  - GPU: `cmd = 12` (`GetVGA1temp`) hoặc `cmd = 13` (`GetVGA1tempThermalIC`).
- **Xử lý ngoại lệ:** Nếu thao tác đọc nhiệt độ thất bại, hoặc giá trị nhiệt độ trả về nằm ngoài ngưỡng hợp lý về mặt vật lý (ví dụ: `Temp <= 0°C` hoặc `Temp >= 105°C` do lỗi cảm biến/lỗi đọc WMI), phần mềm phải **HỦY BỎ NGAY LẬP TỨC** lệnh ghi tốc độ quạt và lập tức phát lệnh trả về chế độ tự động `cmd = 105` (`SetFanAutoDuty`).

### 7.2. (b) Quy tắc đường lui tự động khi thoát hoặc gặp sự cố (Failsafe Auto Recovery)
- Luôn luôn phải duy trì đường lui an toàn trả quạt về chế độ tự động của firmware EC (`cmd = 105 SetFanAutoDuty`):
  1. **Khi thoát chương trình bình thường (Graceful Exit):** Gửi `cmd = 105` trước khi kết thúc tiến trình.
  2. **Khi nhận tín hiệu dừng đột ngột của hệ điều hành:** Cài đặt bộ đón tín hiệu (Signal Handlers) cho `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT` để phát lệnh `cmd = 105` trước khi thoát.
  3. **Khi gặp ngoại lệ / lỗi truyền thông WMI:** Khối `try ... finally` hoặc cơ chế bảo vệ tương đương bắt buộc phải kích hoạt `cmd = 105`.
  4. **Watchdog Timer nội bộ:** Nếu phần mềm chạy daemon định kỳ điều chỉnh quạt theo đường cong nhiệt độ, phải có bộ đếm thời gian (Watchdog timer ví dụ 5 giây). Nếu luồng tính toán bị treo, phải có cơ chế fallback đưa quạt về Auto.

### 7.3. (c) Cơ chế bảo vệ ngoài tiến trình (Bắt buộc — Out-of-Process Protection)
- **Lý do kỹ thuật:** Bộ đón tín hiệu (Signal Handlers) trong nội bộ tiến trình **bất lực trước lệnh `SIGKILL` (`kill -9`)** hoặc các lỗi sập nguồn/lỗi phân trang (Segmentation Fault / Core Dump) làm tiến trình chết tức thì. Khi đó quạt có thể bị "kẹt cứng" ở mức duty thấp trong khi hệ thống đang chịu tải nặng, dẫn tới quá nhiệt nguy hiểm.
- **Yêu cầu bắt buộc:** Bắt buộc phải thiết lập cơ chế phục hồi độc lập nằm ngoài tiến trình điều khiển chính:
  - **Cấu hình Systemd Service Unit:** Sử dụng chỉ thị `ExecStopPost=` trong file cấu hình service của systemd (ví dụ `ExecStopPost=/usr/bin/clevo-fan-control --set-auto`), đảm bảo systemd sẽ luôn thực thi lệnh trả quạt về Auto (`cmd = 105 SetFanAutoDuty`) trong mọi tình huống tiến trình dịch vụ dừng, dù là thoát êm hay bị kill cứng (`SIGKILL`).
  - **Hoặc Watchdog Daemon độc lập:** Một tiến trình giám sát siêu nhẹ độc lập (hoặc tích hợp với Hardware Watchdog `/dev/watchdog`) theo dõi nhịp tim (heartbeat) của tiến trình chính; nếu tiến trình chính biến mất hoặc treo quá thời hạn cho phép, watchdog ngoài tiến trình sẽ lập tức kích hoạt `cmd = 105`.

### 7.4. (d) Quy tắc giới hạn Duty tối thiểu (Minimum Duty Floor Constraint)
- > [!WARNING]
  > **LƯU Ý QUAN TRỌNG VỀ THÔNG SỐ:** Các con số ngưỡng nhiệt độ và tỷ lệ % duty cycle được nêu dưới đây (như `45°C`, `50°C / 30% duty`, `75°C / 60% duty`, `85°C`) **CHỈ LÀ VÍ DỤ TỰ ĐẶT ĐỂ MINH HỌA NGUYÊN TẮC THIẾT KẾ AN TOÀN, HOÀN TOÀN KHÔNG PHẢI LÀ THÔNG SỐ CHÍNH THỨC CỦA HÃNG GIGABYTE HAY CLEVO**. Bảng quạt và ngưỡng an toàn chuẩn bắt buộc phải được trích xuất từ dữ liệu cấu hình OEM thực tế (ví dụ: phân tích file `FanSpeedSetting\oem.ini`, bảng quạt trong BIOS ACPI/EC) trước khi triển khai thực tế.
- **Nghiêm cấm tắt quạt khi có tải nhiệt:** Tuyệt đối không được phép thiết lập mức tốc độ quạt bằng `0%` (hoặc dừng quạt hoàn toàn) khi nhiệt độ CPU hoặc GPU vượt quá ngưỡng nhiệt độ nghỉ an toàn (ví dụ minh họa: `Temp > 45°C`).
- **Thiết lập sàn tối thiểu (Duty Floor):** Trong mọi điều kiện điều khiển thủ công, mức duty cycle tối thiểu phải được giới hạn cứng trong mã nguồn (Hard Floor):
  - Ví dụ minh họa khi `Temp >= 50°C`: Mức duty tối thiểu không được thấp hơn **30%** (hoặc giá trị duty tương đương do OEM quy định).
  - Ví dụ minh họa khi `Temp >= 75°C`: Mức duty tối thiểu không được thấp hơn **60%**.
  - Ví dụ minh họa khi `Temp >= 85°C`: Bắt buộc kích hoạt chế độ Max Fan hoặc nhường hoàn toàn quyền kiểm soát cho cơ chế bảo vệ phần cứng của EC để chống quá nhiệt (Thermal Throttling / Emergency Shutdown).

---

## 8. Bảng Tổng Hợp MỨC D — NGOÀI PHẠM VI (Out of Scope)

Tất cả các mã lệnh không thuộc 3 mục tiêu Quạt, Đèn bàn phím, Chế độ hiệu năng được tổng hợp gọn gàng trong bảng dưới đây và được phân loại là **Ngoài phạm vi triển khai**:

| Nhóm Thiết Bị Ngoại Vi | Danh Sách Mã `cmd` (Thập phân) | Tên Phương Thức WMI & Ý Nghĩa Tóm Tắt | Trạng Thái Phân Loại | Nguồn Bằng Chứng Kỹ Thuật |
| :--- | :--- | :--- | :--- | :--- |
| **Mạng không dây (WLAN & Bluetooth)** | `5`, `7`, `32`, `33` | `GetRadioStateForWirless` (5), `GetPowerStateForBluetooth` (7), `SetWLan` (32), `SetBT` (33) | Ngoài phạm vi (Quản lý qua `rfkill` / NetworkManager / BlueZ của Linux) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12E7`, `IL_130B`, `IL_147B`, `IL_148E`). |
| **Camera & Ổ đĩa quang (ODD)** | `6`, `11`, `34` | `GetPowerStateForCamera` (6), `GetPowerStateForODD` (11), `SetCamera` (34) | Ngoài phạm vi (Quản lý qua V4L2 / USB subsystem của Linux) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12F9`, `IL_1353`, `IL_14A1`). |
| **Bàn di chuột & Cụm phím số (Touchpad & TenKey)** | `9`, `21`, `42`, `96` | `GetTouchPadState` (9), `SetTenKey` (21), `SetTP` (42), `GetTP_SW` (96) | Ngoài phạm vi (Quản lý qua `libinput` / driver touchpad Linux) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_132F`, `IL_13F6`, `IL_1500`, `IL_18B2`). |
| **Cổng USB & Mạng 3G/WWAN** | `10`, `26`, `76`, `91` | `GetPowerStateFor3G` (10), `ResetUsbHub` (26), `Set3G` (76), `USB` (91) | Ngoài phạm vi (Quản lý qua Linux USB Core & ModemManager) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1341`, `IL_1409`, `IL_174E`, `IL_1866`). |
| **Chế độ máy bay (Airplane Mode)** | `19`, `109` | `SetAirplaneOsd` (19), `AirplaneButton` (109) | Ngoài phạm vi (Quản lý qua Linux input subsystem & desktop environment) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_13E3`, `IL_198B`). |
| **Màn hình, Độ sáng & Cảm biến ánh sáng** | `18`, `31`, `59`, `69`, `75`, `83`, `92`, `93`, `94` | `GetLCDAutoDimmer` (18), `SetLCDAutoDimmer` (31), `GetLCDResolution` (59), `GetCurrentBrightness` (69), `SetXPBrightness` (75), `GetLux` (83), `SetBrightnessLevel` (92, 93), `SetBacklightOff` (94) | Ngoài phạm vi (Quản lý qua chuẩn sysfs `/sys/class/backlight/` và DRM/KMS của Linux) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_13D1`, `IL_1468`, `IL_1620`, `IL_16D4`, `IL_172E`, `IL_17D0`, `IL_1879`, `IL_188C`, `IL_189F`). |
| **Pin, Nguồn & Cổng sạc** | `50`, `51`, `52`, `80`, `81`, `119` | `GetBatteryDesignCpacity` (50), `GetBatteryAverageTimeToFullCharge` (51), `GetBatteryAverageTimeToEmpty` (52), `GetACmA` (80), `GetDCmAmV` (81), `GetChargingStatus` (119) | Ngoài phạm vi (Quản lý qua chuẩn `/sys/class/power_supply/` của Linux) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1598`, `IL_15AA`, `IL_15BC`, `IL_179A`, `IL_17AC`, `IL_1A5B`). |
| **Cảm biến chuyên dụng (RFID, GPS, Barcode, G-Sensor)** | `43`, `46`, `47`, `48`, `62`, `63`, `64`, `65`, `66`, `78` | `SetupRotationdegree` (43), `SetRFID` (46), `SetGPS` (47), `SetBarCode` (48), `GetGSensorMode` (62), `GetHDPollingTime` (63), `GetRFID` (64), `GetGPS` (65), `GetBarCode` (66), `SetSensor` (78) | Ngoài phạm vi (Thiết bị ngoại vi công nghiệp/chuyên dụng không thuộc laptop gaming Gigabyte) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1513`, `IL_154C`, `IL_155F`, `IL_1572`, `IL_1656`, `IL_1668`, `IL_167A`, `IL_168C`, `IL_169E`, `IL_1774`). |
| **Âm thanh, Nút bấm & Đèn LED phụ** | `8`, `27`, `28`, `44`, `45`, `49`, `60`, `87`, `88`, `89`, `90`, `108` | `GetSRSState` (8), `SetEmailLEDOFF` (27), `SetEmailLEDON` (28), `ReturnHDTemp` (44), `ReturnPopupMode` (45), `SetVolumeLED` (49), `GetHDMIport` (60), `SetMuteButton` (87), `SetDocking` (88), `SetMenu` (89), `EmulatedButton` (90), `SetCCDLED` (108) | Ngoài phạm vi (Quản lý qua ALSA/PulseAudio/PipeWire hoặc LED class) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_131D`, `IL_141C`, `IL_142F`, `IL_1526`, `IL_1539`, `IL_1585`, `IL_1632`, `IL_181A`, `IL_182D`, `IL_1840`, `IL_1853`, `IL_1978`). |
| **Đồng hồ RTC & Trạng thái ngủ** | `40`, `41`, `67`, `72`, `74`, `98` | `SetYearMonth` (40), `SetDayHour` (41), `GetBIOS_SF` (67), `OS_S3_S4` (72), `RapidStarMode` (74), `RapidStar` (98) | Ngoài phạm vi (Quản lý qua Linux RTC driver và kernel power state S3/S4) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_14DA`, `IL_14ED`, `IL_16B0`, `IL_170A`, `IL_171C`, `IL_18D6`). |
| **Quản lý Vòng đời WMI & Lệnh No-op** | `0`, `1`, `57`, `58`, `248`, `249`, `251` | `WatchWMI` (0), `StopWatchWmi` (1), No-op (57, 58, 248, 249, 251) | Ngoài phạm vi (Lệnh nội bộ của dịch vụ Windows, không gửi ra WMI bus hoặc nhánh rỗng không thực thi) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1299`, `IL_12A5`, `IL_1616`, `IL_161B`, `IL_1A99`, `IL_1A9B`, `IL_1A9D`). |

---

## 9. Tổng Kết Quy Tắc Kỹ Thuật Khi Triển Khai Driver / Client Trên Linux

1. **Giao tiếp tiêu chuẩn và kiểm chứng thực tế:** Hướng tới giao tiếp Linux WMI Interface tiêu chuẩn thông qua driver của nhân Linux. Tuyệt đối không nhúng hoặc đòi hỏi `acpi_call`. Cần kiểm chứng thực tế trên Nobara live USB xem kernel driver đã có sẵn hay cần bổ sung driver nền tảng phù hợp.
2. **Tuân thủ phân cấp rủi ro:**
   - Các lệnh đọc thuộc **Mức A** được đánh giá là rủi ro thấp nhưng vẫn cần theo dõi tác động phía BIOS.
   - Các lệnh ghi thuộc **Mức B0** bị tạm khóa; chỉ được nâng lên **Mức B** sau khi cấu trúc tham số được xác minh rõ ràng từ REA hoặc kiểm chứng trên Windows.
   - Chặn đứng từ tầng phân tích cú pháp (API parser) mọi yêu cầu gửi lệnh thuộc **Mức C** (đặc biệt là cmd=121, cmd=4 DCHU, ép xung PL1/PL2 page=6, và H2RAM).
   - Bỏ qua các chức năng thuộc **Mức D** để tập trung tối ưu tài nguyên cho Quạt, Đèn bàn phím và Hiệu năng.
3. **An toàn quạt là ưu tiên số 1:**
   - Không đọc được nhiệt độ -> Không cho phép ghi quạt.
   - Luôn tự động trả về Auto (`cmd = 105`) bằng cả cơ chế nội tiến trình lẫn cơ chế bảo vệ ngoài tiến trình (chỉ thị `ExecStopPost=` trong systemd unit hoặc watchdog ngoài tiến trình) khi có bất kỳ sự cố, ngoại lệ, crash hoặc tín hiệu kết thúc nào.
   - Luôn duy trì giới hạn tốc độ quạt tối thiểu (minimum duty floor) không để linh kiện quá nhiệt, với các ngưỡng lấy từ cấu hình OEM thực tế.
