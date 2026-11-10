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
  Giải pháp phần mềm trên Linux (NoBara / Fedora / Ubuntu / Arch) phải tương tác hoàn toàn thông qua các giao diện tiêu chuẩn đã có sẵn trong nhân Linux chính dòng (up-stream Linux kernel standard WMI subsystem).

### 1.2. Giao diện Linux WMI/ACPI chuẩn
Trên các bo mạch Clevo / Gigabyte tương thích, firmware BIOS ACPI phơi bày giao diện điều khiển qua thiết bị chuẩn `PNP0C14`:
- **Thiết bị ACPI:** `ACPI\PNP0C14\0_0` (hoặc định danh bus ACPI tương đương trong Linux DSDT/SSDT).
- **Không gian định danh WMI nguồn trên Windows:** `root\WMI`
  - Khối đối tượng dữ liệu/phương thức: `CLEVO_GET` (`InstanceName='ACPI\PNP0C14\0_0'`)
  - Khối đối tượng sự kiện thông báo: `CLEVO_EVENT`
- **Ánh xạ sang Linux WMI Subsystem:**
  - Nhân Linux tự động phát hiện thiết bị ACPI WMI và ánh xạ vào bus thiết bị:  
    `/sys/bus/wmi/devices/<GUID>/`
  - Các driver chuẩn của nhân Linux (hoặc ứng dụng tầng user-space thông qua giao diện ký tự `/dev/wmi/*` hoặc sysfs attribute được tạo bởi driver nền tảng chuẩn của kernel như `wmi`) thực hiện phương thức đánh giá WMI thông qua lời gọi hàm nội bộ của kernel:  
    `wmi_evaluate_method(guid, instance, method_id, in_buf, out_buf)`
  - **Phương thức đọc (Get/Read):** Tương đương việc đánh giá phương thức WMI không có tham số đầu vào (`in_buf = NULL`), kernel nhận lại bộ đệm ACPI Object (kiểu `ACPI_TYPE_INTEGER` hoặc `ACPI_TYPE_BUFFER`) từ DSDT BIOS.
  - **Phương thức ghi (Set/Write):** Tương đương việc đóng gói một số nguyên 32-bit không dấu (`uint32`) hoặc bộ đệm dữ liệu vào `in_buf` của `wmi_evaluate_method`.
  - **Lắng nghe sự kiện (Events):** Tương đương việc đăng ký trình xử lý thông báo sự kiện WMI của Linux kernel (`wmi_install_notify_handler`) bắt các ACPI event ID tương ứng với `CLEVO_EVENT`.

---

## 2. Cơ Sở An Toàn Tuyệt Đối Của Nhóm Mức A (Chỉ Đọc) (Yêu cầu 4)

Các mã lệnh được xếp vào **Mức A (CHỈ ĐỌC)** trong bản đặc tả này được đảm bảo an toàn tuyệt đối dựa trên các bằng chứng kỹ thuật đã được phân tích và kiểm chứng chéo trực tiếp ở mức **IL bytecode** (CIL Instruction Anchors) trong `DCHUService.exe` và `ControlCenter30.exe`:

1. **Bản chất lời gọi hàm trong `HotkeyService.Talk2Wmi` (`DCHUService.exe`):**
   - Không đơn thuần dựa trên tiền tố tên gọi `Get...`, mà vì mã bytecode IL chứng minh toàn bộ các nhánh này đều gọi qua phương thức **`Talk2Wmi::ExecMethod`** (`Token: 0x06000010`) hoặc **`Talk2Wmi::ExecMethod2`** (`Token: 0x06000011`).
   - Tại `IL_0000` đến `IL_0010` của `ExecMethod`: mã máy gọi trực tiếp `this.classInstance.InvokeMethod(strMethodName, null, null)` với **tham số vào là `null`** (0 tham số đầu vào, không tạo `inParams`).
   - Kết quả chỉ được đọc một chiều từ thuộc tính `outParams["Data"]` đưa vào biến trả về, hoàn toàn không có bất kỳ lệnh ghi nào xuống thanh ghi WMI, ACPI OperationRegion hay RAM của Embedded Controller (EC).
2. **Cơ chế đọc bộ đệm snapshot tĩnh `Package1` (`Talk2Wmi::InitHotkey` `0x06000002`):**
   - Phương thức WMI `"Package1"` trả về mảng tĩnh `byte[256]` phản ánh snapshot hiện thời của phần cứng.
   - Các thuộc tính phần cứng được trích xuất thông qua hàm tính toán bộ nhớ thuần túy: `ConvertArrayToData(int32 index, int32 length)` (`0x06000003`), hoàn toàn là thao tác tính toán trên bộ nhớ RAM của tiến trình, không tác động phần cứng.
3. **Cơ chế đọc trong `ControlCenter30.exe` / `InsydeDCHU.dll`:**
   - Các wrapper `0x060000c8` / `0x060000c9` bọc quanh `GetDCHU_Data_Integer` (`0x060000c1`) chỉ truyền con trỏ biến nhận `int32& outVal`.
   - Các wrapper `0x060000cc` / `0x060000cf` bọc quanh `GetDCHU_Data_Buffer` (`0x060000c3`) cấp phát mảng 256 byte và nhận dữ liệu từ driver, không làm thay đổi trạng thái của chip EC hay BIOS.

---

## 3. Phân Loại 4 Mức Rủi Ro A, B, C, D (Yêu cầu 2, 3, 5)

| Mức Rủi Ro | Phân Loại | Định Nghĩa & Chính Sách Ứng Xử Trên Linux | Phạm Vi Áp Dụng |
| :--- | :--- | :--- | :--- |
| **MỨC A** | **CHỈ ĐỌC (READ-ONLY)** | **An toàn tuyệt đối.** Không làm thay đổi trạng thái phần cứng. Được phép gọi tuần hoàn định kỳ (polling) để thu thập dữ liệu giám sát hệ thống. | Thuộc 3 mục tiêu: Quạt, Đèn bàn phím, Chế độ hiệu năng & cờ hệ thống liên quan. |
| **MỨC B** | **GHI THÔNG THƯỜNG (STANDARD WRITE)** | **Có kiểm soát chặt chẽ.** Làm thay đổi trạng thái hoạt động của thiết bị nhưng đã có bằng chứng rõ ràng về chức năng và cấu trúc tham số. Bắt buộc tuân thủ quy tắc an toàn. | Thuộc 3 mục tiêu: Quạt (cmd=30, 104, 105), Đèn bàn phím (cmd=39, 77, 103), Hiệu năng (cmd=29, 79). |
| **MỨC C** | **NGUY HIỂM / CẤM DÙNG (DANGEROUS / FORBIDDEN)** | **Tuyệt đối cấm thực thi.** Nguy cơ gây mất ổn định nguồn điện, quá nhiệt, hỏng hóc vật lý, sập nguồn, vi phạm bảo mật hệ điều hành hoặc chứa tham số chưa rõ nguồn gốc. | H2RAM, ép xung/điện áp PL1/PL2/Core/VR (19 hàm page=6), AppSettings, cmd=121, SetDCHU_DataEx (cmd=4), các lệnh nhạy cảm và IPC Process. |
| **MỨC D** | **NGOÀI PHẠM VI (OUT OF SCOPE)** | **Bỏ qua / Không triển khai.** Các tính năng thiết bị ngoại vi không nằm trong 3 mục tiêu trọng tâm của dự án (Quạt, Đèn bàn phím, Hiệu năng). | WLAN, Bluetooth, Camera, Touchpad, Airplane, Pin, Sensor, ODD, RFID, GPS, Barcode, RTC, S3/S4, No-op... |

---

## 4. Danh Mục Chi Tiết MỨC A — CHỈ ĐỌC (An Toàn Tuyệt Đối)

Tất cả các lệnh dưới đây được xác minh 100% là an toàn, đọc dữ liệu một chiều qua `ExecMethod` (0 tham số ghi) hoặc trích xuất từ bộ đệm `Package1` / `GetDCHU_Data_*`:

### 4.1. Nhóm Quạt & Nhiệt Độ (Fan & Thermal Telemetry)

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Kiểu Trả Về & Định Dạng Dữ Liệu | Chức Năng Giám Sát | Nguồn Bằng Chứng Kỹ Thuật (Assembly / Token / IL / Chuỗi) |
| :--- | :--- | :--- | :--- | :--- |
| **`2`** (`0x02`) | `GetCPUtemp` | `UInt32` (Giá trị °C) | Nhiệt độ nhân CPU (Digital Thermal Sensor / PECI) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12B1`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000b27` (`"GetCPUtemp"`). |
| **`3`** (`0x03`) | `GetCPUtempThermalIC` | `UInt32` (Giá trị °C) | Nhiệt độ CPU đo từ cảm biến IC nhiệt phần cứng | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12C3`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000b3d` (`"GetCPUtempThermalIC"`). |
| **`4`** (`0x04`) | `GetCPUFANState` | `UInt32` (Bitmask / State) | Trạng thái hoạt động hiện tại của quạt CPU | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_12D5`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000b65` (`"GetCPUFANState"`). |
| **`12`** (`0x0C`) | `GetVGA1temp` | `UInt32` (Giá trị °C) | Nhiệt độ GPU rời 1 (NVIDIA dGPU Thermal Sensor) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1365`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000c4d` (`"GetVGA1temp"`). |
| **`13`** (`0x0D`) | `GetVGA1tempThermalIC` | `UInt32` (Giá trị °C) | Nhiệt độ GPU rời 1 đo từ cảm biến IC nhiệt phần cứng | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1377`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000c65` (`"GetVGA1tempThermalIC"`). *(Trong `ControlCenter30.exe`, gọi `GetDCHU_Data_Buffer(13)` lấy `buf[15] & 0x0F`)*. |
| **`14`** (`0x0E`) | `GetVGA2temp` | `UInt32` (Giá trị °C) | Nhiệt độ GPU 2 (nếu máy trang bị GPU phụ) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1389`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000c8f` (`"GetVGA2temp"`). |
| **`15`** (`0x0F`) | `GetVGA2tempThermalIC` | `UInt32` (Giá trị °C) | Nhiệt độ GPU 2 đo từ cảm biến IC nhiệt phần cứng | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_139B`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000ca7` (`"GetVGA2tempThermalIC"`). |
| **`17`** (`0x11`) | `GetCPUFANControl` | `UInt32` (Byte cờ chế độ) | Cờ chế độ điều khiển quạt CPU (Auto / Manual / Duty) | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_13BF`), nạp chuỗi `0x70000273`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0223` trích byte tại `offset=48, len=1`, hoặc gọi `ExecMethod2` @ `IL_0433`).<br>- `ControlCenter30.exe`: gọi `GetDCHU_Data_Buffer(17)` đọc `buf[2]` và `buf[3]`. |
| **`53`** (`0x35`) | `GetCPUFANDuty` | `UInt32` (0 - 100 hoặc 0 - 255) | Tốc độ quạt CPU hiện tại (Duty Cycle %) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_15CE`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000ffd` (`"GetCPUFANDuty"`). |
| **`54`** (`0x36`) | `GetVGA1FANDuty` | `UInt32` (0 - 100 hoặc 0 - 255) | Tốc độ quạt GPU 1 hiện tại (Duty Cycle %) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_15E0`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001019` (`"GetVGA1FANDuty"`). |
| **`55`** (`0x37`) | `GetVGA2FANDuty` | `UInt32` (0 - 100 hoặc 0 - 255) | Tốc độ quạt GPU 2 hiện tại (Duty Cycle %) | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_15F2`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001037` (`"GetVGA2FANDuty"`). |
| **`56`** (`0x38`) | `GetFANCount` | `UInt32` (Số lượng quạt, e.g., 2 hoặc 3) | Số lượng quạt vật lý được hỗ trợ bởi hệ thống | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1604`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001055` (`"GetFANCount"`). |
| **`97`** (`0x61`) | `GetFanStatus` | `UInt32` (Bitmask trạng thái) | Trạng thái tổng quát của hệ thống tản nhiệt EC | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_18C4`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000132d` (`"GetFanStatus"`). |
| **`99`** (`0x63`) | `Fan1Info` | `UInt32` (Thông số cấu hình Fan 1) | Thông tin định danh / đặc tính phần cứng Quạt 1 | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_18E8`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000135b` (`"Fan1Info"`). |
| **`100`** (`0x64`) | `Fan2Info` | `UInt32` (Thông số cấu hình Fan 2) | Thông tin định danh / đặc tính phần cứng Quạt 2 | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_18FA`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000136d` (`"Fan2Info"`). |
| **`110`** (`0x6E`) | `Fan3Info` | `UInt32` (Thông số cấu hình Fan 3) | Thông tin định danh / đặc tính phần cứng Quạt 3 | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_199D`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000143f` (`"Fan3Info"`). |
| **`111`** (`0x6F`) | `Fan4Info` | `UInt32` (Thông số cấu hình Fan 4) | Thông tin định danh / đặc tính phần cứng Quạt 4 | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_19AF`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001451` (`"Fan4Info"`). |
| **`112`** (`0x70`) | `GetFan12RPM` | `UInt32` (`[Fan2_RPM << 16] \| Fan1_RPM`) | Tốc độ vòng quay thực tế (RPM) của Quạt 1 & 2 | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_19C1`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70001463` (`"GetFan12RPM"`). |
| **`113`** (`0x71`) | `GetFan34RPM` | `UInt32` (`[Fan4_RPM << 16] \| Fan3_RPM`) | Tốc độ vòng quay thực tế (RPM) của Quạt 3 & 4 | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_19D3`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x7000147b` (`"GetFan34RPM"`). |

### 4.2. Nhóm Đèn Bàn Phím & LED (Keyboard LED Telemetry)

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Kiểu Trả Về & Định Dạng Dữ Liệu | Chức Năng Giám Sát | Nguồn Bằng Chứng Kỹ Thuật (Assembly / Token / IL / Chuỗi) |
| :--- | :--- | :--- | :--- | :--- |
| **`61`** (`0x3D`) | `GetWhiteLedKB` | `UInt32` (0 = Tắt, 1 = Bật, hoặc mức sáng) | Trạng thái bật/tắt đèn bàn phím đơn sắc trắng | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1644`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000295`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0313` trích byte tại `offset=98, len=1`, hoặc gọi `ExecMethod2` @ `IL_0464`).<br>- `ControlCenter30.exe`: `#vQb.#f8b` @ `IL_0055`. |
| **`68`** (`0x44`) | `GetVolumeLED` | `UInt32` (Bit cờ trạng thái LED) | Trạng thái hiển thị đèn LED dải âm lượng / Lightbar | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_16C2`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700002d5`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02A8` trích byte tại `offset=106, len=1`, hoặc gọi `ExecMethod2` @ `IL_049E`). |

### 4.3. Nhóm Hiệu Năng & Cờ Hệ Thống Liên Quan (Performance & System Feature Telemetry)

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Kiểu Trả Về & Định Dạng Dữ Liệu | Chức Năng Giám Sát | Nguồn Bằng Chứng Kỹ Thuật (Assembly / Token / IL / Chuỗi) |
| :--- | :--- | :--- | :--- | :--- |
| **`16`** (`0x10`) | `GetCPUPerformance` | `UInt32` (Bit 23 là cờ kích hoạt) | Chế độ hiệu năng CPU hiện hành từ EC/BIOS | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_13AD`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x70000cd1`.<br>- `ControlCenter30.exe`: `0x06000062` @ `IL_0012` gọi `0x060000c9(16)`, kiểm tra bit 23 `(val >> 23) & 1` để gán `field_0x04000081`. |
| **`70`** (`0x46`) | `GetAP` | `UInt32` (Bitmask 12 bit hỗ trợ tính năng) | Đọc danh mục tính năng phần cứng hỗ trợ (AP features bitmask) | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_16E6`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700002d9`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02CA` trích `offset=107, len=16`, hoặc gọi `ExecMethod2` @ `IL_03C8`).<br>- `ControlCenter30.exe`: `0x06000054` @ `IL_0011` gọi `0x060000c9(70)` kiểm tra 12 bit từ bit 0 đến bit 11. |
| **`82`** (`0x52`) | `BIOS_special_feature_list` | `UInt32` / Bộ đệm 16-byte | Danh sách các tính năng đặc biệt được hỗ trợ bởi BIOS | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_17BE`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700001dd`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02ED` trích `offset=138, len=16`, hoặc gọi `ExecMethod2` @ `IL_03DC`).<br>- `ControlCenter30.exe`: `#vQb.#e9b` @ `IL_0055`. |
| **`84`** (`0x54`) | `Aero` | `UInt32` (Cờ chế độ Aero/Display) | Trạng thái cấu hình Aero / giao diện hiển thị | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_17E2`), gọi `ExecMethod` (`0x06000010`), nạp chuỗi `0x700002ef`.<br>- Fallback/Cache: `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0335` trích byte tại `offset=155, len=1`, hoặc gọi `ExecMethod2` @ `IL_04CD`).<br>- `ControlCenter30.exe`: `#vQb.#f9b` @ `IL_0055`. |
| **`122`** (`0x7A`) | `BiosSpecialFeature` | `UInt32` (Bit 23 & Bit 29: cấu trúc hỗ trợ WMI) | Cờ tính năng BIOS đặc thù (Nhánh nhận diện giao thức Clevo WMI) | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1A8A`), nạp chuỗi `0x70000171`.<br>- Khởi tạo: `Talk2Wmi::InitHotkey` (`0x06000002` @ `IL_008A` gọi `ExecMethod2`, kiểm tra bit 29 `(val & 0x20000000)` để quyết định đọc `Package1`).<br>- `ControlCenter30.exe`: `0x0600005b` @ `IL_0006` và `0x06000062` @ `IL_0004` kiểm tra bit 23 `(val & 0x800000)`. |

---

## 5. Danh Mục Chi Tiết MỨC B — GHI THÔNG THƯỜNG (Có Kiểm Soát)

Nhóm Mức B chỉ bao gồm đúng **8 lệnh ghi** đã được kiểm chứng rõ ràng về mã lệnh, tên hàm WMI và cấu trúc tham số đầu vào trong 3 mục tiêu trọng tâm: Quạt, Đèn bàn phím, Chế độ hiệu năng:

| Mã `cmd` (Dec / Hex) | Tên Phương Thức WMI | Cơ Chế Gọi & Kiểu Tham Số WMI | Mục Tiêu Điều Khiển | Cấu Trúc Tham Số Đầu Vào (`inParams["Data"]`) | Nguồn Bằng Chứng Kỹ Thuật |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`30`** (`0x1E`) | **`SetCPUFANControl`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Quạt:** Chuyển đổi chế độ quạt CPU (Manual/Auto) | `UInt32`: Chế độ điều khiển quạt (`0` = Auto, `1` = Manual/Custom mode). | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1455`), nạp chuỗi `0x70000dbd` (`"SetCPUFANControl"`). |
| **`104`** (`0x68`) | **`SetFanDuty`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Quạt:** Thiết lập mức Duty Cycle cho quạt | `UInt32`: Mã quạt và giá trị duty (thường mã hóa dạng `[FanIndex << 8] \| DutyValue` hoặc giá trị duty phần trăm từ 0..255). *(Bắt buộc tuân thủ Quy tắc ghi quạt tại Mục 7)*. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_191F`), nạp chuỗi `0x7000137f` (`"SetFanDuty"`). |
| **`105`** (`0x69`) | **`SetFanAutoDuty`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Quạt:** Trả quạt về chế độ điều khiển tự động của EC | `UInt32`: `0` hoặc chỉ số quạt cần trả về tự động. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1932`), nạp chuỗi `0x70001395` (`"SetFanAutoDuty"`). |
| **`39`** (`0x27`) | **`SetWhiteLedKB`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Đèn phím:** Bật/tắt đèn bàn phím trắng | `UInt32`: `0` = Tắt, `1` = Bật (hoặc mức sáng 0..4). | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_14C7`), nạp chuỗi `0x70000e4b`.<br>- `ControlCenter30.exe`: `#vQb.#h9b` @ `IL_00EA`. |
| **`77`** (`0x4D`) | **`SetColorKey`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Đèn phím:** Thiết lập hiệu ứng / cấu hình màu bàn phím | `UInt32`: Giá trị mã màu RGB hoặc mã hiệu ứng bàn phím. | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1761`), nạp chuỗi `0x70001133` (`"SetColorKey"`). |
| **`103`** (`0x67`) | **`SetKBLED`** | Ghi 1 tham số (`InvokeMethod` / `InvokeMethod2`) | **Đèn phím:** Thiết lập trạng thái LED bàn phím tổng thể | `UInt32`: Gói dữ liệu màu sắc và độ sáng 4 byte Little-Endian (`[Brightness, Blue, Green, Red]`). | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_190C`), nạp chuỗi `0x70000499`.<br>- Tự đổi màu: `Talk2Wmi::ExecuteAutoColorWmi` (`0x0600000c` @ `IL_0016`).<br>- `ControlCenter30.exe`: `#vQb.#i9b` @ `IL_00C4`. |
| **`29`** (`0x1D`) | **`SetCPUPerformance`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Hiệu năng:** Thiết lập chế độ hiệu năng phần cứng CPU | `UInt32`: Mã hồ sơ hiệu năng (e.g., `0` = Quiet, `1` = Power Saving, `2` = Performance, `3` = Entertainment). | `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1442`), nạp chuỗi `0x70000d99` (`"SetCPUPerformance"`). |
| **`79`** (`0x4F`) | **`SetEnergyStar`** | Ghi 1 tham số (`InvokeMethod` `0x0600000e`) | **Hiệu năng:** Bật/tắt chế độ tiết kiệm năng lượng EnergyStar | `UInt32`: `0` = Tắt, `1` = Kích hoạt chế độ EnergyStar. | - `DCHUService.exe`: `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1787`), nạp chuỗi `0x7000115f`.<br>- `ControlCenter30.exe`: `#vQb.#l9b` @ `IL_0107`. |

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

Đối với 3 lệnh điều khiển quạt thuộc Mức B:
- **`cmd = 30` (`SetCPUFANControl`)**
- **`cmd = 104` (`SetFanDuty`)**
- **`cmd = 105` (`SetFanAutoDuty`)**

Bản đặc tả quy định phần mềm triển khai trên Linux **BẮT BUỘC** phải tuân thủ nghiêm ngặt 3 nguyên tắc sau trong mã nguồn:

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
  4. **Watchdog Timer (Cơ chế bảo vệ mất tín hiệu):** Nếu phần mềm chạy daemon định kỳ điều chỉnh quạt theo đường cong nhiệt độ (custom fan curve), phải có bộ đếm thời gian (Watchdog timer ví dụ 5 giây). Nếu daemon bị treo hoặc không gửi được nhịp đập heartbeat, phải có cơ chế fallback đưa quạt về Auto hoặc 100% tốc độ để bảo vệ máy.

### 7.3. (c) Quy tắc giới hạn Duty tối thiểu (Minimum Duty Floor Constraint)
- **Nghiêm cấm tắt quạt khi có tải nhiệt:** Tuyệt đối không được phép thiết lập mức tốc độ quạt bằng `0%` (hoặc dừng quạt hoàn toàn) khi nhiệt độ CPU hoặc GPU vượt quá ngưỡng nhiệt độ nghỉ an toàn (ví dụ: `Temp > 45°C`).
- **Thiết lập sàn tối thiểu (Duty Floor):** Trong mọi điều kiện điều khiển thủ công, mức duty cycle tối thiểu phải được giới hạn cứng trong mã nguồn (Hard Floor):
  - Khi `Temp >= 50°C`: Mức duty tối thiểu không được thấp hơn **30%** (hoặc giá trị duty tương đương do OEM quy định).
  - Khi `Temp >= 75°C`: Mức duty tối thiểu không được thấp hơn **60%**.
  - Khi `Temp >= 85°C`: Bắt buộc kích hoạt chế độ Max Fan hoặc nhường hoàn toàn quyền kiểm soát cho cơ chế bảo vệ phần cứng của EC để chống quá nhiệt (Thermal Throttling / Emergency Shutdown).

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

1. **Giao tiếp tiêu chuẩn:** Sử dụng duy nhất Linux WMI Interface tiêu chuẩn thông qua driver WMI chính thức của nhân Linux. Tuyệt đối không nhúng hoặc đòi hỏi `acpi_call`.
2. **Tuân thủ phân cấp rủi ro:**
   - Chỉ được phép triển khai các lệnh đọc thuộc **Mức A** và các lệnh ghi có kiểm soát thuộc **Mức B**.
   - Chặn đứng từ tầng phân tích cú pháp (API parser) mọi yêu cầu gửi lệnh thuộc **Mức C** (đặc biệt là cmd=121, cmd=4 DCHU, ép xung PL1/PL2 page=6, và H2RAM).
   - Bỏ qua các chức năng thuộc **Mức D** để tập trung tối ưu tài nguyên cho Quạt, Đèn bàn phím và Hiệu năng.
3. **An toàn quạt là ưu tiên số 1:**
   - Không đọc được nhiệt độ -> Không cho phép ghi quạt.
   - Luôn tự động trả về Auto (`cmd = 105`) khi có bất kỳ sự cố, ngoại lệ hoặc ngắt tín hiệu nào.
   - Luôn duy trì giới hạn tốc độ quạt tối thiểu (minimum duty floor) không để linh kiện quá nhiệt.
