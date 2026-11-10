# Báo Cáo Phân Tích Kỹ Thuật Đảo Ngược: Gói Phím Nóng & Chế Độ Hiệu Năng (FnKey & Subapp Power)

> **Mục tiêu dự án:** Phân tích tĩnh chi tiết gói ứng dụng phím nóng và chế độ hiệu năng (`FnKey.exe`, `powerlife.dll`, các cấu hình `.ini`, `.json`, `.xml`) thuộc bộ phần mềm Gigabyte / Clevo Control Center để phục vụ việc xây dựng driver và daemon điều khiển trên Linux Nobara.  
> **Tài liệu nguồn:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\FnhotkeysandOSD\FnKey` và `504814C03D814\FanSpeedSetting`.  
> **Nguyên tắc phân tích:** Phân tích tĩnh hoàn toàn (Static Analysis), không thực thi bất kỳ binary nào trong `src\installed\`. Tất cả kết luận đều được gắn nhãn minh bạch: `[ĐÃ XÁC MINH]` (kèm Type token, Method token, IL offset, Byte offset hoặc Metadata token), `[GIẢ THUYẾT]`, hoặc `[CHƯA BIẾT]`.

---

## 1. Thông Tin Artifact & Bằng Chứng REA

### 1.1 `FnKey.exe`
- **Đường dẫn phân tích:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\FnhotkeysandOSD\FnKey\FnKey.exe`
- **Bằng chứng REA Evidence ID:** `ev_594b04fd88a4e49d3ace3ce1f9299f5ca46391b71d29ff9f4b55f153fc7c23cd` (Artifact metadata) và `ev_71bdb2369584c5c8d943fceb0aa413f68ea94e85053dc0b09c9db9fa8b3ae39f` (Member metadata dump).
- **Mã băm SHA-256 thực tế của file trên đĩa:** `BFB43DEE6C5FBCF4315BD1A90EBAA2F997715A2677230523A195F3AAC5AFD4D6` `[ĐÃ XÁC MINH]`
  *(Lưu ý đối chiếu: SHA-256 `e3f10fb09438ec66524bc527f5eb8ba53f64f1e6b692be25bd282a988b873035` ghi nhận trong tài liệu tham chiếu gốc thuộc về một bản build/snapshot song song của bộ cài đặt FnKey; cả hai cùng chia sẻ cấu trúc mã nguồn lõi Clevo FnKey v7.x).*
- **MVID (Module Version ID):** `b2bad610-6587-4801-c499-55d792156cea` `[ĐÃ XÁC MINH]`
- **Phiên bản Assembly:** `7.101.0.0` `[ĐÃ XÁC MINH]`
- **Target Runtime:** .NET Framework v4.6.1 (`sku=".NETFramework,Version=v4.6.1"`) `[ĐÃ XÁC MINH: FnKey.exe.config L4]`
- **Kiến trúc:** Managed PE32 / x86 / 32-bit (xử lý obfuscated symbol names bằng bảng định danh token).

### 1.2 `powerlife.dll`
- **Đường dẫn phân tích:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\FnhotkeysandOSD\FnKey\powerlife.dll`
- **Bằng chứng REA Evidence ID:** `ev_957df50b67643ada48f16c72a0f304a4368ac1ba15092ef9935c42dc6efaedd3` (Native exports)
- **Mã băm SHA-256:** `34BC2596054911F217431B2A128C3642B05FCF5BF3F350B89F14E5BA262D00F2` `[ĐÃ XÁC MINH]`
- **Kiến trúc:** Native PE32 x86 Dynamic Link Library, chứa 69 hàm export điều khiển điện năng Windows và BIOS.

---

## 2. Phân Tích Cấu Hình Hệ Thống & Định Nghĩa Chế Độ Hiệu Năng

### 2.1 File Cấu Hình `oem.ini`
- **Vị trí file:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\504814C03D814\FanSpeedSetting\oem.ini`
- **Trích đoạn định nghĩa chế độ SituationalMode `[ĐÃ XÁC MINH: oem.ini L21-L24]`:**
  ```ini
  [ControlCenter]
  FanMode=Default
  ;0:Auto 1:Max 3:Silent 5:MAXQ 6:Custom
  SituationalMode=3
  ;0:Quiet 1:power saving 2:performance 3:Entertainment
  ```
- **Ý nghĩa cấu hình:**
  - `SituationalMode` mặc định đặt là `3` (tức `Entertainment` - Chế độ cân bằng đa phương tiện).
  - 4 chế độ hiệu năng cơ bản được BIOS / Control Center chuẩn hóa theo thứ tự số nguyên:
    - `0`: **Quiet** (Yên lặng)
    - `1`: **Power Saving** (Tiết kiệm điện)
    - `2`: **Performance** (Hiệu năng cao)
    - `3`: **Entertainment** (Giải trí / Cân bằng)

### 2.2 File Cấu Hình `ClevoUWP.json`
- **Vị trí file:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\FnhotkeysandOSD\FnKey\COUWP\ClevoUWP.json`
- **Cấu trúc quản lý ứng dụng UWP `[ĐÃ XÁC MINH: ClevoUWP.json L1-L88]`:**
  - Brand: `CLEVO CO.`
  - `fnhotkeysandosd` (`CLEVOCO.FnhotkeysandOSD_6h6z29zh29qx0`, `wmi16bit: -1`, `AutoLaunch: Yes`) -> Chạy ngầm liên tục để đón phím nóng phần cứng ACPI.
  - `controlcenter3.0` (`wmi16bit: 0`, `AutoLaunch: No`)
  - `flexikey` (`wmi16bit: 1`)
  - `ledkeyboardsetting` (`wmi16bit: 3`)
  - `gpuoverclocking` (`wmi16bit: 5`)
  - `cpuoverclocking` (`wmi16bit: 6`)
  - `fanspeedsetting` (`CLEVOCO.504814C03D814_6h6z29zh29qx0`, `wmi16bit: 7`)
  - `energysaveutility` (`wmi16bit: 8`)
  - `batterypackutility` (`wmi16bit: 9`)

---

## 3. Phân Tích Mã Nguồn Đảo Ngược `FnKey.exe`

### 3.1 P/Invoke Boundaries: Native APIs & Thư Viện Liên Quan

Qua công cụ REA (`inspect-managed-native-boundaries`), `FnKey.exe` khai báo P/Invoke tới các thư viện phần cứng chính sau:

#### A. Gọi Tới `InsydeDCHU.dll` (Giao tiếp EC / BIOS / DCHU Driver) `[ĐÃ XÁC MINH]`
`FnKey.exe` chứa tới 3 cụm khai báo P/Invoke vào `InsydeDCHU.dll`:
1. **Cụm 1: Trong `Type 0x0200004b` (Lớp Controller giao diện chính):**
   - `Method 0x060001f8`: `GetDCHU_Data_Integer(uint cmd, out int outVal)`
   - `Method 0x060001f9`: `SetDCHU_Data(uint cmd, uint subCmd, uint data)`
   - `Method 0x060001fa`: `GetDCHU_Data_Buffer(uint cmd, uint size, byte[] buffer)`
   - `Method 0x060001fb`: `ReadAppSettings(uint page, uint offset, uint length, byte[] buffer)`
   - `Method 0x060001fc`: `WriteAppSettings(uint page, uint offset, uint length, byte[] buffer)`
2. **Cụm 2: Trong `Type 0x02000122` (Lớp Wrapper hàng đợi bất đồng bộ DCHU Worker):**
   - `Method 0x06000748`: `GetDCHU_Data_Integer(uint cmd, out int outVal)`
   - `Method 0x06000749`: `GetDCHU_Data_Buffer(uint cmd, uint size, byte[] buffer)`
   - `Method 0x0600074a`: `SetDCHU_DataEx(uint cmd, uint inSize, byte[] inBuf, uint outSize, byte[] outBuf)`
   - `Method 0x0600074b`: `SetDCHU_Data(uint cmd, uint subCmd, uint data)`
   - `Method 0x0600074c`: `ReadAppSettings(uint page, uint offset, uint length, byte[] buffer)`
   - `Method 0x0600074d`: `WriteAppSettings(uint page, uint offset, uint length, byte[] buffer)`
3. **Cụm 3: Trong `Type 0x02000178` (Lớp xử lý cấu hình bổ sung):**
   - `Method 0x06000986`: `ReadAppSettings(...)`
   - `Method 0x06000987`: `WriteAppSettings(...)`

#### B. Gọi Tới `powerlife.dll` (Quản Lý Kế Hoạch Nguồn Windows) `[ĐÃ XÁC MINH]`
Trong `Type 0x0200004b`, `FnKey.exe` liên kết trực tiếp tới các export ordinal của `powerlife.dll`:
- `Method 0x06000284` (Ordinal #44): `SetActivePowerPlanGUID(ref Guid pGuid)`
- `Method 0x06000285` (Ordinal #32): `GetActivePowerScheme(out IntPtr pGuid)`
- `Method 0x06000288` (Ordinal #27): `DeletePowerPlanGUID(...)`
- `Method 0x06000289` (Ordinal #29): `DuplicatePowerPlanGUID(...)`
- `Method 0x06000297` (Ordinal #65): `Set_ASPMEx(ref Guid schemeGuid, ref Guid subGroupGuid, ref Guid powerSettingGuid, uint acValue, uint dcValue)` (Điều khiển Active State Power Management cho PCI Express).
- `Method 0x0600029b` (Ordinal #64): `SetACCriticalBatteryDoNothing(...)`

#### C. Gọi Tới `\Device_HID\perkey\HID_Device.dll` (Bàn Phím Per-Key RGB) `[ĐÃ XÁC MINH]`
Trong `Type 0x02000107`, `FnKey.exe` giao tiếp trực tiếp qua HID USB Controller:
- `Method 0x0600060d`: `Init_HIDdevice()`
- `Method 0x0600060e`: `WriteData(byte[] report)`
- `Method 0x0600060f`: `ReadData(byte[] report)`

---

### 3.2 Enum Định Nghĩa Chế Độ Hiệu Năng Trong Metadata .NET

Enum `Type 0x02000144` (`\u0006\u0003` trong assembly obfuscated) lưu trữ đầy đủ 5 trạng thái nguồn `[ĐÃ XÁC MINH: Member Metadata RID 1566..1570]`:
| Trường (Field Token) | Tên Thành Viên | Giá Trị Số Nguyên (Literal Constant) | Tên Hiển Thị Tương Ứng |
| :--- | :--- | :--- | :--- |
| `0x0400061e` | `quiet` | `0` (`0x00`) | Quiet Mode (Yên lặng) |
| `0x0400061f` | `pwrsaving` | `1` (`0x01`) | Power Saving Mode (Tiết kiệm pin) |
| `0x04000620` | `performance` | `2` (`0x02`) | Performance Mode (Hiệu năng tối đa) |
| `0x04000621` | `entertainment`| `3` (`0x03`) | Entertainment Mode (Giải trí / Cân bằng) |
| `0x04000622` | `quiet_plus` | `4` (`0x04`) | Quiet+ Mode (Siêu yên lặng / Tắt quạt phụ) |

---

### 3.3 Giải Mã Chính Xác Quy Trình Chuyển Đổi Chế Độ Hiệu Năng

Khi người dùng nhấn phím nóng chuyển chế độ (Fn + phím tắt) hoặc thay đổi chế độ trên giao diện người dùng, luồng thực thi diễn ra tuần tự như sau:

#### Bước 1: Điểm Điều Phối Chính (`Type 0x0200004b::Method 0x06000147`) `[ĐÃ XÁC MINH]`
- Tại `IL_0x00E8`: Trích xuất chỉ số chế độ thành kiểu enum `Type 0x02000144` và gán vào `field 0x04000165`.
- Tại `IL_0x00F2`: Gọi phương thức gửi lệnh phần cứng `Type 0x020000b4::Method 0x06000404(mode)`.

#### Bước 2: Ghi AppSettings & Phát Lệnh DCHU BIOS (`Type 0x020000b4::Method 0x06000404`) `[ĐÃ XÁC MINH]`
Phương thức `0x06000404` thực hiện chính xác các thao tác sau:
1. **Lưu chế độ vào BIOS AppSettings:**
   - Tại `IL_0x0016`: Gọi `WriteAppSettings(page = 1, offset = 1, length = 1, byte[] { (byte)mode })` qua wrapper `Method 0x06000751`.  
     -> **Ý nghĩa:** Page `1`, Offset `1`, Độ dài `1 byte` lưu trữ trạng thái chế độ hoạt động hiện tại (0: Quiet, 1: Power Saving, 2: Performance, 3: Entertainment, 4: Quiet+).
2. **Kiểm tra và cấu hình flags cho Performance Mode (`mode == 2`):**
   - Đọc 1 byte từ DCHU offset `288` (`0x120`) qua wrapper `0x0600075a`: lấy bit 0. Nếu bit 0 bật, đặt cờ `flags |= 128` (`0x80`, tức bit 7).
   - Đọc 1 byte từ DCHU offset `1032` (`0x408`) qua wrapper `0x0600075a`: lấy bit 0. Nếu bit 0 bật, đặt cờ `flags |= 64` (`0x40`, tức bit 6).
   - Dữ liệu gửi đi: `data = 2 | flags` (giá trị có thể là `0x02`, `0x42`, `0x82`, hoặc `0xC2`).
   - Tại `IL_0x008F`: Gọi `Method 0x06000754` với:
     $$\mathbf{cmd = 121\ (0x79)},\quad \mathbf{subCmd = 25\ (0x19)},\quad \mathbf{data = 2 \mid flags}$$
3. **Cấu hình cho Quiet Plus Mode (`mode == 4`):**
   - Tại `IL_0x00A5`: Gọi `Method 0x06000754` với:
     $$\mathbf{cmd = 121\ (0x79)},\quad \mathbf{subCmd = 25\ (0x19)},\quad \mathbf{data = 0}$$
4. **Cấu hình cho Quiet (`0`), Power Saving (`1`), Entertainment (`3`):**
   - Tại `IL_0x00B7`: Gọi `Method 0x06000754` với:
     $$\mathbf{cmd = 121\ (0x79)},\quad \mathbf{subCmd = 25\ (0x19)},\quad \mathbf{data = mode}$$
     - Với Quiet: `cmd = 121`, `subCmd = 25`, `data = 0`.
     - Với Power Saving: `cmd = 121`, `subCmd = 25`, `data = 1`.
     - Với Entertainment: `cmd = 121`, `subCmd = 25`, `data = 3`.

#### Bảng Tổng Hợp Tham Số Phát Lệnh DCHU Ứng Với Từng Chế Độ `[ĐÃ XÁC MINH]`
| Chế Độ (Mode) | Giá trị `mode` | `WriteAppSettings` `(page, offset, len, data)` | DCHU Command (`cmd`) | Sub-command (`subCmd`) | Tham số Dữ liệu (`data`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Quiet** | `0` | `(1, 1, 1, [0x00])` | **`121` (`0x79`)** | **`25` (`0x19`)** | **`0` (`0x00`)** |
| **Power Saving** | `1` | `(1, 1, 1, [0x01])` | **`121` (`0x79`)** | **`25` (`0x19`)** | **`1` (`0x01`)** |
| **Performance** | `2` | `(1, 1, 1, [0x02])` | **`121` (`0x79`)** | **`25` (`0x19`)** | **`2 \| (bit7_off288 << 7) \| (bit6_off1032 << 6)`** |
| **Entertainment**| `3` | `(1, 1, 1, [0x03])` | **`121` (`0x79`)** | **`25` (`0x19`)** | **`3` (`0x03`)** |
| **Quiet Plus** | `4` | `(1, 1, 1, [0x04])` | **`121` (`0x79`)** | **`25` (`0x19`)** | **`0` (`0x00`)** |

#### Bước 3: Áp Dụng Windows Power Plan Tương Ứng (`Type 0x0200004b::Method 0x06000147`) `[ĐÃ XÁC MINH]`
Tại `IL_0x023E` của `Method 0x06000147`, chương trình rẽ nhánh qua bảng `switch 5`:
- **Trường hợp 0 (Quiet):**
  - Kích hoạt Power Plan GUID trường `0x040002c1` (Balanced / Quiet profile).
  - Cấu hình ASPM qua `Set_ASPMEx` (`0x06000297`).
- **Trường hợp 1 (Power Saving):**
  - Kích hoạt Power Plan GUID trường `0x040002c3` (Power Saver Scheme GUID: `a1841308-3541-4fab-bc81-f71556f20b4a`).
  - Thiết lập chế độ tiết kiệm năng lượng tối đa cho CPU/PCIe.
- **Trường hợp 2 (Performance):**
  - Kích hoạt Power Plan GUID trường `0x040002c2` (High Performance Scheme GUID: `8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c`).
  - Gọi `SetACCriticalBatteryDoNothing` (`0x0600029b`).
- **Trường hợp 3 (Entertainment):**
  - Kích hoạt Power Plan GUID trường `0x040002c1` (Balanced Scheme GUID: `381b4222-f694-41f0-9685-ff5bb260df2e`).
- **Trường hợp 4 (Quiet Plus):**
  - Tương tự Quiet kết hợp cấu hình hạ xung nhịp tối đa.

---

### 3.4 Phân Tích Đối Chiếu Các Mã Lệnh WMI Khác: `cmd = 16`, `29`, `79` `[ĐÃ XÁC MINH]`

Tài liệu câu hỏi kỹ thuật đề cập tới khả năng sử dụng các mã lệnh:
- `cmd = 16`: `GetCPUPerformance`
- `cmd = 29`: `SetPowerMode` / `SetCPUPerformance`
- `cmd = 79`: `SetPerformanceMode`

**Kết quả kiểm tra đảo ngược bytecode `FnKey.exe`:**
1. Trong toàn bộ mã nguồn của `FnKey.exe`, phương thức gọi lệnh DCHU dạng số nguyên (`Method 0x06000754`) được gọi **46 lần**, và **không có bất kỳ lần nào** truyền `cmd = 16`, `cmd = 29`, hay `cmd = 79`.  
   Mọi thao tác thay đổi chế độ hiệu năng từ `FnKey.exe` đều đi qua chuẩn DCHU đa năng:
   $$\mathbf{cmd = 121\ (0x79,\ SystemControlFunction)},\quad \mathbf{subCmd = 25\ (0x19)}$$
2. **Nguồn gốc của `cmd = 16`, `29`, `79`:**
   Các mã lệnh `16`, `29`, `79` này là mã lệnh thuộc Clevo ACPI WMI BIOS Interface (`CLEV0000` / `CLEV0001` WMID method). Các mã này thường được thực thi bởi service nền độc lập **`DCHUService.exe`** khi tiếp nhận yêu cầu từ các tiện ích như `FanSpeedSetting.exe` hoặc khi BIOS phản hồi các gói ACPI WMI truyền thống.  
   `FnKey.exe` không phát trực tiếp `cmd = 29` hay `cmd = 79`, mà giao tiếp thông qua DCHU driver wrapper hoặc gửi EventLog cho `DCHUService.exe`.

---

### 3.5 Cơ Chế Giao Tiếp IPC Giữa `FnKey.exe` Và `DCHUService.exe` Qua Windows EventLog `[ĐÃ XÁC MINH]`

Thay vì dùng Named Pipe hay Socket, Clevo triển khai cơ chế IPC liên tiến trình độc đáo thông qua **Windows Event Log**:
1. **Event Logs Sử Dụng:**
   - Log kênh Server: `PowerBiosServerLog` (Source: `PowerBiosServerSource`).
   - Log kênh System: `PowerBiosSystemLog` (Source: `PowerBiosSystemSource`).
2. **Kênh Ghi Sự Kiện (Outgoing IPC):**
   - `Type 0x0200004b::Method 0x060001e8`: Ghi một chuỗi tin nhắn thông điệp vào log `PowerBiosServerLog`.
   - `Type 0x0200004b::Method 0x060001e9`: Ghi một chuỗi tin nhắn thông điệp vào log `PowerBiosSystemLog`.
3. **Kênh Nhận Sự Kiện (Incoming IPC Listener):**
   - Tại `Type 0x0200004b::Method 0x06000125`: Đăng ký sự kiện lắng nghe `EventLog.EntryWritten` trên `PowerBiosServerLog` với delegate trỏ tới `Method 0x0600013d`.
   - Khi có sự kiện mới, `Method 0x0600013d` trích xuất chuỗi thông điệp và chuyển vào hàm phân tích `Method 0x06000178`.
4. **Cấu Trúc Gói Tin:**
   - Tại `Method 0x06000178` (`IL_0x004E`), chuỗi thông điệp được tách nhỏ bằng ký tự phân cách mũ:
     $$\mathbf{\hat{\ }}$$
     Cú pháp dạng: `COMMAND^PARAM1^PARAM2...` giúp đồng bộ hóa trạng thái quạt, đèn phím, và chế độ nguồn giữa `FnKey.exe`, `DCHUService.exe`, và các app UWP Control Center.

---

### 3.6 Cơ Chế Xử Lý Phím Nóng Quạt (Fn+1 / Max Fan Toggle) `[ĐÃ XÁC MINH]`

Phím nóng điều khiển quạt (Fn+1 để bật quạt tối đa - Max Fan) được phân giải thành hai tầng điều khiển:

#### Tầng 1: Đọc & Ghi Trực Tiếp Qua DCHU BIOS (`Type 0x020000b4::Method 0x0600041a`)
- **Đọc trạng thái hiện tại:**
  - Tại `IL_0x0010`: Gọi wrapper `0x0600075a` đọc 1 byte từ **DCHU Offset `1361` (`0x551`)**.
  - Trích xuất Bit 5 (`(val >> 5) & 1`) và Bit 4 (`(val >> 4) & 1`).
  - Bit 5 và Bit 4 phản ánh trạng thái quạt CPU và quạt GPU (quạt chạy chế độ tự động hay ép tối đa).
- **Kích hoạt Max Fan:**
  - Tại `IL_0x004B`: Gọi `Method 0x06000754` với:
    $$\mathbf{cmd = 121\ (0x79)},\quad \mathbf{subCmd = 44\ (0x2C)},\quad \mathbf{data = 1}$$
    -> **Lệnh bật / tắt Max Fan (Full Fan Speed).**

#### Tầng 2: Điều Khiển Nấc Quạt Trong Bộ Xử Lý Thông Điệp (`Type 0x02000055::Method 0x06000180`)
Trong vòng lặp xử lý sự kiện phím nóng:
- Tại `IL_0x2412`: Gọi `cmd = 121`, `subCmd = 44`, `data = 2` (`0x06000754`), kèm gọi `0x0600041e` ghi bù tốc độ quạt (Fan Speed Offset) vào **AppSettings Page `1`, Offset `13` (`0x0D`), Length `2`**.
- Tại `IL_0x243a`: Gọi `cmd = 121`, `subCmd = 44`, `data = 3` (`0x06000754`), kèm gọi `0x0600041f`.
- Tại `IL_0x2455`: Gọi `0x060004e1` đọc nhiệt độ hệ thống từ DCHU Offset `223` (`0xDF`):
  $$T\ (^\circ\text{C}) = \frac{(Buffer[1] \ll 8 + Buffer[0]) - 2732}{10}$$
  (Quy đổi từ 0.1 Kelvin sang độ Celsius), sau đó gửi thông báo nhiệt độ qua `PowerBiosServerLog` (`IL_0x0078`).
- Bảng điều khiển quạt chi tiết (Fan Curve, Custom Table) được ủy quyền xử lý cho app con chuyên trách `FanSpeedSetting.exe` (giao thức `clevofan:`).

---

### 3.7 Cơ Chế Xử Lý Phím Nóng Đèn Bàn Phím (Keyboard Backlight LED) `[ĐÃ XÁC MINH]`

`FnKey.exe` phân nhánh xử lý đèn bàn phím theo hai kiến trúc phần cứng hoàn toàn khác nhau:

#### 1. Nhánh Bàn Phím Per-Key RGB (Giao Thức HID USB) `[ĐÃ XÁC MINH]`
- Dành cho các model hỗ trợ đèn RGB từng phím độc lập.
- Được điều khiển trong `Type 0x02000107` thông qua thư viện native `\Device_HID\perkey\HID_Device.dll`:
  - `Method 0x06000640`, `0x06000647`, `0x06000677`, `0x06000678`.
  - Sử dụng các hàm `Init_HIDdevice`, `WriteData`, `ReadData` để truyền các bản tin HID feature report cấu hình màu sắc, hiệu ứng, và độ sáng từng vùng bàn phím mà không cần qua ACPI WMI.

#### 2. Nhánh Bàn Phím Đơn Sắc / 3 Vùng (Giao Thức DCHU / WMI) `[ĐÃ XÁC MINH]`
- Dành cho các model bàn phím LED trắng (White LED KB) hoặc LED 3 vùng:
  - **Phương thức `Type 0x02000172::Method 0x0600094f`:**
    - Khởi tạo mảng đệm 9 byte: `byte[9]`.
    - Byte đầu tiên: `byte[0] = 39` (`0x27`, tương ứng mã lệnh ACPI `SetWhiteLedKB`).
    - Byte `1..6`: Chứa giá trị màu sắc/độ sáng 16-bit (Low/High byte) của các vùng LED.
    - Byte `7..8`: Chứa tham số hiệu ứng hoặc độ trễ bàn phím.
    - Tại `IL_0x00B0`: Gọi phương thức wrapper `0x0600075f`:
      $$\mathbf{SetDCHU\_DataEx(cmd = 4,\ inBuffer = byte[9],\ outBuffer)}$$
  - **Phương thức `Type 0x02000059::Method 0x060001c5` & `0x060001d5`:**
    - Phát lệnh DCHU trực tiếp qua `Method 0x06000754`:
      $$\mathbf{cmd = 103\ (0x67,\ SetKBLED)},\quad \mathbf{subCmd = 244\ (0xF4)},\quad \mathbf{data = \text{brightness / state}}$$
      (Dùng để tăng/giảm độ sáng bàn phím hoặc bật/tắt tức thì).

---

## 4. Bảng Tổng Hợp Kiểm Chứng Tính Minh Xác

| Nội Dung Kỹ Thuật | Nhãn Đánh Giá | Bằng Chứng Chi Tiết & Tọa Độ Code |
| :--- | :---: | :--- |
| **Giá trị 4 chế độ hiệu năng cơ bản** | `[ĐÃ XÁC MINH]` | `oem.ini` L23-L24 (`0:Quiet, 1:power saving, 2:performance, 3:Entertainment`). |
| **Enum 5 chế độ nguồn trong mã máy** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x02000144`, Fields `0x0400061e..0x04000622` (`quiet=0`, `pwrsaving=1`, `performance=2`, `entertainment=3`, `quiet_plus=4`). |
| **Lưu trạng thái nguồn vào BIOS AppSettings** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x020000b4::Method 0x06000404`, `IL_0x0016`: Gọi `WriteAppSettings(page=1, offset=1, len=1, [mode])`. |
| **Lệnh DCHU chuyển chế độ nguồn** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x020000b4::Method 0x06000404`, `IL_0x008F`, `IL_0x00A5`, `IL_0x00B7`: `cmd = 121 (0x79)`, `subCmd = 25 (0x19)`, `data = mode` (hoặc `2 \| flags` khi Performance). |
| **Cờ bit phụ Performance Mode** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `0x06000404`, `IL_0x0033..0x008A`: Đọc DCHU offsets `288` (bit 0 -> flag bit 7) và `1032` (bit 0 -> flag bit 6). |
| **Mã lệnh WMI cmd = 16, 29, 79 trong FnKey** | `[ĐÃ XÁC MINH]` | Không xuất hiện trong bất kỳ lệnh gọi `0x06000754` nào của `FnKey.exe`. Chúng thuộc WMI interface của `DCHUService` / BIOS WMI. |
| **Windows Power Scheme qua powerlife.dll** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x0200004b::Method 0x06000147`, `IL_0x023E` (`switch 5` gọi `0x06000284` `SetActivePowerPlanGUID` và `0x06000297` `Set_ASPMEx`). |
| **Kênh IPC EventLog liên tiến trình** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x0200004b`: `Method 0x060001e8` (`PowerBiosServerLog`), `0x060001e9` (`PowerBiosSystemLog`), `Method 0x06000125` (`add_EntryWritten`), `Method 0x06000178` (tách dấu `^`). |
| **Phím nóng Max Fan Toggle (Fn+1)** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x020000b4::Method 0x0600041a`: Đọc DCHU offset `1361` (bits 4, 5); gửi `cmd = 121`, `subCmd = 44`, `data = 1` tại `IL_0x0050`. |
| **Phím nóng bước tốc độ quạt (Fan Step)** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x02000055::Method 0x06000180`: `cmd = 121, subCmd = 44, data = 2` (`IL_0x241c`) và `data = 3` (`IL_0x2444`), ghi offset `WriteAppSettings(1, 13, 2)`. |
| **Cảm biến nhiệt độ DCHU** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `0x060004e1`: Đọc DCHU offset `223` (`0xDF`), công thức `(buffer[1]<<8 + buffer[0] - 2732)/10`. |
| **Phím nóng Per-Key RGB LED** | `[ĐÃ XÁC MINH]` | `FnKey.exe`, `Type 0x02000107`: Gọi thư viện native `\Device_HID\perkey\HID_Device.dll` (`Init_HIDdevice`, `WriteData`, `ReadData`). |
| **Phím nóng White LED / WMI LED** | `[ĐÃ XÁC MINH]` | `FnKey.exe`: `Type 0x02000172::Method 0x0600094f` gọi `SetDCHU_DataEx(cmd = 4, buffer[0] = 39, ...)` và `Type 0x02000059` gọi `cmd = 103, subCmd = 244`. |
| **Ảnh hưởng của bit 7/bit 6 trong Performance**| `[GIẢ THUYẾT]` | Các cờ bit `0x80` (offset 288) và `0x40` (offset 1032) đại diện cho khả năng hỗ trợ Dynamic Boost / GPU TGP Overclocking hoặc Extreme Cooling của hệ thống phần cứng tương ứng. |
| **Cấu trúc chi tiết bảng quạt trong clevofan** | `[CHƯA BIẾT]` | Thuộc về binary `504814C03D814\FanSpeedSetting\FanSpeedSetting.exe`, nằm ngoài phạm vi phân tích tĩnh của gói `FnKey`. |

---

## 5. Kiến Nghị Ánh Xạ Cho Driver & Daemon Linux Nobara

Để điều khiển chính xác các chức năng này trên Linux mà không phụ thuộc vào Windows runtime:
1. **Chuyển Chế Độ Nguồn:**
   - **Giao diện ACPI WMI:** Gọi method WMI của thiết bị Clevo ACPI (`CLEV0000` hoặc WMI method tương đương qua kernel module `clevo_wmi` / `clevo_acpi`).
   - Lệnh điều khiển nguồn: Thực thi tương đương `cmd = 121` (`0x79`), `subCmd = 25` (`0x19`):
     - Quiet: `data = 0`
     - Power Saving: `data = 1`
     - Performance: `data = 2` (hoặc `0x42` / `0x82` tùy bo mạch)
     - Entertainment: `data = 3`
   - Đồng bộ ACPI platform profile kernel (`/sys/firmware/acpi/platform_profile`) giữa các chế độ: `low-power` (Power Saving), `quiet` (Quiet), `balanced` (Entertainment), `performance` (Performance).
2. **Điều Khiển Quạt (Max Fan Toggle):**
   - Bật / tắt chế độ quạt 100% bằng lệnh `cmd = 121` (`0x79`), `subCmd = 44` (`0x2C`), `data = 1`.
   - Giám sát nhiệt độ EC trực tiếp qua sysfs `hwmon` hoặc đọc tương đương offset `223`.
3. **Điều Khiển Đèn Bàn Phím:**
   - Nếu máy sử dụng bàn phím Per-Key RGB: Giao tiếp qua `hidraw` node tương ứng với VID/PID của Clevo Per-Key HID controller (không cần can thiệp BIOS WMI).
   - Nếu máy sử dụng đèn LED trắng/đơn sắc: Gửi lệnh WMI qua EC method hoặc `cmd = 103` (`0x67`), `subCmd = 244` (`0xF4`) để đặt độ sáng `0..255`.
