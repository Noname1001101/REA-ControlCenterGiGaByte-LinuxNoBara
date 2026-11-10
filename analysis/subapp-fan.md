# Báo cáo Phân tích Tĩnh Subapp Fan Control (FanSpeedSetting)

- **Mục tiêu phân tích:** Gói điều khiển quạt Gigabyte / Clevo Control Center (`FanSpeedSetting.exe`, `oem.ini`)
- **Đường dẫn thư mục nguồn:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\504814C03D814\FanSpeedSetting`
- **Tệp thực thi chính:** `FanSpeedSetting.exe` (SHA-256: `43e3e17f285039c68b3aab1ce546da8d9b5547e449b93f4afb3d185294c2c5d0`)
- **Tệp cấu hình chính:** `oem.ini`
- **Phương pháp phân tích:** Tĩnh 100% (Static Analysis via REA CIL IL-anchors, Metadata Token Mapping, P/Invoke Extraction, String and Hex Buffer Analysis). Tuyệt đối không chạy binary mục tiêu.

---

## 1. Trích xuất Cấu hình `oem.ini`

Toàn bộ nội dung tệp cấu hình `oem.ini` đã được đọc và phân tích tĩnh:

```ini
[General]
SituationalMode=3
SupportXTUFanTable=1
SupportFanSpeedOffset=1
SupportMEMSetting=2

[FanSpeedSetting]
FanMode=Default
;0:Auto 1:Max 3:Silent 5:MAXQ 6:Custom
ColorR=255
ColorG=0
ColorB=210
ColorGPU_R=0
ColorGPU_G=168
ColorGPU_B=255

[OverClock]
SupportOverClock=0
Core_Freq_Lower=-100
Core_Freq_Upper=200
VRAM_Freq_Lower=-100
VRAM_Freq_Upper=300
```

### Các thông số đã xác minh từ cấu hình:
1. **Chế độ quạt và kịch bản:**
   - `SituationalMode=3` [ĐÃ XÁC MINH: oem.ini dòng 2]: Bật hỗ trợ bộ chuyển đổi chế độ kịch bản (Scenario / Situational Mode).
   - `FanMode=Default` [ĐÃ XÁC MINH: oem.ini dòng 8]: Chế độ quạt khởi tạo mặc định theo BIOS/EC.
   - Các mã chế độ ghi chú trong OEM comment [ĐÃ XÁC MINH: oem.ini dòng 9]:
     - `0`: Auto
     - `1`: Max
     - `3`: Silent
     - `5`: MAXQ / Quiet
     - `6`: Custom
2. **Khả năng phần cứng hỗ trợ (Feature Flags):**
   - `SupportXTUFanTable=1` [ĐÃ XÁC MINH: oem.ini dòng 3]: Cho phép chỉnh sửa bảng đường đặc tính quạt (Fan Curve Table) tương thích XTU/EC.
   - `SupportFanSpeedOffset=1` [ĐÃ XÁC MINH: oem.ini dòng 4]: Cho phép tính năng bù tốc độ quạt (Fan Speed Offset).
   - `SupportMEMSetting=2` [ĐÃ XÁC MINH: oem.ini dòng 5]: Cấu hình chế độ ép xung bộ nhớ GPU (Level 2).
   - `SupportOverClock=0` [ĐÃ XÁC MINH: oem.ini dòng 19]: Chức năng ép xung thủ công bị tắt mặc định.
3. **Bảng màu RGB mặc định cho Giao diện UI:**
   - Main / CPU Palette: `R=255, G=0, B=210` (`#FF00D2` - Màu cánh sen / Magenta) [ĐÃ XÁC MINH: oem.ini dòng 10-12].
   - GPU Palette: `R=0, G=168, B=255` (`#00A8FF` - Màu xanh lơ / Cyan-Blue) [ĐÃ XÁC MINH: oem.ini dòng 13-15].

---

## 2. Kiến trúc Lớp Giao tiếp Phần cứng `InsydeDCHU.dll`

Binary `FanSpeedSetting.exe` là ứng dụng .NET Framework 4.7.2 (x64) bị obfuscate bởi ConfuserEx. Tuy nhiên, toàn bộ Metadata Token và CIL Bytecode đã được giải mã tĩnh để xác định chính xác các điểm P/Invoke và luồng nghiệp vụ.

### 2.1. Danh sách P/Invoke Nguyên thủy tới `InsydeDCHU.dll`
Tất cả các lệnh tương tác phần cứng thực tế được đóng gói tập trung tại **`Type 0x02000023`** [ĐÃ XÁC MINH: FanSpeedSetting.exe Type 0x02000023]. Các lớp wrapper khác (`0x0200003b`, `0x02000049`) chứa các P/Invoke dự phòng nhưng không có caller trong luồng thực thi:

| Token Hàm | Tên P/Invoke | Kiểu tham số | Mô tả chức năng |
| :--- | :--- | :--- | :--- |
| `0x06000050` | `GetDCHU_Data_Integer` | `(int32 cmd, ref int32 val) -> int32` | Đọc số nguyên 32-bit từ driver Insyde DCHU |
| `0x06000051` | `SetDCHU_Data` | `(int32 cmd, uint8[] buf, int32 len) -> int32` | Ghi buffer byte xuống DCHU |
| `0x06000052` | `SetDCHU_DataEx` | `(int32 cmd, uint8[] inBuf, int32 inLen, ref uint8 outBuf) -> int32` | Gửi buffer và nhận kết quả phản hồi |
| `0x06000053` | `GetDCHU_Data_Buffer` | `(int32 cmd, ref uint8 outBuf) -> int32` | Đọc buffer dữ liệu từ DCHU |
| `0x06000054` | `ReadAppSettings` | `(int32 page, int32 offset, int32 len, ref uint8 outBuf) -> int32` | Đọc cấu hình NVRAM / EEPROM BIOS |
| `0x06000055` | `WriteAppSettings` | `(int32 page, int32 offset, int32 len, ref uint8 inBuf) -> int32` | Ghi cấu hình NVRAM / EEPROM BIOS |

### 2.2. Các hàm Wrapper Bậc cao trong `Type 0x02000023`
- **Method `0x06000057`** `(int32 cmd, int32 subCmd, uint32 val) -> int32` [ĐÃ XÁC MINH: Type 0x02000023, Method 0x06000057]:
  - Đóng gói 4 byte Little-Endian:
    ```csharp
    byte[] loc0 = BitConverter.GetBytes(val);
    loc0[3] = (byte)subCmd;
    return SetDCHU_Data(cmd, loc0, 4);
    ```
- **Method `0x06000058`** `(int32 cmd, byte[] buf) -> int32` [ĐÃ XÁC MINH: Type 0x02000023, Method 0x06000058]:
  - Gọi trực tiếp `SetDCHU_Data(cmd, buf, 256)`.
- **Method `0x06000059`** `(int32 cmd, byte[] inBuf, ref byte[] outBuf) -> int32` [ĐÃ XÁC MINH: Type 0x02000023, Method 0x06000059]:
  - Gọi `SetDCHU_DataEx(cmd, inBuf, 256, ref outBuf[0])`.
- **Method `0x0600005a`** `(int32 cmd) -> int32` [ĐÃ XÁC MINH: Type 0x02000023, Method 0x0600005a]:
  - Gọi `GetDCHU_Data_Integer(cmd, ref val)` và trả về giá trị `val`.
- **Method `0x0600005b`** `(int32 cmd) -> byte[]` [ĐÃ XÁC MINH: Type 0x02000023, Method 0x0600005b]:
  - Cấp phát mảng 256 byte `byte[] buf = new byte[256]`, gọi `GetDCHU_Data_Buffer(cmd, ref buf[0])` và trả về mảng `buf`.
- **Method `0x0600005c` & `0x0600005d`**: Đọc/ghi AppSettings theo khối `(page, offset, len)`.
- **Method `0x0600005e` & `0x0600005f`**: Helper tính `page = address / 256`, `offset = address % 256` để truy cập NVRAM tuyến tính.

---

## 3. Giải mã Cơ chế ĐỌC Dữ liệu Phần cứng (Nhiệt độ, RPM, Trạng thái Quạt)

Cơ chế cập nhật dữ liệu quạt diễn ra định kỳ qua Timer Tick tại UI MainWindow (`Type 0x02000054`, Method `0x06000231`) kích hoạt Controller Core (`Type 0x02000007`, Method `0x0600001a`).

### 3.1. Đọc Trạng thái và Tốc độ Quạt (Telemetry Read)
- **Mã lệnh:** Gọi `GetDCHU_Data_Buffer(cmd = 12)` (`0x0C`) qua Method `0x0600005b(12)` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_0006].
- Kết quả trả về mảng `byte[256]` (ký hiệu `buf`).

#### A. Công thức tính Tốc độ Vòng/phút (RPM)
Tốc độ quạt được mã hóa dưới dạng số nguyên không dấu 16-bit Big-Endian:
$$\text{RPM} = (\text{Byte}_{\text{High}} \ll 8) \mid \text{Byte}_{\text{Low}}$$

- **Fan 1 (CPU Fan):**
  $$\text{RPM}_{\text{CPU}} = (buf[2] \ll 8) \mid buf[3]$$
  [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_001e - IL_0027]
- **Fan 2 (GPU 1 Fan):**
  $$\text{RPM}_{\text{GPU1}} = (buf[4] \ll 8) \mid buf[5]$$
  [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_0041 - IL_004a]
- **Fan 3 (GPU 2 Fan):**
  $$\text{RPM}_{\text{GPU2}} = (buf[6] \ll 8) \mid buf[7]$$
  [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_0064 - IL_006d]
- **Fan 4 (Aux Fan):**
  $$\text{RPM}_{\text{Fan4}} = (buf[36] \ll 8) \mid buf[37]$$
  [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_0087 - IL_0092]

#### B. Đọc Tỉ lệ Duty hiện thời
- **Fan 1 Duty:** $buf[16]$ [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_009b]
- **Fan 2 Duty:** $buf[19]$ [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_00bc]
- **Fan 3 Duty:** $buf[22]$ [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_00cb]
- **Fan 4 Duty:** $buf[38]$ [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001a, IL_00da]

#### C. Đọc và Bù Nhiệt độ Phần cứng (°C)
- **Nhiệt độ GPU 1:** $T_{\text{GPU1}} = buf[21]$ (°C nguyên trực tiếp) [ĐÃ XÁC MINH: Method 0x0600001a, IL_00c7]
- **Nhiệt độ GPU 2:** $T_{\text{GPU2}} = buf[24]$ (°C nguyên trực tiếp) [ĐÃ XÁC MINH: Method 0x0600001a, IL_00d6]
- **Nhiệt độ Quạt 4:** $T_{\text{Fan4}} = buf[40]$ (°C nguyên trực tiếp) [ĐÃ XÁC MINH: Method 0x0600001a, IL_00e5]
- **Nhiệt độ CPU:**
  Đọc giá trị thô $raw = buf[18]$ [ĐÃ XÁC MINH: Method 0x0600001a, IL_00a7], sau đó đưa qua hàm nội suy bù nhiệt theo model: `Method 0x0600002b(modelId, raw)` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600002b]:
  1. **Nhánh Model A** (`modelId == 1031815101` hoặc `1031815095`):
     - Nếu $raw > 60$: $T_{\text{CPU}} = \text{round}((raw - 12) \times 0.33 + 44)$
     - Nếu $raw \le 60$: $T_{\text{CPU}} = raw - 1$
  2. **Nhánh Model B** (`modelId == 1031815073`):
     - Nếu $raw > 50$: $T_{\text{CPU}} = \text{round}((raw - 35) \times 0.41 + 43.7)$
     - Nếu $raw \le 50$: $T_{\text{CPU}} = raw - 1$
  3. **Nhánh Model C** (`modelId == 1031815067`):
     - Nếu $raw > 50$: $T_{\text{CPU}} = \text{round}((raw - 9) \times 0.22 + 43.7)$
     - Nếu $raw \le 50$: $T_{\text{CPU}} = raw - 5$
  4. **Nhánh Model D** (`modelId == 1031815061`):
     - Nếu $raw > 32$: $T_{\text{CPU}} = \text{round}(raw \times 0.5 + 16)$
     - Nếu $raw \le 32$: $T_{\text{CPU}} = raw$
  5. **Nhánh Model E** (`modelId == 1031815055`):
     - Nếu $raw > 26$: $T_{\text{CPU}} = \text{round}(raw \times 0.5 + 13)$
     - Nếu $raw \le 26$: $T_{\text{CPU}} = raw$
  6. **Mặc định (các model khác):**
     - $T_{\text{CPU}} = raw$

### 3.2. Đọc Bảng Đường đặc tính Quạt Mặc định của OEM (Fan Curve Table)
- **Mã lệnh:** Gọi `GetDCHU_Data_Buffer(cmd = 13)` (`0x0D`) qua Method `0x0600001b` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001b, IL_0006].
- Kết quả buffer 256 byte:
  - `buf[12]`: Số lượng quạt phần cứng hỗ trợ (`FanCount`, thường là 2 hoặc 3).
  - `buf[14]`: Chế độ quạt đang lưu trong firmware (`FanMode`: 0=Auto, 1=Max, 5=Silent, 6=Custom).
  - `buf[50]`: Bitmask cờ khả năng quạt (`buf[50] & 1`).
  - **Các điểm đường cong nhiệt độ - công suất (Fan Curve Points):** Mỗi điểm gồm cặp `(Nhiệt_độ_°C, Duty_Byte)`:
    - Công thức chuyển đổi: $\text{Duty}_{\%} = \text{round}\left(\frac{\text{Duty\_Byte}}{255.0} \times 100.0\right)$
    - **Fan 1 (CPU):**
      - Điểm 1: $(buf[16], buf[17])$
      - Điểm 2: $(buf[18], buf[19])$
      - Điểm 3: $(buf[20], buf[21])$
    - **Fan 2 (GPU 1):**
      - Điểm 1: $(buf[24], buf[25])$
      - Điểm 2: $(buf[26], buf[27])$
      - Điểm 3: $(buf[28], buf[29])$
    - **Fan 3 (GPU 2):**
      - Điểm 1: $(buf[32], buf[33])$
      - Điểm 2: $(buf[34], buf[35])$
      - Điểm 3: $(buf[36], buf[37])$

### 3.3. Đọc Palette Màu Giao diện RGB
- **Mã lệnh:** Gọi `GetDCHU_Data_Buffer(cmd = 17)` (`0x11`) qua Method `0x0600019a` [ĐÃ XÁC MINH: Type 0x02000042, Method 0x0600019a]:
  - `buf[2]`: Trạng thái hợp lệ.
  - `buf[3..5]`: Main UI Skin RGB (R, G, B).
  - `buf[6..8]`: GPU Skin RGB (R, G, B).
  - `buf[9..11]`: Custom palette RGB.
  - Nếu đọc thất bại hoặc không hợp lệ, ứng dụng lấy giá trị từ `oem.ini` (`ColorR`, `ColorG`, `ColorB` và `ColorGPU_R`, `ColorGPU_G`, `ColorGPU_B`).

---

## 4. Giải mã Cơ chế GHI Thiết lập Tốc độ Quạt Xuống Phần cứng

Tất cả các hành động điều khiển quạt từ UI được điều phối qua Controller Core `Type 0x02000007` và Fan Manager `Type 0x02000025`.

### 4.1. Thiết lập Chế độ Quạt (Fan Mode: Auto / Max / Silent / Custom)
- **Luồng gọi UI:** UI MainWindow gọi `Method 0x06000068(mode)` [ĐÃ XÁC MINH: Type 0x02000025, Method 0x06000068], chuyển tiếp đến `Method 0x06000020(mode)` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x06000020]:
  - **Auto:** `mode = 0` (`0x00`) [ĐÃ XÁC MINH @ Method 0x0600023e]
  - **Max:** `mode = 1` (`0x01`) [ĐÃ XÁC MINH @ Method 0x06000240]
  - **Quiet / Silent:** `mode = 5` (`0x05`) hoặc `3` (`0x03`) [ĐÃ XÁC MINH @ Method 0x06000242, 0x06000244]
  - **Custom:** `mode = 6` (`0x06`) [ĐÃ XÁC MINH @ Method 0x0600024c]
- **Đóng gói mã lệnh xuống Driver:**
  - Gọi `Method 0x06000057(cmd = 121, subCmd = 1, val = mode)`:
    - `cmd = 121` (`0x79`)
    - `subCmd = 1` (`0x01` đặt tại Byte index 3)
    - Buffer 4 byte gửi tới `SetDCHU_Data`:
      ```
      Byte 0: mode (0x00, 0x01, 0x05, hoặc 0x06)
      Byte 1: 0x00
      Byte 2: 0x00
      Byte 3: 0x01 (subCmd = 1)
      ```
- **Lưu trạng thái vào NVRAM:**
  - Gọi `WriteAppSettings(page = 4, offset = 5, len = 1, buf = [mode])` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x06000020, IL_0036 - IL_0042].

### 4.2. Thiết lập Tốc độ Quạt Cố định (Fixed Fan Duty / Manual Slider)
- **Luồng gọi UI:** Kéo thanh trượt tốc độ quạt gọi UI Handler `Method 0x0600023c`, chuyển tiếp vào `Method 0x06000021(dutyPercent)` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x06000021]:
  - Chuyển đổi phần trăm sang giá trị 1 byte:
    $$val = \text{round}\left(\frac{\text{dutyPercent}}{100.0} \times 255.0\right)$$
- **Đóng gói mã lệnh xuống Driver:**
  - Gọi `Method 0x06000057(cmd = 121, subCmd = 14, val)`:
    - `cmd = 121` (`0x79`)
    - `subCmd = 14` (`0x0E` đặt tại Byte index 3)
    - Buffer 4 byte gửi tới `SetDCHU_Data`:
      ```
      Byte 0: val (0 - 255)
      Byte 1: 0x00
      Byte 2: 0x00
      Byte 3: 0x0E (subCmd = 14)
      ```
- **Lưu trạng thái vào NVRAM:**
  - Gọi `WriteAppSettings(page = 4, offset = 7, len = 1, buf = [dutyPercent])` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x06000021, IL_003b - IL_0047].

### 4.3. Thiết lập Fan Speed Offset
- **Luồng gọi UI:** Method `0x06000261` kích hoạt khi người dùng thay đổi giá trị bù tốc độ quạt, gọi `Method 0x06000027(enableFlag, offsetValue, fanBitmask)` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x06000027]:
  - `loc0`: Bitmask 7-bit các quạt được chọn (`0x01` = Fan 1, `0x02` = Fan 2, `0x04` = Fan 3).
  - `loc3`: Giá trị offset (mã hóa theo nấc của UI, chuẩn hóa $SelectedValue$ hoặc $SelectedValue + 12$).
  - `arg1`: Cờ kích hoạt (`1` = Bật, `0` = Tắt).
- **Quy tắc đóng gói bitmask dữ liệu 32-bit:**
  $$val = ((arg1 \ll 7) \mid (loc0 \ \& \ 0x7F)) \mid (loc3 \ll 8)$$
- **Đóng gói mã lệnh xuống Driver:**
  - Gọi `Method 0x06000057(cmd = 121, subCmd = 40, val)`:
    - `cmd = 121` (`0x79`)
    - `subCmd = 40` (`0x28` đặt tại Byte index 3)
    - Buffer 4 byte gửi tới `SetDCHU_Data`:
      ```
      Byte 0: ((enableFlag << 7) | (fanBitmask & 0x7F)) & 0xFF
      Byte 1: offsetValue & 0xFF
      Byte 2: 0x00
      Byte 3: 0x28 (subCmd = 40)
      ```
- **Lưu trạng thái vào NVRAM:**
  - Gọi `WriteAppSettings(page = 4, offset = 81, len = 5, buf = [1, Byte0, Byte1, 0, 0])` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x06000027, IL_0060 - IL_0079].

### 4.4. Ghi Toàn bộ Bảng Đường đặc tính Quạt Tuỳ chỉnh (Custom Fan Curve Table)
- **Luồng gọi UI:** Người dùng chỉnh các mốc nhiệt độ và công suất trên biểu đồ tùy chỉnh, UI gọi `Method 0x0600001c` [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001c].
- **Tính toán hệ số góc (Slope) tại Method `0x0600001e`:**
  Trước khi ghi, hệ thống tính độ dốc giữa từng mốc nhiệt độ theo định dạng số thực dấu phẩy tĩnh 4.4:
  $$\text{Slope} = \text{round}\left(\frac{\text{Duty}_{\text{end}} - \text{Duty}_{\text{start}}}{\text{Temp}_{\text{end}} - \text{Temp}_{\text{start}}} \times 2.55 \times 16.0\right)$$
  [ĐÃ XÁC MINH: Type 0x02000007, Method 0x0600001e, IL_0000 - IL_003f]
- **Đóng gói buffer 256 byte ghi qua `Method 0x06000058(cmd = 14, buf)` (`0x0E`):**
  - Cấu trúc các trường trong buffer 256 byte:
    - `buf[2]`: Fan 1 Temp 1
    - `buf[3]`: Fan 1 Duty 1 (quy đổi $0 - 255$)
    - `buf[4]`: Fan 1 Temp 2
    - `buf[5]`: Fan 1 Duty 2
    - `buf[6..9]`: Fan 2 Temp 1, Duty 1, Temp 2, Duty 2
    - `buf[10..13]`: Fan 3 Temp 1, Duty 1, Temp 2, Duty 2
    - `buf[14..17]`: Slope 1 và Slope 2 của Fan 1 (mỗi slope chiếm 2 byte Big-Endian)
    - `buf[18..21]`: Slope 1 và Slope 2 của Fan 2 (mỗi slope chiếm 2 byte Big-Endian)
    - `buf[22..25]`: Slope 1 và Slope 2 của Fan 3 (mỗi slope chiếm 2 byte Big-Endian)

---

## 5. Cơ chế Giao tiếp IPC, WMI và Windows EventLog với `DCHUService.exe`

Ứng dụng `FanSpeedSetting.exe` và dịch vụ nền `DCHUService.exe` duy trì kênh đồng bộ trạng thái hai chiều để đảm bảo khi chế độ máy thay đổi (ví dụ: chuyển từ Gaming sang Silent hoặc cắm/rút sạc), cài đặt quạt được cập nhật tức thì.

### 5.1. Kênh EventLog IPC (`PowerBiosServerLog`)
- **Tên EventLog:** `PowerBiosServerLog` [ĐÃ XÁC MINH: Chuỗi giải mã tại Method 0x06000193].
- **Cơ chế Lắng nghe Sự kiện từ Service:**
  - Method `0x06000193` khởi tạo đối tượng `EventLog("PowerBiosServerLog")` và đăng ký callback `add_EntryWritten`.
  - Callback giải mã nội dung sự kiện tại Method `0x060001b5`:
    - Dữ liệu IPC được định dạng theo cấu trúc chuỗi phân tách bởi dấu mũ (`^`):
      $$\text{COMMAND} \wedge \text{PARAM1} \wedge \text{PARAM2}$$
      [ĐÃ XÁC MINH: Type 0x02000045, Method 0x060001b5, IL_0028 gọi `String.Split('^')`].
- **Cơ chế Phát Thông điệp tới Service:**
  - Method `0x0600015e` và `0x0600015f` ghi bản tin vào `PowerBiosServerLog` với định dạng chuỗi `FAN_SETTING^...` để thông báo cho `DCHUService.exe` biết trạng thái thay đổi.

### 5.2. Kênh WMI (Windows Management Instrumentation)
- `FanSpeedSetting.exe` kiểm tra trạng thái BIOS và EC qua namespace WMI `root\WMI` với các lớp ACPI WMI do BIOS Insyde cung cấp (`Method 0x06000152`) để xác định định danh model bo mạch chủ và tương thích phần cứng trước khi gửi lệnh DCHU.

---

## 6. Bảng Tổng hợp Mã Lệnh DCHU (Command Mapping Matrix)

| Lệnh DCHU (`cmd`) | SubCmd | Chiều | Chiều dài | Ý nghĩa & Dữ liệu | Trạng thái xác minh |
| :---: | :---: | :---: | :---: | :--- | :---: |
| **12** (`0x0C`) | N/A | READ | 256 B | Telemetry: RPM (BE 16-bit: offset 2, 4, 6, 36), Duty (offset 16, 19, 22, 38), Temp (offset 18, 21, 24, 40) | [ĐÃ XÁC MINH] |
| **13** (`0x0D`) | N/A | READ | 256 B | OEM Fan Table: Fan Count (12), Mode (14), Fan Curve Points (16..37) | [ĐÃ XÁC MINH] |
| **14** (`0x0E`) | N/A | WRITE | 256 B | Ghi Custom Fan Curve Table: Điểm nhiệt/duty và hệ số góc Slope (4.4 fixed point) | [ĐÃ XÁC MINH] |
| **17** (`0x11`) | N/A | READ | 256 B | Đọc Palette màu RGB (offset 3..5: Main, offset 6..8: GPU) | [ĐÃ XÁC MINH] |
| **121** (`0x79`) | **1** (`0x01`) | WRITE | 4 B | Ghi Fan Mode: `[mode, 0, 0, 1]` (0=Auto, 1=Max, 5=Silent, 6=Custom) | [ĐÃ XÁC MINH] |
| **121** (`0x79`) | **14** (`0x0E`) | WRITE | 4 B | Ghi Fixed Fan Duty: `[dutyByte, 0, 0, 14]` | [ĐÃ XÁC MINH] |
| **121** (`0x79`) | **40** (`0x28`) | WRITE | 4 B | Ghi Fan Speed Offset: `[flags|fans, offsetVal, 0, 40]` | [ĐÃ XÁC MINH] |
| **ReadAppSettings** | N/A | READ | 1-5 B | Đọc NVRAM: Page 4, offset 5 (Mode), offset 7 (Duty), offset 81 (Offset) | [ĐÃ XÁC MINH] |
| **WriteAppSettings** | N/A | WRITE | 1-5 B | Ghi NVRAM: Page 4, offset 5 (Mode), offset 7 (Duty), offset 81 (Offset) | [ĐÃ XÁC MINH] |

---

## 7. Khuyến nghị cho Bản cài đặt Linux (Nobara / Open Source Driver)

1. **Giao thức điều khiển quạt trên Linux:**
   - Không cần phụ thuộc vào `InsydeDCHU.dll` (vốn gọi qua WMI ACPI GUID hoặc `\\.\InsydeDCHU` device driver).
   - Trên Linux, toàn bộ các mã lệnh `cmd` và payload byte trên có thể ánh xạ trực tiếp sang các phương thức ACPI WMI evaluation (qua `/sys/bus/wmi/devices/...`) hoặc cổng EC I/O trực tiếp (`clevo_wmi` / `clevo_acpi`).
2. **Công thức RPM:**
   - Đảm bảo ghép byte theo chuẩn Big-Endian: `(buf[hi] << 8) | buf[lo]`.
3. **Nhiệt độ CPU:**
   - Cần phát hiện Model ID của laptop để áp dụng công thức bù nhiệt chính xác theo `Method 0x0600002b` trước khi hiển thị cho người dùng hoặc tính toán đường cong tự động.
