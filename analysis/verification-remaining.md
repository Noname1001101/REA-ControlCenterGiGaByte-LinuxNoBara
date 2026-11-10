# Báo cáo Đối chiếu Độc lập (Chỉ Đọc) — Worker 2: Toàn bộ 56 Mã Lệnh Còn Lại (Task 2 - Giai đoạn 4)

- **Người thực hiện:** Worker 2 (Task 2 - Giai đoạn 4, Dự án REA Control Center GiGaByte Linux NoBara)
- **Thời gian thực hiện:** 2026-11-10
- **File nhị phân kiểm tra:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\DCHUService\DCHUService.exe`
- **Định danh Artifact đã xác minh:**
  - **SHA-256:** `f0f66063562971747430bc7001ca98a9f06c3d8038b07f8b6bb93aa1c178dff2` (PASS)
  - **MVID:** `ae1d86e0-d466-4d6c-9ac8-b4b26780b4f6` (PASS)
  - **Target Framework:** `.NETFramework,Version=v4.6.1` (PASS)
- **Công cụ phân tích:** REA CLI (`rea-agents@6.8.0`), chế độ phân tích tĩnh PE/CLI metadata (`inspect-managed-members`) trích xuất toàn bộ 1.978 lệnh CIL instruction anchors, signatures, và user string table mà không thực thi bất kỳ tệp binary nào.
- **Nguyên tắc tuân thủ:**
  1. 100% Chỉ đọc (Read-only), tuyệt đối không thực thi file `.exe`/`.dll` trong thư mục target, không cài đặt gì.
  2. Chỉ ghi duy nhất vào file báo cáo thật `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\analysis\verification-remaining.md`.

---

## 1. Giải thích chênh lệch số lượng mã lệnh: Vì sao số mã còn lại là 56 chứ không phải 43?

Trước đó, tiêu đề mục 2c.3 trong `analysis/findings.md` ghi nhận: *"Bảng dưới đây liệt kê toàn bộ 104 nhánh mã lệnh (`cmd`) có mặt trong câu lệnh `switch`..."*. Do đó, nếu lấy 104 trừ đi 61 mã đã kiểm chứng ở Worker 1 (`verification-worker.md`), số lượng danh nghĩa có vẻ là $104 - 61 = 43$.

Tuy nhiên, khi đối chiếu độc lập trực tiếp với CIL bytecode thực tế của `DCHUService.exe`:
1. **Câu lệnh `switch` trong `HotkeyService.Talk2Wmi::ExecuteWMI` (`0x0600000d`):**
   - Trình biên dịch C# biên dịch cấu trúc switch-case trên chuỗi `strNumber` với bảng so sánh gồm đúng **117 lệnh rẽ nhánh `brtrue` / `beq`** tương ứng với **117 giá trị chuỗi mã lệnh khác nhau** (từ `IL_0900` đến `IL_128F`).
   - Bảng ánh xạ mục 2c.3 trong `analysis/findings.md` (từ dòng 502 đến dòng 618) trên thực tế cũng chứa đầy đủ **117 dòng mã lệnh riêng biệt**, hoàn toàn trùng khớp với 117 case của `ExecuteWMI`. Con số "104" ở tiêu đề là sự nhầm lẫn về số đếm trước đó.
2. **Phân bổ trạng thái đối chiếu:**
   - **Đã kiểm chứng bởi Worker 1:** 61 mã lệnh (toàn bộ các mã ghi WMI `InvokeMethod` / `InvokeMethod2`, các mã kiểm soát quạt/LED bàn phím/hiệu năng và các mã nền tảng `0, 1, 2, 3, 4, 12, 13, 16, 17, 19, 21, 26, 27, 28, 29, 30, 31, 32, 33, 34, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 70, 71, 75, 76, 77, 78, 79, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 103, 104, 105, 106, 107, 108, 116, 117, 118, 120, 121, 122`) — Tất cả đã đạt **PASS**.
   - **Số mã còn lại Worker 2 phải kiểm chứng độc lập:**
     $$\text{Tổng số case (117)} - \text{Đã PASS Worker 1 (61)} = \mathbf{56\text{ mã lệnh chưa kiểm}}$$
3. **Phân loại 56 mã lệnh chưa kiểm:**
   - **47 mã đọc WMI qua `ExecMethod` (`0x06000010`):** 5, 6, 7, 8, 9, 10, 11, 14, 15, 18, 50, 51, 52, 53, 54, 55, 56, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 72, 74, 80, 81, 82, 83, 84, 96, 97, 98, 99, 100, 109, 110, 111, 112, 113, 115, 119.
   - **9 mã No-op / IPC EventLog / Thực thi tiến trình:** 57, 58, 248, 249, 251, 252, 253, 254, 255.

---

## 2. Bảng đối chiếu 47 Mã Lệnh Đọc WMI qua `ExecMethod` (`0x06000010`)

Cơ chế chung của 47 mã lệnh này trong `HotkeyService.Talk2Wmi::ExecuteWMI(string strNumber, string strData)`:
- Nạp `this` (`ldarg.0`), chuỗi mã lệnh (`ldarg.1`), nạp chuỗi tên phương thức WMI (`ldstr 0x70......`), sau đó gọi phương thức đọc WMI không tham số vào: `ExecMethod(string strNumber, string strMethodName)` (`Token MethodDef: 0x06000010`).
- Kết quả boolean trả về được lưu vào biến cục bộ `stloc.0`, sau đó nhảy tới `IL_1AC2` (`ldloc.0`, `ret`).
- Đối với các mã có mặt trong bộ đệm khởi tạo WMI `Package1` (`InitHotkey` `0x06000002`), bảng đối chiếu ghi nhận chính xác offset và độ dài trích xuất từ mảng byte thông qua hàm `ConvertArrayToData(int offset, int length)` (`0x06000003`), cùng hàm fallback `ExecMethod2` (`0x06000011`).

| Mã `cmd` (Dec / Hex) | Tên hàm WMI (`root\WMI` -> `CLEVO_GET`) | IL Offset trong `ExecuteWMI` (`0x0600000d`) | Token & Giá trị chuỗi WMI (`#US`) | Token hàm gọi & Cơ chế thực thi | Đối chiếu `InitHotkey` (`0x06000002`) & Cache `Package1` | Trạng thái |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`5`** (`0x05`) | **`GetRadioStateForWirless`** | `IL_12E7`..`IL_12F4` | `0x70000b83` (`"GetRadioStateForWirless"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`6`** (`0x06`) | **`GetPowerStateForCamera`** | `IL_12F9`..`IL_1306` | `0x70000223` (`"GetPowerStateForCamera"`) | `0x06000010` (`ExecMethod`) | `Package1`: `offset=37, len=1` (`IL_0286`). Fallback gọi `ExecMethod2` (`IL_0417`) | **PASS** |
| **`7`** (`0x07`) | **`GetPowerStateForBluetooth`** | `IL_130B`..`IL_1318` | `0x70000bb3` (`"GetPowerStateForBluetooth"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`8`** (`0x08`) | **`GetSRSState`** | `IL_131D`..`IL_132A` | `0x70000be7` (`"GetSRSState"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`9`** (`0x09`) | **`GetTouchPadState`** | `IL_132F`..`IL_133C` | `0x70000251` (`"GetTouchPadState"`) | `0x06000010` (`ExecMethod`) | `Package1`: `offset=40, len=1` (`IL_035A`). Fallback gọi `ExecMethod2` (`IL_042A`) | **PASS** |
| **`10`** (`0x0A`) | **`GetPowerStateFor3G`** | `IL_1341`..`IL_134E` | `0x70000bff` (`"GetPowerStateFor3G"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`11`** (`0x0B`) | **`GetPowerStateForODD`** | `IL_1353`..`IL_1360` | `0x70000c25` (`"GetPowerStateForODD"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`14`** (`0x0E`) | **`GetVGA2temp`** | `IL_1389`..`IL_1396` | `0x70000c8f` (`"GetVGA2temp"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`15`** (`0x0F`) | **`GetVGA2tempThermalIC`** | `IL_139B`..`IL_13A8` | `0x70000ca7` (`"GetVGA2tempThermalIC"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`18`** (`0x12`) | **`GetLCDAutoDimmer`** | `IL_13D1`..`IL_13DE` | `0x70000cf5` (`"GetLCDAutoDimmer"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`50`** (`0x32`) | **`GetBatteryDesignCpacity`** | `IL_1598`..`IL_15A5` | `0x70000f4f` (`"GetBatteryDesignCpacity"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`51`** (`0x33`) | **`GetBatteryAverageTimeToFullCharge`** | `IL_15AA`..`IL_15B7` | `0x70000f7f` (`"GetBatteryAverageTimeToFullCharge"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`52`** (`0x34`) | **`GetBatteryAverageTimeToEmpty`** | `IL_15BC`..`IL_15C9` | `0x70000fc3` (`"GetBatteryAverageTimeToEmpty"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`53`** (`0x35`) | **`GetCPUFANDuty`** | `IL_15CE`..`IL_15DB` | `0x70000ffd` (`"GetCPUFANDuty"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`54`** (`0x36`) | **`GetVGA1FANDuty`** | `IL_15E0`..`IL_15ED` | `0x70001019` (`"GetVGA1FANDuty"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`55`** (`0x37`) | **`GetVGA2FANDuty`** | `IL_15F2`..`IL_15FF` | `0x70001037` (`"GetVGA2FANDuty"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`56`** (`0x38`) | **`GetFANCount`** | `IL_1604`..`IL_1611` | `0x70001055` (`"GetFANCount"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`59`** (`0x3B`) | **`GetLCDResolution`** | `IL_1620`..`IL_162D` | `0x7000106d` (`"GetLCDResolution"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`60`** (`0x3C`) | **`GetHDMIport`** | `IL_1632`..`IL_163F` | `0x7000108f` (`"GetHDMIport"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`61`** (`0x3D`) | **`GetWhiteLedKB`** | `IL_1644`..`IL_1651` | `0x70000295` (`"GetWhiteLedKB"`) | `0x06000010` (`ExecMethod`) | `Package1`: `offset=98, len=1` (`IL_0313`). Fallback gọi `ExecMethod2` (`IL_0464`) | **PASS** |
| **`62`** (`0x3E`) | **`GetGSensorMode`** | `IL_1656`..`IL_1663` | `0x700010a7` (`"GetGSensorMode"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`63`** (`0x3F`) | **`GetHDPollingTime`** | `IL_1668`..`IL_1675` | `0x700010c5` (`"GetHDPollingTime"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`64`** (`0x40`) | **`GetRFID`** | `IL_167A`..`IL_1687` | `0x700010e7` (`"GetRFID"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`65`** (`0x41`) | **`GetGPS`** | `IL_168C`..`IL_1699` | `0x700010f7` (`"GetGPS"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`66`** (`0x42`) | **`GetBarCode`** | `IL_169E`..`IL_16AB` | `0x70001105` (`"GetBarCode"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`67`** (`0x43`) | **`GetBIOS_SF`** | `IL_16B0`..`IL_16BD` | `0x7000111b` (`"GetBIOS_SF"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`68`** (`0x44`) | **`GetVolumeLED`** | `IL_16C2`..`IL_16CF` | `0x700002d5` (`"GetVolumeLED"`) | `0x06000010` (`ExecMethod`) | `Package1`: `offset=106, len=1` (`IL_02A8`). Fallback gọi `ExecMethod2` (`IL_049E`) | **PASS** |
| **`69`** (`0x45`) | **`GetCurrentBrightness`** | `IL_16D4`..`IL_16E1` | `0x70001131` (`"GetCurrentBrightness"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`72`** (`0x48`) | **`OS_S3_S4`** | `IL_170A`..`IL_1717` | `0x70001179` (`"OS_S3_S4"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`74`** (`0x4A`) | **`RapidStarMode`** | `IL_171C`..`IL_1729` | `0x7000118b` (`"RapidStarMode"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`80`** (`0x50`) | **`GetACmA`** | `IL_179A`..`IL_17A7` | `0x7000121b` (`"GetACmA"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`81`** (`0x51`) | **`GetDCmAmV`** | `IL_17AC`..`IL_17B9` | `0x7000122b` (`"GetDCmAmV"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`82`** (`0x52`) | **`BIOS_special_feature_list`** | `IL_17BE`..`IL_17CB` | `0x700001dd` (`"BIOS_special_feature_list"`) | `0x06000010` (`ExecMethod`) | `Package1`: `offset=138, len=16` (`IL_02ED`). Fallback gọi `ExecMethod2` (`IL_03DC`) | **PASS** |
| **`83`** (`0x53`) | **`GetLux`** | `IL_17D0`..`IL_17DD` | `0x7000123f` (`"GetLux"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`84`** (`0x54`) | **`Aero`** | `IL_17E2`..`IL_17EF` | `0x700002ef` (`"Aero"`) | `0x06000010` (`ExecMethod`) | `Package1`: `offset=155, len=1` (`IL_0335`). Fallback gọi `ExecMethod2` (`IL_04CD`) | **PASS** |
| **`96`** (`0x60`) | **`GetTP_SW`** | `IL_18B2`..`IL_18BF` | `0x7000131b` (`"GetTP_SW"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`97`** (`0x61`) | **`GetFanStatus`** | `IL_18C4`..`IL_18D1` | `0x7000132d` (`"GetFanStatus"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`98`** (`0x62`) | **`RapidStar`** | `IL_18D6`..`IL_18E3` | `0x70001347` (`"RapidStar"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`99`** (`0x63`) | **`Fan1Info`** | `IL_18E8`..`IL_18F5` | `0x7000135b` (`"Fan1Info"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`100`** (`0x64`) | **`Fan2Info`** | `IL_18FA`..`IL_1907` | `0x7000136d` (`"Fan2Info"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`109`** (`0x6D`) | **`AirplaneButton`** | `IL_198B`..`IL_1998` | `0x70001421` (`"AirplaneButton"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`110`** (`0x6E`) | **`Fan3Info`** | `IL_199D`..`IL_19AA` | `0x7000143f` (`"Fan3Info"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`111`** (`0x6F`) | **`Fan4Info`** | `IL_19AF`..`IL_19BC` | `0x70001451` (`"Fan4Info"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`112`** (`0x70`) | **`GetFan12RPM`** | `IL_19C1`..`IL_19CE` | `0x70001463` (`"GetFan12RPM"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`113`** (`0x71`) | **`GetFan34RPM`** | `IL_19D3`..`IL_19E0` | `0x7000147b` (`"GetFan34RPM"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`115`** (`0x73`) | **`GetH2RAMData`** | `IL_19E5`..`IL_19F2` | `0x700013f3` (`"GetH2RAMData"`) | `0x06000010` (`ExecMethod`) | — (Chỉ đọc qua `ExecMethod`) | **PASS** |
| **`119`** (`0x77`) | **`GetChargingStatus`** | `IL_1A5B`..`IL_1A68` | `0x700002b1` (`"GetChargingStatus"`) | `0x06000010` (`ExecMethod`) | `Package1`: `offset=223, len=3` (`IL_037C`). Fallback gọi `ExecMethod2` (`IL_048B`) | **PASS** |

---

## 3. Bảng đối chiếu 9 Mã Lệnh No-op, IPC EventLog và Thực thi Tiến trình

Nhóm 9 mã lệnh này không gọi các phương thức WMI thông thường (`ExecMethod`/`InvokeMethod`) trong `ExecuteWMI`, mà phục vụ cơ chế bỏ qua (No-op), IPC giữa Client GUI và DCHUService thông qua Windows EventLog (`PowerBiosServerLog`), hoặc khởi chạy tiến trình bên ngoài.

| Mã `cmd` (Dec / Hex) | Hành vi trong `ExecuteWMI` (`0x0600000d`) | Hành vi trong `Service1::inlog_EntryWritten` (`0x0600005f`) | Bằng chứng IL & Token hàm gọi | Ý nghĩa kỹ thuật & Vai trò hệ thống | Trạng thái |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`57`** (`0x39`) | **No-op**: Nhảy thẳng tới `IL_1AC2` (ret `false`) | Không xử lý | `IL_1616`: `br 6850` (`IL_1AC2`) | Nhánh rỗng dự phòng trong WMI switch. | **PASS** |
| **`58`** (`0x3A`) | **No-op**: Nhảy thẳng tới `IL_1AC2` (ret `false`) | Không xử lý | `IL_161B`: `br 6850` (`IL_1AC2`) | Nhánh rỗng dự phòng trong WMI switch. | **PASS** |
| **`248`** (`0xF8`) | **No-op**: Nhảy thẳng tới `IL_1AC2` (ret `false`) | Không xử lý | `IL_1A99`: `br.s 6850` (`IL_1AC2`) | Nhánh rỗng dự phòng trong WMI switch. | **PASS** |
| **`249`** (`0xF9`) | **No-op**: Nhảy thẳng tới `IL_1AC2` (ret `false`) | Không xử lý | `IL_1A9B`: `br.s 6850` (`IL_1AC2`) | Nhánh rỗng dự phòng trong WMI switch. | **PASS** |
| **`251`** (`0xFB`) | **No-op**: Nhảy thẳng tới `IL_1AC2` (ret `false`) | Không xử lý | `IL_1A9D`: `br.s 6850` (`IL_1AC2`) | Nhánh rỗng dự phòng trong WMI switch. | **PASS** |
| **`252`** (`0xFC`) | **No-op trong `ExecuteWMI`** | **Khởi chạy tiến trình Bypass UAC theo Explorer Session ID** | - `ExecuteWMI` @ `IL_1A9F`: `br.s 6850`<br>- `inlog_EntryWritten` @ `IL_02BF`: nạp chuỗi `"252"` (`0x70000b07`), so sánh khớp nhảy tới `IL_02D3` gọi `0x0600006a` (`StartProcessAndBypassUACAsExplorerSessionId(strData)`) | IPC kênh EventLog: Thực thi ứng dụng với quyền người dùng tương tác trong phiên đăng nhập Explorer. | **PASS** |
| **`253`** (`0xFD`) | **No-op trong `ExecuteWMI`** | **Điều phối khởi chạy FnKey / UWP App / Explorer Process** | - `ExecuteWMI` @ `IL_1AA1`: `br.s 6850`<br>- `inlog_EntryWritten` @ `IL_00BA`: nạp chuỗi `"253"` (`0x70000b0f`), kiểm tra các nhánh con của `strData`:<br>  + Nếu `strData == "launchfnkey"` (`0x7000219d` @ `IL_00D5`): gọi `0x06000062` (`LaunchFnKeyFromCMD`)<br>  + Nếu `strData` chứa tiền tố `"launchapp"` (`0x700021fb` @ `IL_0134`): phân tách tham số qua `^` và gọi `0x06000063` (`LaunchAppFromCMD(appName, pkgFamilyName, killOther, procName)`)<br>  + Nhánh mặc định: gọi `0x0600006a` (`StartProcessAndBypassUACAsExplorerSessionId(strData)`) | IPC kênh EventLog: Kênh điều phối khởi chạy OSD FnKey và các ứng dụng Control Center dạng UWP/Desktop. | **PASS** |
| **`254`** (`0xFE`) | **No-op trong `ExecuteWMI`** | **Khởi chạy tiến trình Bypass UAC tiêu chuẩn** | - `ExecuteWMI` @ `IL_1AA3`: `br.s 6850`<br>- `inlog_EntryWritten` @ `IL_009E`: nạp chuỗi `"254"` (`0x70000b17`), so sánh khớp nhảy tới `IL_00B2` gọi `0x0600006b` (`StartProcessAndByPassUAC(strData)`) | IPC kênh EventLog: Khởi chạy tiến trình vượt qua UAC với token của session hiện hành. | **PASS** |
| **`255`** (`0xFF`) | **Thực thi tiến trình qua `Talk2Wmi::ExecuteProcess`** | **Thực thi tiến trình qua `Service1::ExecuteProcess`** | - `ExecuteWMI` @ `IL_1AA5`: nạp `strData` (`ldarg.2`), gọi `0x06000012` (`HotkeyService.Talk2Wmi::ExecuteProcess`)<br>- `inlog_EntryWritten` @ `IL_0082`: nạp chuỗi `"255"` (`0x70000b1f`), gọi `0x0600006d` (`Service1::ExecuteProcess(strData)`) | Khởi chạy tiến trình trực tiếp (`System.Diagnostics.Process::Start`) từ chuỗi tham số `strData`. | **PASS** |

---

## 4. Chi tiết Kỹ thuật Đối chiếu Chéo giữa các Phương thức

### 4.1. Đối chiếu Cơ chế Cache `Package1` và Fallback trong `Talk2Wmi::InitHotkey` (`0x06000002`)
Khi dịch vụ khởi động, `InitHotkey` thực hiện tối ưu hóa đọc hàng loạt trạng thái phần cứng bằng cách gọi phương thức WMI `Package1` (`0x70000111`) một lần duy nhất, nhận về một mảng byte chứa toàn bộ snapshot dữ liệu. Sau đó, nó dùng hàm `ConvertArrayToData(int offset, int length)` (`0x06000003`) để trích xuất từng thuộc tính:
- **Mã `6` (`GetPowerStateForCamera`):** trích xuất tại `offset = 37, length = 1` (`IL_0286`). Nếu WMI `Package1` thất bại, gọi hàm đọc riêng rẽ `ExecMethod2(regKey, "6", "GetPowerStateForCamera")` (`IL_0417`).
- **Mã `9` (`GetTouchPadState`):** trích xuất tại `offset = 40, length = 1` (`IL_035A`). Fallback gọi `ExecMethod2(regKey, "9", "GetTouchPadState")` (`IL_042A`).
- **Mã `17` (`GetCPUFANControl`):** trích xuất tại `offset = 48, length = 1` (`IL_0264`). Fallback gọi `ExecMethod2(regKey, "17", "GetCPUFANControl")` (`IL_043D`).
- **Mã `61` (`GetWhiteLedKB`):** trích xuất tại `offset = 98, length = 1` (`IL_0313`). Fallback gọi `ExecMethod2(regKey, "61", "GetWhiteLedKB")` (`IL_0464`).
- **Mã `68` (`GetVolumeLED`):** trích xuất tại `offset = 106, length = 1` (`IL_02A8`). Fallback gọi `ExecMethod2(regKey, "68", "GetVolumeLED")` (`IL_049E`).
- **Mã `70` (`GetAP`):** trích xuất tại `offset = 107, length = 16` (`IL_02CA`). Fallback gọi `ExecMethod2(regKey, "70", "GetAP")` (`IL_03C8`).
- **Mã `82` (`BIOS_special_feature_list`):** trích xuất tại `offset = 138, length = 16` (`IL_02ED`). Fallback gọi `ExecMethod2(regKey, "82", "BIOS_special_feature_list")` (`IL_03DC`).
- **Mã `84` (`Aero`):** trích xuất tại `offset = 155, length = 1` (`IL_0335`). Fallback gọi `ExecMethod2(regKey, "84", "Aero")` (`IL_04CD`).
- **Mã `119` (`GetChargingStatus`):** trích xuất tại `offset = 223, length = 3` (`IL_037C`). Fallback gọi `ExecMethod2(regKey, "119", "GetChargingStatus")` (`IL_048B`).
- **Mã `122` (`BiosSpecialFeature`):** trích xuất tại `offset = 228, length = 16` (`IL_023E`). Fallback gọi `ExecMethod2(regKey, "122", "BiosSpecialFeature")` (`IL_0094`).

*Kết luận:* Toàn bộ các tọa độ offset, độ dài byte và thứ tự dự phòng được ghi nhận trong `findings.md` khớp chính xác 100% với IL instruction anchors của `InitHotkey`.

### 4.2. Đối chiếu Cơ chế IPC qua EventLog trong `DCHUService.Service1::inlog_EntryWritten` (`0x0600005f`)
Hàm `inlog_EntryWritten` lắng nghe sự kiện ghi vào nguồn `PowerBiosServerSource` trong log `PowerBiosServerLog` (`IL_0374`..`IL_038A`):
1. **Định dạng thông điệp:** Dữ liệu nhận được có định dạng `w_arg{cmd}^{strData}` hoặc `r_arg{cmd}^{strData}`. Sau khi tách chuỗi tại ký tự `^` (`IL_0014`, `IL_0043`), mã lệnh `cmd` được trích xuất để so sánh:
2. **Mã `255` (`IL_0082`):** So sánh `cmd == "255"`, nếu khớp gọi `Service1::ExecuteProcess(strData)` (`0x0600006d`).
3. **Mã `254` (`IL_009E`):** So sánh `cmd == "254"`, nếu khớp gọi `Service1::StartProcessAndByPassUAC(strData)` (`0x0600006b`).
4. **Mã `253` (`IL_00BA`):** So sánh `cmd == "253"`, kiểm tra `strData`:
   - So sánh bằng `strData == "launchfnkey"` (`IL_00D5`) -> gọi `0x06000062` (`LaunchFnKeyFromCMD`).
   - Kiểm tra chứa tiền tố `"launchapp"` (`IL_0134`) -> tách 4 trường thông tin `appName`, `pkgFamilyName`, `killOtherSessionApp`, `procName` (`IL_0251`..`IL_0291`) và gọi `0x06000063` (`LaunchAppFromCMD`).
   - Không khớp 2 điều kiện trên -> gọi `0x0600006a` (`StartProcessAndBypassUACAsExplorerSessionId`).
5. **Mã `252` (`IL_02BF`):** So sánh `cmd == "252"`, nếu khớp gọi `Service1::StartProcessAndBypassUACAsExplorerSessionId(strData)` (`0x0600006a`).

---

## 5. Tổng kết Toàn diện Đối chiếu 56 Mã Lệnh Còn Lại

1. **Tổng số mã lệnh kiểm chứng trong Task 2:** 56 mã lệnh.
2. **Kết quả đối chiếu:**
   - **47 / 47 mã đọc WMI qua `ExecMethod`:** Đạt **PASS** (100% trùng khớp với bytecode thực tế của `ExecuteWMI` và các tham chiếu tại `InitHotkey`).
   - **9 / 9 mã No-op, IPC EventLog, và ExecuteProcess:** Đạt **PASS** (100% trùng khớp với bytecode thực tế của `ExecuteWMI` và `Service1::inlog_EntryWritten`).
3. **Tổng hợp toàn bộ Giai đoạn 4 (Worker 1 + Worker 2):**
   - **Worker 1:** 61 mã lệnh (PASS 61/61).
   - **Worker 2:** 56 mã lệnh (PASS 56/56).
   - **Toàn bộ 117 mã lệnh trong `DCHUService.exe`:** **117 / 117 nhánh mã lệnh đạt PASS tuyệt đối 100%**, không có bất kỳ sai lệch nào giữa tài liệu `findings.md` và mã nhị phân thực tế.
