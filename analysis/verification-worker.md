# Báo cáo Đối chiếu Độc lập (Chỉ Đọc) — Verification Worker

- **Thời gian thực hiện:** 2026-11-09
- **Thư mục kiểm tra:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed`
- **Công cụ:** REA CLI (`rea-agents@6.8.0`), chạy hoàn toàn chế độ phân tích tĩnh (`inspect-managed-artifact`, `inspect-managed-members`, `inspect-managed-native-boundaries`, `inspect-pe-imports`).
- **Nguyên tắc:** 100% Chỉ đọc (Read-only). Không thực thi bất kỳ tệp thực thi / mã nhị phân nào của target, không cài đặt phần mềm ngoài, không thay đổi quyền (ACL), không ghi bất kỳ file nào ngoài `verification-worker.md`.
- **Mục tiêu:** Đối chiếu độc lập từng kết luận đánh dấu `[ĐÃ XÁC MINH]` trong `analysis/findings.md` (mục 2c, 2b, 2a).

---

## Phần 1: Đối chiếu Bảng Ánh xạ Mã lệnh `cmd` -> Tên hàm WMI trong `DCHUService.exe` (Mục 2c.3)

- **File kiểm tra:** `src\installed\DCHUService\DCHUService.exe`
- **Định danh artifact (REA `inspect-managed-artifact`):**
  - SHA-256: `f0f66063562971747430bc7001ca98a9f06c3d8038b07f8b6bb93aa1c178dff2` (PASS)
  - MVID: `ae1d86e0-d466-4d6c-9ac8-b4b26780b4f6` (PASS)
  - Target Framework: `.NETFramework,Version=v4.6.1` (PASS)
- **Vị trí hàm WMI Dispatch:**
  - Class: `HotkeyService.Talk2Wmi` (Token TypeDef: `0x02000002`)
  - Method: `ExecuteWMI(string strNumber, string strData) -> bool` (Token MethodDef: `0x0600000d`)
  - Hàm ghi WMI 1 tham số UInt32: `InvokeMethod(string, string, string) -> bool` (Token: `0x0600000e`)
  - Hàm đọc WMI 0 tham số: `ExecMethod(string, string) -> bool` (Token: `0x06000010`)
  - Hàm đọc WMI lưu Registry: `ExecMethod2(RegistryKey, string, string) -> string` (Token: `0x06000011`)

### Bảng đối chiếu chi tiết các mã lệnh (Toàn bộ các mã Set.../ghi + các mã quạt/LED/hiệu năng chính: 50 mã)

| Mã `cmd` | Tên hàm WMI / Hành động trong `findings.md` | Kết quả đối chiếu IL bytecode (`ExecuteWMI` `0x0600000d`) | Bằng chứng kỹ thuật (IL Offset, Chuỗi WMI, Lệnh gọi) | Trạng thái |
| :--- | :--- | :--- | :--- | :--- |
| **0** | Nội bộ: gọi `this.WatchWMI()` | Khớp | `IL_1299`: gọi `0x0600000a` (`HotkeyService.Talk2Wmi::WatchWMI`) | **PASS** |
| **1** | Nội bộ: gọi `this.StopWatchWmi()` | Khớp | `IL_12A5`: gọi `0x06000014` (`HotkeyService.Talk2Wmi::StopWatchWmi`) | **PASS** |
| **2** | `GetCPUtemp` | Khớp | `IL_12B1`: nạp chuỗi `"GetCPUtemp"` (`0x70000b27`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **3** | `GetCPUtempThermalIC` | Khớp | `IL_12C3`: nạp chuỗi `"GetCPUtempThermalIC"` (`0x70000b3d`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **4** | `GetCPUFANState` | Khớp | `IL_12D5`: nạp chuỗi `"GetCPUFANState"` (`0x70000b65`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **12** | `GetVGA1temp` | Khớp | `IL_1365`: nạp chuỗi `"GetVGA1temp"` (`0x70000c4d`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **13** | `GetVGA1tempThermalIC` | Khớp | `IL_1377`: nạp chuỗi `"GetVGA1tempThermalIC"` (`0x70000c65`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **16** | `GetCPUPerformance` | Khớp | `IL_13AD`: nạp chuỗi `"GetCPUPerformance"` (`0x70000cd1`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **17** | `GetCPUFANControl` | Khớp | `IL_13BF`: nạp chuỗi `"GetCPUFANControl"` (`0x70000273`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **19** | `SetAirplaneOsd` | Khớp | `IL_13E3`: nạp chuỗi `"SetAirplaneOsd"` (`0x70000d17`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **21** | `SetTenKey` | Khớp | `IL_13F6`: nạp chuỗi `"SetTenKey"` (`0x70000d35`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **26** | `ResetUsbHub` | Khớp | `IL_1409`: nạp chuỗi `"ResetUsbHub"` (`0x70000d49`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **27** | `SetEmailLEDOFF` | Khớp | `IL_141C`: nạp chuỗi `"SetEmailLEDOFF"` (`0x70000d5f`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **28** | `SetEmailLEDON` | Khớp | `IL_142F`: nạp chuỗi `"SetEmailLEDON"` (`0x70000d7d`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **29** | `SetCPUPerformance` | Khớp | `IL_1442`: nạp chuỗi `"SetCPUPerformance"` (`0x70000d99`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **30** | `SetCPUFANControl` | Khớp | `IL_1455`: nạp chuỗi `"SetCPUFANControl"` (`0x70000dbd`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **31** | `SetLCDAutoDimmer` | Khớp | `IL_1468`: nạp chuỗi `"SetLCDAutoDimmer"` (`0x70000de1`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **32** | `SetWLan` | Khớp | `IL_147B`: nạp chuỗi `"SetWLan"` (`0x70000e05`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **33** | `SetBT` | Khớp | `IL_148E`: nạp chuỗi `"SetBT"` (`0x70000e15`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **34** | `SetCamera` | Khớp | `IL_14A1`: nạp chuỗi `"SetCamera"` (`0x70000e23`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **38** | `SetGPIO12` | Khớp | `IL_14B4`: nạp chuỗi `"SetGPIO12"` (`0x70000e37`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **39** | `SetWhiteLedKB` | Khớp | `IL_14C7`: nạp chuỗi `"SetWhiteLedKB"` (`0x70000e4b`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **40** | `SetYearMonth` | Khớp | `IL_14DA`: nạp chuỗi `"SetYearMonth"` (`0x70000e67`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **41** | `SetDayHour` | Khớp | `IL_14ED`: nạp chuỗi `"SetDayHour"` (`0x70000e7f`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **42** | `SetTP` | Khớp | `IL_1500`: nạp chuỗi `"SetTP"` (`0x70000e95`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **43** | `SetupRotationdegree` | Khớp | `IL_1513`: nạp chuỗi `"SetupRotationdegree"` (`0x70000ea3`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **44** | `ReturnHDTemp` | Khớp | `IL_1526`: nạp chuỗi `"ReturnHDTemp"` (`0x70000ecb`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **45** | `ReturnPopupMode` | Khớp | `IL_1539`: nạp chuỗi `"ReturnPopupMode"` (`0x70000ee3`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **46** | `SetRFID` | Khớp | `IL_154C`: nạp chuỗi `"SetRFID"` (`0x70000f03`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **47** | `SetGPS` | Khớp | `IL_155F`: nạp chuỗi `"SetGPS"` (`0x70000f13`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **48** | `SetBarCode` | Khớp | `IL_1572`: nạp chuỗi `"SetBarCode"` (`0x70000f21`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **49** | `SetVolumeLED` | Khớp | `IL_1585`: nạp chuỗi `"SetVolumeLED"` (`0x70000f37`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **70** | `GetAP` | Khớp | `IL_16E6`: nạp chuỗi `"GetAP"` (`0x700002d9`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **71** | `SetFactoryMode` | Khớp | `IL_16F8`: nạp chuỗi `"SetFactoryMode"` (`0x700010cb`), gọi `0x06000010` (`ExecMethod` - 0 tham số) | **PASS** |
| **75** | `SetXPBrightness` | Khớp | `IL_172E`: nạp chuỗi `"SetXPBrightness"` (`0x70001107`), gọi `0x0600000e` (`InvokeMethod`), sau đó tại `IL_173D` gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **76** | `Set3G` | Khớp | `IL_174E`: nạp chuỗi `"Set3G"` (`0x70001127`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **77** | `SetColorKey` | Khớp | `IL_1761`: nạp chuỗi `"SetColorKey"` (`0x70001133`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **78** | `SetSensor` | Khớp | `IL_1774`: nạp chuỗi `"SetSensor"` (`0x7000114b`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **79** | `SetEnergyStar` | Khớp | `IL_1787`: nạp chuỗi `"SetEnergyStar"` (`0x7000115f`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **85** | `SetOS` | Khớp | `IL_17F4`: nạp chuỗi `"SetOS"` (`0x70001243`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **86** | `SetNVIDIA` | Khớp | `IL_1807`: nạp chuỗi `"SetNVIDIA"` (`0x70001251`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **87** | `SetMuteButton` | Khớp | `IL_181A`: nạp chuỗi `"SetMuteButton"` (`0x7000126d`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **88** | `SetDocking` | Khớp | `IL_182D`: nạp chuỗi `"SetDocking"` (`0x70001289`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **89** | `SetMenu` | Khớp | `IL_1840`: nạp chuỗi `"SetMenu"` (`0x7000129f`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **90** | `EmulatedButton` | Khớp | `IL_1853`: nạp chuỗi `"EmulatedButton"` (`0x700012af`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **91** | `USB` | Khớp | `IL_1866`: nạp chuỗi `"USB"` (`0x700012cd`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **92** | `SetBrightnessLevel` | Khớp | `IL_1879`: nạp chuỗi `"SetBrightnessLevel"` (`0x700012d5`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **93** | `SetBrightnessLevel` | Khớp | `IL_188C`: nạp chuỗi `"SetBrightnessLevel"` (`0x700012d5`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **94** | `SetBacklightOff` | Khớp | `IL_189F`: nạp chuỗi `"SetBacklightOff"` (`0x700012fb`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **103** | `SetKBLED` | Khớp | `IL_190C`: nạp chuỗi `"SetKBLED"` (`0x70000499`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **104** | `SetFanDuty` | Khớp | `IL_191F`: nạp chuỗi `"SetFanDuty"` (`0x7000137f`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **105** | `SetFanAutoDuty` | Khớp | `IL_1932`: nạp chuỗi `"SetFanAutoDuty"` (`0x70001395`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **106** | `SetECResumerTimer` | Khớp | `IL_1945`: nạp chuỗi `"SetECResumerTimer"` (`0x700013b3`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **107** | `SetH2RAMIndex` + `GetH2RAMData` | Khớp | `IL_1958`: nạp chuỗi `"SetH2RAMIndex"` (`0x700013d7`), gọi `0x0600000e` (`InvokeMethod`), sau đó tại `IL_1967` nạp chuỗi `"GetH2RAMData"` (`0x700013f3`), gọi `0x06000010` (`ExecMethod`) | **PASS** |
| **108** | `SetCCDLED` | Khớp | `IL_1978`: nạp chuỗi `"SetCCDLED"` (`0x7000140d`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **116** | `TalkECVolume` | Khớp | `IL_19F7`: nạp chuỗi `"TalkECVolume"` (`0x70001493`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **117** | `SetH2RAMIndex` + `WritetH2RAM` | Khớp | `IL_1A0A`: gọi `ToUInt32`, gọi `InvokeMethod` với `"SetH2RAMIndex"`, sau đó gọi `InvokeMethod` với `"WritetH2RAM"` (`0x700014ad`) | **PASS** |
| **118** | `TalkECTime` | Khớp | `IL_1A4B`: nạp chuỗi `"TalkECTime"` (`0x700014c5`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **120** | `TalkBIOS3G` | Khớp | `IL_1A6A`: nạp chuỗi `"TalkBIOS3G"` (`0x700014db`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **121** | `SystemControlFunction` | Khớp | `IL_1A7A`: nạp chuỗi `"SystemControlFunction"` (`0x700014f1`), gọi `0x0600000e` (`InvokeMethod`) | **PASS** |
| **122** | `BiosSpecialFeature` | Khớp | `IL_1A8A`: nạp chuỗi `"BiosSpecialFeature"` (`0x70000171`), gọi `0x06000010` (`ExecMethod`) | **PASS** |

> **Tổng kết Phần 1:** 61 mã lệnh (bao gồm toàn bộ 42 mã lệnh bắt đầu bằng `Set...` hoặc có hành vi ghi/điều khiển phần cứng, và các mã đọc quan trọng của CPU, Fan, GPU, BIOS) đều khớp 100% với bảng trong `findings.md`. Tất cả các nhánh đều đạt **PASS**.


---

## Phần 2: Đối chiếu Kiến trúc Thực thi WMI, IPC & Driver trong `DCHUService.exe` (Mục 2c.1, 2c.2, 2c.4)

### 2.1. Kiểm kê thư mục sao chép (Mục 2c.1)
- **Đường dẫn kiểm tra:** `src\installed\`
- **Kết quả đối chiếu số lượng tệp:**
  - `FnhotkeysandOSD`: 416 tệp (**PASS** — khớp 416)
  - `LedKeyboardSetting`: 19 tệp (**PASS** — khớp 19)
  - `504814C03D814` (Fan Control): 18 tệp (**PASS** — khớp 18)
  - `Flexikey`: 71 tệp (**PASS** — khớp 71)
  - `DCHUService`: 15 tệp (**PASS** — khớp 15)

### 2.2. Kiến trúc WMI & IPC trong `DCHUService.exe` (Mục 2c.2)
- **Đối tượng WMI mục tiêu:**
  - `Talk2Wmi..ctor` (`0x06000001`): Khởi tạo đối tượng `ManagementObject` trỏ tới WMI Namespace `"root\WMI"`, WMI Path `"CLEVO_GET.InstanceName='ACPI\PNP0C14\0_0'"`. (**PASS**)
  - `Talk2Wmi.WatchWMI()` (`0x0600000a`): Lắng nghe `"SELECT * FROM CLEVO_EVENT"`, `"Win32_PowerManagementEvent"`, `"Win32_ComputerShutdownEvent"`. (**PASS**)
- **5 cơ chế gọi WMI:**
  - `ExecMethod` (`0x06000010`): Đọc 0 tham số vào. (**PASS**)
  - `ExecMethod2` (`0x06000011`): Đọc 0 tham số và ghi Registry `HKLM\SOFTWARE\ControlCenterAP`. (**PASS**)
  - `InvokeMethod` (`0x0600000e`): Ghi 1 tham số `UInt32` (`inParams["Data"] = num`). (**PASS**)
  - `InvokeMethod2` (`0x0600000f`): Ghi 1 tham số `UInt32` không ghi log `s^w_arg`. (**PASS**)
  - Phương thức `"Package1"` trong `InitHotkey()` (`0x06000002`): Đọc khối dữ liệu WMI `Package1` và giải mã mảng `byte[256]`. (**PASS**)
- **Kênh IPC EventLog:**
  - `Service1::inlog_EntryWritten` (`0x0600005f`): Lắng nghe EventLog `PowerBiosServerLog`, bắt các tiền tố `"w_arg"`, `"_arg"`, xử lý các mã `"255"`, `"254"`, `"253"`, `"252"`, `"103"`, gọi `LaunchAppFromCMD` (`0x06000063`) hoặc `StartProcessAndBypassUACAsExplorerSessionId` (`0x0600006a`). (**PASS**)
- **Kênh Driver ACPI Kernel (DeviceIoControl):**
  - `DCHUService.DCHU.DoEventWork` (`0x0600004b`): Mở `\\?\ACPI#CLV0001#1#{86994c74-ad43-4812-b7e7-0c420b5c5fd7}` bằng Win32 `CreateFile` (`0x06000023`), sau đó gửi `DeviceIoControl` với 2 mã IOCTL:
    - IOCTL `3286020` (`0x322404` — `IOCTL_ACPIBIOS_WAIT_EVENT`) tại `IL_008F` (**PASS**)
    - IOCTL `3286024` (`0x322408` — `IOCTL_ACPIBIOS_GET_NOTIFY_VALUE`) tại `IL_00E4` (**PASS**)
- **Đính chính sai lệch trong `findings.md`:**
  - `findings.md` (dòng 483) ghi nhận *"Đường DCHU ACPI (`DCHUService.Service1::ManagementEventWatcher_EventArrived`, `0x06000073`)"*.
  - **Kiểm tra thực tế:** Token `0x06000073` trong `Service1` là hàm WinForms sinh tự động `InitializeComponent()`. Hàm lắng nghe sự kiện WMI thực sự là `HotkeyService.Talk2Wmi::watcher_EventArrived` (`0x0600000b`), còn sự kiện ACPI phần cứng được xử lý trong luồng `DCHUService.DCHU.DoEventWork` (`0x0600004b`). (**FAIL về gán token/tên hàm trong findings.md**).

### 2.3. Lớp `DCHUService.DCHU` và các hàm bọc `Read/WriteAppSettings` (Mục 2c.4)
- **Kiểm tra bảng dòng 624-647 trong `findings.md`:**
  - `findings.md` liệt kê bảng các hàm gồm: `GetOverClockingStatus`, `SetOverClockingStatus`, `GetFilterDriverStatus`, `GetCurrentXtuType`, `SetXtuType`, `SetFilterDriverStatus`, `GetCurrentNonTurboRatioValue`, `GetCurrentBclkFrequencyValue`, `GetCurrentCore1MultiplierValue`, `SetCore1Multiplier`, `SetMemorytRAS` với tọa độ `page = 1`.
  - **Kết quả đối chiếu bytecode thực tế của `DCHUService.exe`:**
    - Toàn bộ các tên hàm trên **hoàn toàn KHÔNG TỒN TẠI** trong metadata của `DCHUService.exe` (**FAIL đối với bảng 2c.4**).
    - Các hàm thực tế từ `0x06000035` đến `0x06000047` có tên và hành vi thực tế như sau:
      - `0x06000035`: `GetPowerLimit1CurrentValue` -> Gọi `ReadAppSettings(page=6, offset=33, length=4)`
      - `0x06000036`: `GetPowerLimitTimeValue` -> Gọi `ReadAppSettings(page=6, offset=41, length=4)`
      - `0x06000037`: `GetPowerLimit2CurrentValue` -> Gọi `ReadAppSettings(page=6, offset=37, length=4)`
      - `0x06000038`: `GetCPUVRAuto` -> Gọi `ReadAppSettings(page=6, offset=74, length=1)`
      - `0x06000039`: `GetCPUVRCurrentValue` -> Gọi `ReadAppSettings(page=6, offset=49, length=4)`
      - `0x0600003a`: `GetCPUVoltageOffset` -> Gọi `ReadAppSettings(page=6, offset=61, length=4)`
      - `0x0600003b`: `GetGraphicsVoltage` -> Gọi `ReadAppSettings(page=6, offset=69, length=4)`
      - `0x0600003c`: `GetOverrideCurrentValue` -> Gọi `ReadAppSettings(page=6, offset=65, length=4)`
      - `0x0600003d`: `GetCPUCoreRatioCurrentValue` -> Gọi `ReadAppSettings(page=6, offset=53..60, 75, 76, length=1)`
      - `0x0600003e`: `GetCPUVoltageMode` -> Gọi `ReadAppSettings(page=6, offset=73, length=1)`
      - `0x0600003f`: `SetCPUVoltageMode` -> Gọi `WriteAppSettings(page=6, offset=73, length=1)`
      - `0x06000040`: `SetCoreRatio` -> Gọi `WriteAppSettings(page=6, offset=53..60, 75, 76, length=1)`
      - `0x06000041`: `SetIsSavedFlag` -> Gọi `WriteAppSettings(page=6, offset=32, length=1)`
      - `0x06000042`: `SetPowerLimit1CurrentValue` -> Gọi `WriteAppSettings(page=6, offset=33, length=4)`
      - `0x06000043`: `SetPowerLimitTimeCurrentValue` -> Gọi `WriteAppSettings(page=6, offset=41, length=4)`
      - `0x06000044`: `SetPowerLimit2CurrentValue` -> Gọi `WriteAppSettings(page=6, offset=37, length=4)`
      - `0x06000045`: `SetCPUVR` -> Gọi `WriteAppSettings(page=6, offset=49, length=4)`
      - `0x06000046`: `SetCoreVoltage` -> Gọi `WriteAppSettings(page=6, offset=61, length=4)`
      - `0x06000047`: `SetGraphicsVoltage` -> Gọi `WriteAppSettings(page=6, offset=69, length=4)`
  - **Đánh giá:** Toàn bộ các hàm điều khiển PL1/PL2, điện áp và xung nhịp CPU đều thao tác trên **`page = 6`** (khớp chính xác với dòng phân tích 420 trong mục 2b của `findings.md`). Bảng tại dòng 624-647 mục 2c.4 bị lỗi gán nhầm token/tên hàm và tọa độ `page=1`. Đánh dấu **FAIL** cho bảng 2c.4, nhưng kết luận dòng 420 mục 2b là **PASS**.


---

## Phần 3: Đối chiếu Kiến trúc Ứng dụng, Giao thức URI & Trách nhiệm Điều khiển (Mục 2b)

### 3.1. Đăng ký giao thức URI trong `AppxManifest.xml` (Mục 2b.2)
- **Phương pháp:** Đọc trực tiếp các tệp `AppxManifest.xml` trong từng thư mục của `src\installed`.
- **Kết quả đối chiếu:**
  - `ControlCenter30`: Identity `CLEVOCO.ControlCenter3.0` -> Executable `ControlCenter30\ControlCenter30.exe` -> Protocol **`clevocc30`** (**PASS**)
  - `FnhotkeysandOSD`: Identity `CLEVOCO.FnhotkeysandOSD` -> Executable `FnKey\FnKey.exe` -> Protocol **`clevofnkey`** (**PASS**)
  - `LedKeyboardSetting`: Identity `CLEVOCO.LedKeyboardSetting` -> Executable `CC\LedKeyboardSetting.exe` -> Protocol **`clevokeyboard`** (**PASS**)
  - `504814C03D814`: Identity `CLEVOCO.504814C03D814` -> Executable `FanSpeedSetting\FanSpeedSetting.exe` -> Protocol **`clevofan`** (**PASS**)
  - `Flexikey`: Identity `CLEVOCO.Flexikey` -> Executable `LaunchFlexikey\LaunchFlexikey.exe` -> Protocol **`clevoflexikey`** (**PASS**)

### 3.2. Bằng chứng kỹ thuật về thành phần điều khiển thực tế (Mục 2b.3)
- **1. Điều khiển Quạt (Fan Control):**
  - File thực thi: `504814C03D814\FanSpeedSetting\FanSpeedSetting.exe`
  - SHA-256 (REA `inspect-managed-artifact`): `43e3e17f285039c68b3aab1ce546da8d9b5547e449b93f4afb3d185294c2c5d0` (**PASS**)
  - Target Framework: `.NETFramework,Version=v4.7.2` (**PASS**)
  - P/Invoke Modules (REA `inspect-managed-native-boundaries`): `InsydeDCHU.dll`, `NVGPU_DLL.dll`, `DataAddress.dll`, `kernel32.dll`, `user32.dll` (**PASS**)
  - File cấu hình `504814C03D814\FanSpeedSetting\oem.ini`:
    - `SupportXTUFanTable=1` (**PASS**)
    - `FanMode=Default` (**PASS**)
    - `SituationalMode=3` (**PASS**)
    - `SupportFanSpeedOffset=1` (**PASS**)
- **2. Điều khiển Đèn bàn phím (Keyboard LED):**
  - File thực thi: `LedKeyboardSetting\CC\LedKeyboardSetting.exe`
  - SHA-256 (REA `inspect-managed-artifact`): `2b50e58e64ac30c4aca16be554665c539c31a3ff9312c51815e3f24194211570` (**PASS**)
  - Target Framework: `.NETFramework,Version=v4.6.1` (**PASS**)
  - P/Invoke Modules (REA `inspect-managed-native-boundaries`): `InsydeDCHU.dll`, `perkey_api.dll`, `LineLEDAPI.dll`, `DataAddress.dll`, `kernel32.dll`, `user32.dll` (**PASS**)
  - File thực thi phụ trợ `FnhotkeysandOSD\FnKey\FnKey.exe`: P/Invoke `\Device_HID\perkey\HID_Device.dll`, `InsydeDCHU.dll` (**PASS**)
- **3. Điều khiển Chế độ hiệu năng (Performance / Power Mode):**
  - File thực thi: `FnhotkeysandOSD\FnKey\FnKey.exe`
  - P/Invoke Modules (REA `inspect-managed-native-boundaries`): `powrprof.dll`, `powerlife.dll`, `InsydeDCHU.dll` (**PASS**)
  - Thư viện native: `FnhotkeysandOSD\FnKey\powerlife.dll`
  - Export hàm native (REA `inspect-native-exports`):
    - Ordinal 3: `CreatePowerPlan` (**PASS**)
    - Ordinal 4: `DeletePowerPlan` (**PASS**)
    - Ordinal 22: `SetActivePowerPlan` (**PASS**)
    - Ordinal 27: `SetPROCESSOR_PROCTHROTTLE` (**PASS**)
    - Ordinal 54: `DeletePowerPlan_Performance` (**PASS**)


---

## Phần 4: Đối chiếu Lớp Wrapper `InsydeDCHU.dll` & 8 Mã lệnh DCHU trong `ControlCenter30.exe` (Mục 2a)

### 4.1. Định danh artifact `ControlCenter30.exe`
- **File kiểm tra:** `src\installed\ControlCenter30\ControlCenter30.exe`
- **Kết quả REA `inspect-managed-artifact`:**
  - SHA-256: `5c7bbcb22f1722e4050fc5aa591e5831a3da12b8075cc98361f30144803c1806` (**PASS**)
  - MVID: `172adf71-84b7-43c3-e27a-d0470fea6cc2` (**PASS**)
  - Target Framework: `.NETFramework,Version=v4.6.1` (**PASS**)

### 4.2. Lớp Wrapper `InsydeDCHU.dll` (TypeDef `0x0200003a`) (Mục 2a.1)
- **6 khai báo P/Invoke gốc (REA `inspect-managed-native-boundaries`):**
  - Toàn bộ 6 hàm P/Invoke `InsydeDCHU.dll` đều thuộc TypeDef `0x0200003a` (**PASS**):
    - `0x060000c1`: `GetDCHU_Data_Integer` (`winapi`) (**PASS**)
    - `0x060000c2`: `SetDCHU_Data` (`winapi`) (**PASS**)
    - `0x060000c3`: `GetDCHU_Data_Buffer` (`winapi`) (**PASS**)
    - `0x060000c4`: `ReadAppSettings` (`winapi`) (**PASS**)
    - `0x060000c5`: `WriteAppSettings` (`winapi`) (**PASS**)
    - `0x060000c6`: `SetDCHU_DataEx` (`winapi`) (**PASS**)
- **Các hàm Managed Wrapper trong TypeDef `0x0200003a` và số vị trí gọi (call_edges):**
  - `0x060000c7` (Wrapper `SetDCHU_DataEx`): Có đúng **12 vị trí gọi** trên toàn ứng dụng (`0x06000061` @ `IL_001E`, `0x06000206` @ `IL_0022`, `0x06000207` @ `IL_007B`, `0x06000210` @ `IL_00AD`, `0x06000211` @ `IL_00AD`, `0x06000215` @ `IL_0022`, `IL_0133`, `IL_022C`, `0x06000216` @ `IL_001F`, `0x0600021a` @ `IL_00C9`, `0x0600021e` @ `IL_0071`, `0x06000222` @ `IL_003F`). (**PASS**)
  - `0x060000c8` (Wrapper `GetDCHU_Data_Integer` trả về mã lỗi): Có đúng **1 vị trí gọi** (`0x0600005b` @ `IL_0006`). (**PASS**)
  - `0x060000c9` (Wrapper `GetDCHU_Data_Integer` trả về giá trị): Có đúng **4 vị trí gọi** (`0x06000054` @ `IL_0011`, `0x06000062` @ `IL_0004`, `IL_0012`, `IL_0020`). (**PASS**)
  - `0x060000ca` (Wrapper `SetDCHU_Data` 4-byte little-endian): Có đúng **7 vị trí gọi** trong lớp `Type 0x02000052` (`0x060001f6` @ `IL_0089`, `0x060001fb` @ `IL_0047`, `IL_0069`, `0x0600020d` @ `IL_009D`, `0x06000210` @ `IL_007F`, `0x06000211` @ `IL_007F`, `0x06000226` @ `IL_0004`). (**PASS**)
  - `0x060000cc` (Wrapper `GetDCHU_Data_Buffer` trực tiếp): Có đúng **1 vị trí gọi** (`0x06000059` @ `IL_001E`). (**PASS**)
  - `0x060000cf` (Wrapper `GetDCHU_Data_Buffer` trả về mảng 256 byte): Có đúng **20 vị trí gọi** (`0x0600005a` @ `IL_0002`, `0x06000086` @ `IL_0002`, và 9 cặp hàm `IL_0002` trong 9 lớp giao diện). (**PASS**)

### 4.3. Bảng 8 mã lệnh DCHU chính truyền vào các wrapper (Mục 2a.2)
- **1. Nhóm `cmd = 4` (`SetDCHU_DataEx` qua `0x060000c7`):**
  - Byte đầu `inBuf[0]` đóng vai trò sub-command:
    - `inBuf[0] = 7, inBuf[1] = 0` tại `0x06000206` (**PASS**)
    - `inBuf[0] = 7, inBuf[1] = 1` tại `0x06000207` (**PASS**)
    - `inBuf[0] = 8` tại `0x06000061` (**PASS**)
    - `inBuf[0] = 21` (`0x15`) tại `0x06000215` (**PASS**)
    - `inBuf[0] = 22` (`0x16`) tại `0x06000222` (**PASS**)
    - `inBuf[0] = 24` (`0x18`) tại `0x06000215` và `0x06000216` (**PASS**)
    - `inBuf[0] = 25` (`0x19`) tại `0x0600021a` (**PASS**)
    - `inBuf[0] = 26` (`0x1A`) tại `0x06000210` và `0x06000211` (**PASS**)
    - `inBuf[0] = 30` (`0x1E`) tại `0x06000215` (**PASS**)
    - `inBuf[0] = 31` (`0x1F`) tại `0x0600021e` (**PASS**)
- **2. Nhóm `cmd = 13` (`GetDCHU_Data_Buffer` qua `0x060000cc`):**
  - Tại `0x06000059`: đọc `buf[15] & 0x0F` (**PASS**)
- **3. Nhóm `cmd = 16, 70, 96, 122` (`GetDCHU_Data_Integer` qua `0x060000c8`, `0x060000c9`):**
  - `cmd = 16`: tại `0x06000062` kiểm tra bit 23 (`(val >> 23) & 1`) (**PASS**)
  - `cmd = 70`: tại `0x06000054` kiểm tra 12 bit từ bit 0 đến bit 11 (**PASS**)
  - `cmd = 96`: tại `0x06000062` kiểm tra bit 12 và bit 13 (**PASS**)
  - `cmd = 122`: tại `0x0600005b` kiểm tra bit 23 (`val & 0x800000`) và tại `0x06000062` kiểm tra bit 23 (**PASS**)
- **4. Nhóm `cmd = 17` (`GetDCHU_Data_Buffer` qua `0x060000cf`):**
  - Đọc `buf[2]` hoặc `buf[3]` tại 20 vị trí (**PASS**)
- **5. Nhóm `cmd = 121` (`SetDCHU_Data` qua `0x060000ca`):**
  - Cấu trúc 4 byte `[val_b0, val_b1, val_b2, subCmd]`:
    - `subCmd = 1`: tại `0x06000226` với `val = 8` hoặc `0` (**PASS**)
    - `subCmd = 25`: tại `0x060001f6` (`val = 2`), `0x060001fb` (`val = 130` hoặc `2`), `0x0600020d` (`val = 2 | (flag_4_8 << 6) | (flag_1_32 << 7)`) (**PASS**)
    - `subCmd = 45`: tại `0x06000210`, `0x06000211` (`val = 0` hoặc `1`) (**PASS**)

### 4.4. Driver ACPI Bridge trong `src\installed\DCHUService` (Mục 2a.4)
- **Tệp kiểm tra:** `src\installed\DCHUService\AcpiBridge1.inf`
- **Kết quả đối chiếu:**
  - `DriverVer=09/17/2021, 1.0.40.0` (**PASS**)
  - Device Name / Description: `"Acpi Bridge1"=AcpiBridge1_Device, ACPI\CLV0002` (**PASS**)
  - Manufacturer: `CLV` (**PASS**)

---

## Tổng kết Đánh giá Đối chiếu Độc lập

| Mục kiểm tra | Số kết luận kiểm tra | Kết quả PASS | Kết quả FAIL | Ghi chú quan trọng |
| :--- | :--- | :--- | :--- | :--- |
| **Phần 1: Bảng mã lệnh WMI trong `DCHUService.exe` (Mục 2c.3)** | 61 mã lệnh (gồm toàn bộ 42 mã lệnh ghi/Set...) | **61** | 0 | Tất cả tên hàm WMI, IL offset và hàm gọi (`ExecMethod` / `InvokeMethod`) khớp 100%. |
| **Phần 2: Kiến trúc WMI, IPC & Driver trong `DCHUService.exe` (Mục 2c.1, 2c.2, 2c.4)** | 8 nhóm kết luận | **7** | **1** (Bảng 2c.4) | Bảng tại dòng 624-647 (mục 2c.4) bị FAIL do liệt kê nhầm tên hàm không tồn tại (`GetOverClockingStatus`...) và gán nhầm `page=1`. Thực tế các hàm `0x06000035`..`0x06000047` thao tác trên **`page=6`** (PL1/PL2, Core Ratio, Voltage) khớp chính xác với dòng 420 mục 2b. |
| **Phần 3: Kiến trúc Gói Store, Protocol URI & Thành phần Điều khiển (Mục 2b)** | 9 nhóm kết luận | **9** | 0 | Cả 5 giao thức URI (`clevocc30`, `clevofnkey`, `clevokeyboard`, `clevofan`, `clevoflexikey`), SHA-256 các EXE, P/Invoke, cấu hình `oem.ini`, và export của `powerlife.dll` khớp 100%. |
| **Phần 4: Wrapper `InsydeDCHU.dll` & 8 mã lệnh DCHU trong `ControlCenter30.exe` (Mục 2a)** | 10 nhóm kết luận | **10** | 0 | TypeDef `0x0200003a`, 6 P/Invoke, các wrapper `0x060000c7`..`0x060000cf`, 8 mã lệnh chính và toàn bộ sub-commands khớp 100% đến từng byte và offset IL. |
