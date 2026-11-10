# Control Center 3.0 (Clevo) — Giai đoạn 1: Khảo sát tĩnh

- **Ngày:** 2026-11-09
- **Đối tượng:** `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed` (bản copy gói MSIX/Store)
- **Phạm vi:** Chỉ đọc. Không chạy file nào trong thư mục. Không Frida/GDB/process capture. Không cài phần mềm.
- **Công cụ:** REA `rea-agents` 6.8.0 qua CLI (MCP bị ngắt sau khi server khởi động lại; CLI là cùng bản, chạy từ cache npx có sẵn, không tải thêm). Các lệnh REA đã dùng đều là phân tích tĩnh "không thực thi image": `inspect-pe-imports`, `inspect-native-exports`, `inspect-managed-artifact`, `inspect-managed-native-boundaries`, `inspect-managed-members`. Ngoài REA: đọc XML bằng trình đọc file, và quét chuỗi thô (ASCII/UTF‑16) bằng PowerShell `ReadAllBytes` (chỉ đọc byte).

**Quy ước:**
- **ĐÃ XÁC MINH** = quan sát trực tiếp trong file/metadata, có nguồn (file + bảng/hàm/Evidence ID).
- **GIẢ THUYẾT** = suy luận từ dấu hiệu, chưa được chứng minh bằng mã/luồng thực thi.
- **CHƯA BIẾT** = chưa có bằng chứng theo hướng nào.

## Định danh file (SHA-256)

| File | Kích thước | SHA-256 |
|---|---|---|
| `ControlCenter30\ControlCenter30.exe` | 2 089 984 | `5c7bbcb22f1722e4050fc5aa591e5831a3da12b8075cc98361f30144803c1806` |
| `ControlCenter30\GetProductdll.dll` | 2 619 392 | `5395dcd8e77b6bb113c128e04a46ffc860d8ee7769d1662837ed25ae9abcf1fa` |
| `ControlCenter30\InsydeDCHU.dll` | 2 492 416 | `dab807b5d4a621893ef5c5c1941e9d8ce91dda6b2518e931f4bb4727dfd80e98` |

Các file khác trong gói: `System.Management.Automation.dll` (PowerShell SDK, đóng kèm), `System.Runtime.WindowsRuntime*.dll`, `mtlanguage.ini`, `manual.pdf`, `appDescription.xml`, ảnh tile, `AppxSignature.p7x`, `AppxMetadata\CodeIntegrity.cat`. **Không có file `.sys`, `.inf`, `.cat` driver hay EXE dịch vụ nào trong gói** (ĐÃ XÁC MINH — liệt kê thư mục).

---

## 1. AppxManifest.xml

| # | Kết luận | Trạng thái | Nguồn |
|---|---|---|---|
| 1.1 | Gói `CLEVOCO.ControlCenter3.0`, publisher hiển thị "CLEVO CO.", phiên bản 7.68.1.0, x64. | ĐÃ XÁC MINH | `AppxManifest.xml` dòng 3–6 |
| 1.2 | App khởi động **`ControlCenter30\ControlCenter30.exe`** với `EntryPoint="Windows.FullTrustApplication"` (ứng dụng desktop Win32/.NET đóng gói qua Desktop Bridge, không phải UWP sandbox). | ĐÃ XÁC MINH | `AppxManifest.xml` dòng 18 |
| 1.3 | Quyền duy nhất: **`rescap:runFullTrust`**. Không có `deviceCapability`, không có capability WMI/driver/custom nào khác. | ĐÃ XÁC MINH | dòng 39–41 |
| 1.4 | Extension duy nhất: **protocol `clevocc30:`** (DisplayName còn để mặc định "SDK Sample URI Scheme"). | ĐÃ XÁC MINH | dòng 20–25 |
| 1.5 | **Không khai báo** dịch vụ nền (`windows.service`), `windows.fullTrustProcess`, `desktop:StartupTask`, background task, COM server hay driver nào. | ĐÃ XÁC MINH (vắng mặt trong manifest) | toàn bộ `AppxManifest.xml` |
| 1.6 | Build metadata: VS 2019 Professional, `TargetFrameworkMoniker=.NETFramework,Version=v4.5.1` (manifest), còn `ControlCenter30.exe.config` yêu cầu `.NETFramework,Version=v4.6.1`. | ĐÃ XÁC MINH | manifest dòng 44–46; `ControlCenter30.exe.config` dòng 4 |
| 1.7 | `appDescription.xml` liệt kê các tính năng: ép xung CPU/GPU, chế độ hoạt động (FN key), bảng quạt (`_FAN`), đèn LED per-key và bàn phím (`_PERKEY`, `_KEYBOARD`), phím macro (`_FLEXIKEY`), app điện thoại (`_FA20`). | ĐÃ XÁC MINH (là văn bản mô tả, không chứng minh mã thực hiện) | `ControlCenter30\appDescription.xml` |
| 1.8 | Driver/dịch vụ phần cứng được cài **riêng, ngoài gói này** (mô hình DCH: driver + Hardware Support App). | GIẢ THUYẾT | suy ra từ 1.5 + việc `InsydeDCHU.dll` mở device interface (xem 3.x) |

---

## 2. .NET hay native?

| File | Kết luận | Trạng thái | Nguồn |
|---|---|---|---|
| `ControlCenter30.exe` | **.NET Framework (managed, IL-only), x64, WPF.** CLI header có, flag `il-only`, không ReadyToRun, không mixed-mode. Metadata v4.0.30319, TargetFramework `.NETFramework,Version=v4.6.1`. Import native duy nhất: `mscoree.dll!_CorExeMain`. Tham chiếu: PresentationFramework/Core, System.Xaml, WindowsBase (WPF), **System.Management** (WMI), **System.Management.Automation** (PowerShell), Windows.Foundation.*Contract, System.Runtime.WindowsRuntime. | ĐÃ XÁC MINH | REA `inspect_managed_artifact` ev_44b09492…49cf; `inspect_pe_imports` ev_a941e62e…ee23 |
| `ControlCenter30.exe` | **Bị obfuscate**: tên type/method là ký tự điều khiển (`\u0002`, `\u0003`…) hoặc dạng `IIl11i11lili`; chỉ `ControlCenter30.Properties.Settings` còn tên thật. | ĐÃ XÁC MINH | REA `inspect_managed_members` ev_28fadf6f…6cfa (bảng TypeDef/MethodDef) |
| `ControlCenter30.exe` | **Không có chuỗi `ldstr` nào** (0 literal trong #US) dù có 954 method; method `0x06000003` có chữ ký `string(int32)` và được gọi **1224 lần** → nhiều khả năng là hàm giải mã chuỗi của obfuscator. Mọi chuỗi (truy vấn WMI, script PowerShell, URI…) đều bị ẩn. | Số liệu: ĐÃ XÁC MINH. Vai trò "giải mã chuỗi": GIẢ THUYẾT | ev_28fadf6f…6cfa (`user_strings`, `call_edges`, `methods`) |
| `GetProductdll.dll` | **Native C/C++ x64 (PE32+)**, MFC liên kết tĩnh. Không có CLI header (không import mscoree). | ĐÃ XÁC MINH | REA `inspect_pe_imports` ev_6647ed73…fe1e; chuỗi RTTI MFC `.?AVC…@@` |
| `InsydeDCHU.dll` | **Native C/C++ x64 (PE32+)**, MFC liên kết tĩnh. Đường dẫn PDB: `D:\LOCAL_SOURCE_CODE\InsydeDCHU_dll\x64\Release\InsydeDCHU.pdb`; class RTTI `CInsydeDCHUApp`. | ĐÃ XÁC MINH | REA `inspect_pe_imports` ev_e6fd460c…051a; quét chuỗi thô |

---

## 3. Hàm/API liên quan WMI, ACPI, driver, quạt, đèn, hiệu năng

### 3.1 InsydeDCHU.dll (trọng tâm)

**Export (ĐÃ XÁC MINH — REA `inspect_native_exports` ev_f40958bb…79e8):**

| Ord | Export |
|---|---|
| 1 | `GetDCHU_Data_Integer` |
| 2 | `GetDCHU_Data_Buffer` |
| 3 | `ReadAppSettings` |
| 4 | `WriteAppSettings` |
| 5 | `SetDCHU_Data` |
| 6 | `SetDCHU_DataEx` |

**Import liên quan phần cứng (ĐÃ XÁC MINH — REA `inspect_pe_imports` ev_e6fd460c…051a, coverage complete):**

| DLL | Hàm | Ý nghĩa |
|---|---|---|
| `api-ms-win-devices-config-l1-1-1.dll` | `CM_Get_Device_Interface_List_SizeW`, `CM_Get_Device_Interface_ListW`, `CM_MapCrToWin32Err` | Tìm đường dẫn device interface theo GUID |
| `KERNEL32.dll` | `CreateFileW`, **`DeviceIoControl`**, `CloseHandle` | Mở handle tới driver và gửi IOCTL |
| `ADVAPI32.dll` | `RegOpenKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegCreateKeyExW`, `RegDeleteValueW`… | Đọc/ghi registry |
| `KERNEL32.dll` | `GetPrivateProfileStringW/IntW`, `WritePrivateProfileStringW` | Đọc/ghi file .ini |

Phần còn lại (USER32, GDI32, gdiplus, UxTheme, ole32, OLEAUT32, SHELL32…) là runtime MFC.

| # | Kết luận | Trạng thái |
|---|---|---|
| 3.1.a | **Không import WMI** (không `wbemuuid`/`wbemprox`, không chuỗi `ROOT\…`, `Select`, `Win32_`), **không import API ACPI/SetupDi**. | ĐÃ XÁC MINH (vắng mặt trong bảng import và quét chuỗi) |
| 3.1.b | Không thấy chuỗi tên device dạng `\\.\…` hay GUID dạng text; GUID interface nhiều khả năng nằm ở dạng nhị phân trong `.rdata`. | Vắng chuỗi: ĐÃ XÁC MINH. GUID nhị phân: GIẢ THUYẾT |
| 3.1.c | Luồng: `CM_Get_Device_Interface_ListW(GUID)` → `CreateFileW(đường dẫn interface)` → `DeviceIoControl(IOCTL, buffer)` để đọc/ghi "DCHU data" qua một **driver Insyde/Clevo** (có thể driver này chuyển tiếp sang phương thức ACPI/WMI của BIOS hoặc EC). | GIẢ THUYẾT — cần disassembly để xác nhận GUID, mã IOCTL, cấu trúc buffer |
| 3.1.d | Không có export/chuỗi nào gọi đích danh "fan", "LED", "keyboard", "performance". Các chức năng này nhiều khả năng được chọn bằng **tham số số nguyên (function/command ID)** truyền vào `SetDCHU_Data*`/`GetDCHU_Data_*`. | Vắng chuỗi: ĐÃ XÁC MINH. Cơ chế ID: GIẢ THUYẾT |

### 3.2 GetProductdll.dll

**Export (ĐÃ XÁC MINH — REA `inspect_native_exports` ev_8d8e5986…5b66):** `GetProductID`, `GetProductID_PCI`, `GetDocking`, `GetFinger`, `GetFinger1`, `GetELANTouchPad`, `GetATI7970M`, `CheckClevo`.

**Import liên quan (ĐÃ XÁC MINH — ev_6647ed73…fe1e):**
- `SETUPAPI.dll`: `SetupDiGetClassDevsA`, `SetupDiEnumDeviceInfo`, `SetupDiGetDeviceRegistryPropertyA`, `CM_Get_Device_IDA`, `CM_Get_DevNode_Status` → liệt kê thiết bị PnP.
- `ole32.dll`: `CoInitialize(Ex)`, `CoCreateInstance`; `OLEAUT32` (theo ordinal).
- Không có `DeviceIoControl`.

**Chuỗi (ĐÃ XÁC MINH — quét chuỗi thô):** `SELECT * FROM Win32_BaseBoard`, `SELECT * FROM Win32_PnpEntity`, `ROOT\CIMV2` (UTF‑16), `PNPDeviceID`, `E:\clevo\`.

| # | Kết luận | Trạng thái |
|---|---|---|
| 3.2.a | DLL này **nhận diện máy/thiết bị** (mainboard, thiết bị PnP, touchpad ELAN, cảm biến vân tay, docking, kiểm tra máy Clevo), **chỉ đọc**, không điều khiển quạt/đèn. | Export + import + chuỗi: ĐÃ XÁC MINH. "Chỉ đọc": GIẢ THUYẾT (chưa xem mã) |
| 3.2.b | WMI được gọi qua COM (`CoCreateInstance` → WbemLocator) với `ROOT\CIMV2` + `Win32_BaseBoard`/`Win32_PnpEntity`. | GIẢ THUYẾT (chuỗi + import COM khớp, chưa thấy luồng gọi) |

### 3.3 ControlCenter30.exe (managed)

**P/Invoke (ĐÃ XÁC MINH — REA `inspect_managed_native_boundaries` ev_1ae50e2b…0f9e; 39 dòng ImplMap, 5 ModuleRef):**

| Đích | Hàm | Wrapper token | Chữ ký managed | Số chỗ gọi |
|---|---|---|---|---|
| InsydeDCHU.dll | `GetDCHU_Data_Integer` | 0x060000c1 | `int(int, ref int)` | 2 (từ 0x060000c8, 0x060000c9) |
| InsydeDCHU.dll | `GetDCHU_Data_Buffer` | 0x060000c3 | `int(int, ref byte)` | 2 (0x060000cc, 0x060000cf) |
| InsydeDCHU.dll | `SetDCHU_Data` | 0x060000c2 | `int(int, byte[], int)` | 2 (0x060000ca, 0x060000cb) |
| InsydeDCHU.dll | `SetDCHU_DataEx` | 0x060000c6 | `int(int, byte[], int, ref byte)` | 1 (0x060000c7) |
| InsydeDCHU.dll | `ReadAppSettings` | 0x060000c4 | `int(int, int, int, ref byte)` | 19 |
| InsydeDCHU.dll | `WriteAppSettings` | 0x060000c5 | `int(int, int, int, ref byte)` | 11 |
| GetProductdll.dll | `GetProductID_PCI` | 0x06000053 | — | **0** (khai báo nhưng không thấy chỗ gọi) |
| gdi32.dll | `GetDeviceGammaRamp`, `SetDeviceGammaRamp` | 0x060000fa/fb | `int(IntPtr, ref struct)` | 3 mỗi hàm |
| user32.dll | `GetDC`, `FindWindow` (x9), `SetForegroundWindow` (x9) | — | — | — |
| kernel32 | `GetPrivateProfileString` (x10), `WritePrivateProfileString` | — | — | — |

Ghi chú: tham số đầu `int` của mọi hàm DCHU là ứng viên cho **mã lệnh/function ID** (GIẢ THUYẾT). Các wrapper 0x060000c7–0x060000cf (ví dụ `0x060000ca: int(int,int,uint)`, `0x060000cb: int(string)`, `0x060000cf: byte[](int)`) là lớp bọc managed quanh P/Invoke (ĐÃ XÁC MINH chữ ký; vai trò cụ thể CHƯA BIẾT).

**API hệ thống managed (ĐÃ XÁC MINH — `call_edges` trong ev_28fadf6f…6cfa):**

| API | Method gọi (token) | Nhận xét |
|---|---|---|
| `System.Management.ManagementObjectSearcher` .ctor/Get, `ManagementBaseObject.get_Item` | 0x06000011, 0x0600020f | **Truy vấn WMI** — chuỗi truy vấn bị mã hóa → namespace/class CHƯA BIẾT |
| `System.Management.Automation.PowerShell.Create/AddScript/Invoke` | 0x060001e4 | **Chạy script PowerShell** trong tiến trình; nội dung script CHƯA BIẾT |
| `Microsoft.Win32.RegistryKey.OpenBaseKey/OpenSubKey/GetSubKeyNames/GetValue`, `Registry.GetValue` | 0x060001be, 0x0600020e, 0x06000205 | Đọc registry |
| `System.Diagnostics.EventLog` (.ctor, Source, Log, WriteEntry, **EntryWritten**, EnableRaisingEvents) | ~12 method | Ghi **và lắng nghe** Event Log. Có thể dùng làm kênh tín hiệu với một thành phần khác (ví dụ dịch vụ/driver): GIẢ THUYẾT |
| `Windows.System.Launcher.LaunchUriAsync` | 25 chỗ / 10 method | Mở URI (có thể là protocol của app khác hoặc `clevocc30:`): GIẢ THUYẾT |
| `System.Diagnostics.Process.Start` | 0x06000239 | Khởi chạy tiến trình khác; đích CHƯA BIẾT |
| `Process.GetProcessesByName/GetProcesses` | 0x06000056, 0x06000093, 0x060001e5 | Kiểm tra tiến trình (single instance / app liên quan) |

| # | Kết luận | Trạng thái |
|---|---|---|
| 3.3.a | Mọi điều khiển phần cứng trực tiếp từ UI đi qua **InsydeDCHU.dll** (6 export), vì EXE không có P/Invoke nào khác tới API driver/IOCTL. | Không có P/Invoke tới driver khác: ĐÃ XÁC MINH. "Mọi" điều khiển: GIẢ THUYẾT (WMI/PowerShell có thể đảm nhận một phần) |
| 3.3.b | Gamma màn hình được chỉnh qua `Set/GetDeviceGammaRamp` (tính năng màu màn hình, không liên quan EC). | ĐÃ XÁC MINH (P/Invoke + chỗ gọi); mục đích UI: GIẢ THUYẾT |
| 3.3.c | Ánh xạ "function ID → quạt / đèn bàn phím / chế độ hiệu năng" **chưa xác định** vì tên đã bị obfuscate và chuỗi bị mã hóa. | CHƯA BIẾT |

---

## 4. Có cần cài thêm engine không?

Tình trạng hiện tại (REA `doctor`): **chưa cấu hình** Ghidra, IDA, Hopper, Kuna, JADX.

| Câu hỏi tiếp theo | Đủ với REA hiện có? | Cần thêm | Lý do |
|---|---|---|---|
| GUID device interface, mã IOCTL, bố cục buffer trong `GetDCHU_Data_*`/`SetDCHU_Data*` (InsydeDCHU.dll) | **Không** | **Ghidra 12.1.x** (cần JDK 21) — hoặc IDA nếu có bản quyền | Đây là mã máy x64. REA chỉ đọc được bảng import/export; cần decompiler để thấy hằng số truyền vào `CM_Get_Device_Interface_ListW`/`DeviceIoControl`. Đây là thông tin then chốt để viết lại trên Linux. |
| Truy vấn WMI trong GetProductdll.dll | Một phần (đã có chuỗi) | Ghidra (tùy chọn) | Chỉ để xác nhận luồng; mức ưu tiên thấp vì DLL này chỉ nhận diện máy. |
| Ánh xạ function ID ↔ tính năng (quạt/LED/hiệu năng) trong ControlCenter30.exe | **Không đủ** | Công cụ .NET: **de4dot** (gỡ obfuscation, giải mã chuỗi) + **ILSpy/dnSpyEx** (decompile C#) | REA đọc được metadata, P/Invoke, call graph ở mức IL, nhưng không decompile ra C# và không giải mã được chuỗi. Có thể nạp kết quả decompile lại vào REA (`import_managed_reconstruction`) để đối chiếu. Ghidra **không** giúp nhiều với file .NET. |
| Script PowerShell / truy vấn WMI trong EXE | Không | như trên | Chuỗi bị mã hóa (0 `ldstr`, hàm `0x06000003` được gọi 1224 lần). |

**Khuyến nghị (chưa thực hiện, chờ bạn duyệt):** cài Ghidra 12.1.x + JDK 21 rồi đặt `GHIDRA_INSTALL_DIR` để REA dùng `open_binary` trên `InsydeDCHU.dll`; song song dùng de4dot + ILSpy cho `ControlCenter30.exe`. Lưu ý: de4dot giải mã chuỗi bằng cách **nạp và gọi** hàm giải mã → thực chất là **thực thi mã của target**. Nếu giữ quy tắc "không chạy file", phải giải mã chuỗi thủ công/tĩnh bằng cách đọc IL của `0x06000003`.

---

## Câu hỏi còn mở
1. GUID interface và mã IOCTL của driver DCHU là gì? (cần Ghidra)
2. Driver nào cung cấp interface đó (tên service/`.inf`)? Không có trong gói; cần xem driver đã cài trên máy Windows (Device Manager / `pnputil`), ngoài phạm vi thư mục này.
3. Function ID nào ứng với quạt, đèn bàn phím, chế độ hiệu năng? (cần decompile EXE + InsydeDCHU)
4. Script PowerShell (0x060001e4) và các truy vấn WMI (0x06000011, 0x0600020f) làm gì?
5. Event Log `EntryWritten` có phải kênh giao tiếp với dịch vụ nền không?

## Ghi chú phạm vi và giới hạn
- Không thực thi target nào. Quét chuỗi thô chỉ đọc byte; chuỗi tìm thấy chưa chắc được dùng ở runtime.
- P/Invoke chỉ chứng minh **khai báo**; REA không xác minh native export tồn tại lúc chạy (trường hợp này export khớp tên với `inspect_native_exports`).
- Token metadata chỉ có nghĩa với đúng SHA-256 + MVID `172adf71-84b7-43c3-e27a-d0470fea6cc2` của EXE.
- Evidence ID ở trên là từ các lần chạy REA CLI; tôi không xuất evidence bundle ra đĩa (theo yêu cầu chỉ ghi file này).


---

## Giai đoạn 2a: Phân tích IL tĩnh quanh `InsydeDCHU.dll` & Kiểm kê Driver trên máy

**Phạm vi & Tuân thủ quy tắc:**
- Phân tích tĩnh 100% bytecode IL của `ControlCenter30\ControlCenter30.exe` (SHA-256: `5c7bbcb22f1722e4050fc5aa591e5831a3da12b8075cc98361f30144803c1806`, MVID: `172adf71-84b7-43c3-e27a-d0470fea6cc2`, REA Evidence ID: `ev_28fadf6fa8812b444b2c21432857b6de6594db72bb9ff68a8474b12b350c6cfa`).
- Không thực thi bất kỳ file nào trong thư mục đích, không cài Ghidra, không dùng `de4dot`, không gắn debugger/Frida.
- Kiểm kê driver trên máy chỉ đọc qua `pnputil /enum-drivers` và `Get-CimInstance Win32_PnPSignedDriver`.

---

### 1. Kiến trúc lớp Wrapper `InsydeDCHU.dll` trong `ControlCenter30.exe`

- **[ĐÃ XÁC MINH]** Toàn bộ 6 hàm P/Invoke của `InsydeDCHU.dll` nằm trong cùng một lớp tĩnh/wrapper là **TypeDef `0x0200003a`** (tên bị làm rối thành chuỗi ký tự Unicode không in được; trong toàn bộ bảng dưới đây các kiểu và hàm được định danh bằng **Metadata Token** cố định của PE/CLI).
- **[ĐÃ XÁC MINH]** Chữ ký P/Invoke gốc (IL size = 0, `PInvokeImpl`) trong `TypeDef 0x0200003a`:

| Method Token | Tên hàm export (`InsydeDCHU.dll`) | Chữ ký IL đầy đủ | Số nơi gọi trực tiếp P/Invoke |
|---|---|---|---|
| `0x060000c1` | `GetDCHU_Data_Integer` | `(int32 cmd, int32& outVal) -> int32` | 2 (`0x060000c8`, `0x060000c9`) |
| `0x060000c2` | `SetDCHU_Data` | `(int32 cmd, uint8[] inBuf, int32 inLen) -> int32` | 2 (`0x060000ca`, `0x060000cb`) |
| `0x060000c3` | `GetDCHU_Data_Buffer` | `(int32 cmd, uint8& outBufFirstByte) -> int32` | 2 (`0x060000cc`, `0x060000cf`) |
| `0x060000c4` | `ReadAppSettings` | `(int32 page, int32 offset, int32 length, uint8& outBufFirstByte) -> int32` | 6 (`0x060000ce`, `0x060000d0`, `0x060000d3`, `0x060000d6`, `0x060000d7`, `0x06000222`) |
| `0x060000c5` | `WriteAppSettings` | `(int32 page, int32 offset, int32 length, uint8& inBufFirstByte) -> int32` | 5 (`0x060000cd`, `0x060000d1`, `0x060000d2`, `0x060000d4`, `0x060000d5`) |
| `0x060000c6` | `SetDCHU_DataEx` | `(int32 cmd, uint8[] inBuf, int32 inLen, uint8& outBufFirstByte) -> int32` | 1 (`0x060000c7`) |

- **[ĐÃ XÁC MINH]** Các hàm Managed Wrapper trong `TypeDef 0x0200003a` bọc quanh 6 hàm P/Invoke trên:

| Wrapper Token | Chữ ký IL | Hành vi IL chi tiết (ĐÃ XÁC MINH) | Số lời gọi trong toàn app |
|---|---|---|---|
| `0x060000c7` | `(int32 cmd, uint8[] inBuf, uint8[]& outBuf) -> int32` | Gọi `SetDCHU_DataEx(cmd, inBuf, 256, ref outBuf[0])` (`ldc.i4 256`), ghi log qua `0x0600008e`, trả về `1` (hoặc `0` nếu ném ngoại lệ). | 12 |
| `0x060000c8` | `(int32 cmd, int32& outVal) -> int32` | Gọi `GetDCHU_Data_Integer(Convert.ToInt32(cmd), ref outVal)`, ghi log, trả về `1`/`0`. | 1 |
| `0x060000c9` | `(int32 cmd) -> int32` | Khởi tạo `int32 loc0 = 0`, gọi `GetDCHU_Data_Integer(cmd, ref loc0)`, ghi log, trả về trực tiếp `loc0`. | 4 |
| `0x060000ca` | `(int32 cmd, int32 subCmd, uint32 val) -> int32` | Cấp phát `byte[256]`, nhưng ghi đè `loc0 = BitConverter.GetBytes(val)` (mảng **4 byte** little-endian `[b0, b1, b2, b3]`), sau đó gán **`loc0[3] = Convert.ToByte(subCmd)`** (tức 3 byte đầu `loc0[0..2]` chứa 24-bit thấp của `val`, còn `loc0[3]` chứa `subCmd`), rồi gọi `SetDCHU_Data(cmd, loc0, loc0.Length)` (với `loc0.Length == 4`). | 7 |
| `0x060000cb` | `(string s) -> int32` | Chuyển `s` thành `int32`, cấp phát `byte[256]`, gọi `SetDCHU_Data`. **Không có bất kỳ hàm nào gọi `0x060000cb` (dead code).** | 0 |
| `0x060000cc` | `(int32 cmd, uint8& outBuf) -> int32` | Gọi trực tiếp `GetDCHU_Data_Buffer(cmd, ref outBuf)`. | 1 |
| `0x060000cd` | `(int32 page, int32 offset, int32 len, uint8[] buf) -> int32` | Gọi `WriteAppSettings(page, offset, len, ref buf[0])`. | 42 |
| `0x060000ce` | `(int32 page, int32 offset, int32 len) -> uint8[]` | Cấp phát `byte[len]`, gọi `ReadAppSettings(page, offset, len, ref buf[0])`, trả về mảng `byte[len]`. | 14 |
| `0x060000cf` | `(int32 cmd) -> uint8[]` | Cấp phát `byte[256]`, gọi `GetDCHU_Data_Buffer(cmd, ref buf[0])`, trả về mảng `byte[256]`. | 20 |
| `0x060000d0` .. `0x060000d7` | Các hàm helper đọc/ghi nhanh `AppSettings` | Gọi `ReadAppSettings` / `WriteAppSettings` với các bộ `(page, offset, len)` cố định: `(6, 253, 1)`, `(1, 17, 1)`, `(1, 18, 4)` (`int32`/`uint32`), `(1, 22, 4)` (`float32`). Không được gọi nội bộ trong `ControlCenter30.exe` (0 caller). | 0 |

---

### 2. Bảng tổng hợp các Mã lệnh (`cmd`) truyền vào `SetDCHU_Data`, `SetDCHU_DataEx`, `GetDCHU_Data_Integer`, `GetDCHU_Data_Buffer`

**[ĐÃ XÁC MINH]** Toàn bộ `ControlCenter30.exe` chỉ truyền đúng **8 hằng số nguyên mã lệnh chính (`cmd`)** vào 4 hàm giao tiếp DCHU (`4`, `13`, `16`, `17`, `70`, `96`, `121`, `122`). Trong đó mã lệnh `4` (`SetDCHU_DataEx`) có **9 mã lệnh phụ (`inBuf[0]`)** và mã lệnh `121` (`SetDCHU_Data`) có **3 mã lệnh phụ (`inBuf[3]`)**.

#### Nhóm A: Mã lệnh `cmd = 4` (`0x04`) — Gọi qua `SetDCHU_DataEx` (Wrapper `0x060000c7`)
- **[ĐÃ XÁC MINH]** Tham số: `cmd = 4`, `inBuf = byte[256]`, `inLen = 256`, `outBuf = byte[256]`. Byte đầu tiên `inBuf[0]` đóng vai trò **sub-command**.

| Mã lệnh (`cmd` / `inBuf[0]`) | Hàm chứa lời gọi (Method Token & Type Token) | Offset IL | Tham số & Cấu trúc Buffer truyền vào / đọc ra (ĐÃ XÁC MINH) | Ý nghĩa & Mức độ xác minh |
|---|---|---|---|---|
| `cmd = 4`, `inBuf[0] = 7`, `inBuf[1] = 0` | `0x06000206 () -> void` trong `Type 0x02000052` | `IL_0022` | Truyền `inBuf[0]=7, inBuf[1]=0`. Đọc `outBuf[2]` lưu vào field `int32 0x04000180`; đọc `outBuf[3]` qua hàm đổi dấu `0x06000208` lưu vào `int32 0x04000181`; đọc `outBuf[4]` qua `0x06000208` rồi **chia cho `1000.0f`** (`ldc.r4 1000`, `div`) lưu vào field `float32 0x04000182`. | **[GIẢ THUYẾT]** Đọc thông số ép xung / điện áp CPU (do có phép quy đổi chia `1000.0f` như mV -> V và nằm trong lớp cấu hình hệ thống `0x02000052`). |
| `cmd = 4`, `inBuf[0] = 7`, `inBuf[1] = 1` | `0x06000207 (int32) -> void` trong `Type 0x02000052` | `IL_007B` | Truyền `inBuf[0]=7, inBuf[1]=1, inBuf[2]=(byte)arg1`, `inBuf[3]=(byte)0x06000208(2, (uint)Selector_0x0400020c.SelectedValue)`, `inBuf[4]=(byte)0x06000208(0, (int)((float)Selector_0x0400020b.SelectedValue * 1000.0f))`. | **[GIẢ THUYẾT]** Ghi thông số ép xung / điện áp CPU (cặp tương ứng với `inBuf[0]=7, inBuf[1]=0`, nhân `1000.0f` từ V sang mV). |
| `cmd = 4`, `inBuf[0] = 8` | `0x06000061 () -> void` trong `Type 0x02000021` | `IL_001E` | Truyền `inBuf[0]=8`. Đọc `outBuf`: tính `field_0x04000080 = (outBuf[0] << 8) + outBuf[1]`. Truyền `outBuf` sang `0x06000062` / `0x06000064` để kiểm tra từng bit của `outBuf[17]` (`& 0x0F`, bit 0..3, và `(outBuf[17] >> 4) & 0x0F`). | **[ĐÃ XÁC MINH]** Đọc cờ phiên bản/nhánh giao thức (`0x04000080`, quyết định dùng `cmd=121` hay `cmd=4` ở các hàm khác) và bitmask tính năng phần cứng trong `outBuf[17]`. |
| `cmd = 4`, `inBuf[0] = 21` (`0x15`) | `0x06000215 () -> void` trong `Type 0x02000052` | `IL_022C` | Truyền `inBuf[0]=21`. Đọc `outBuf[1]` (kiểm tra các bit `& 1`, `& 2`, `& 4`, `& 8`) để thêm tối đa 4 mục vào `ComboBox 0x040001f5`, và đọc `outBuf[0]` (giá trị `1..4`) để chọn mục đang kích hoạt (`SelectedIndex`). | **[GIẢ THUYẾT]** Đọc danh sách các chế độ hỗ trợ (4 mức) và chế độ hiện tại của một tính năng phần cứng trên trang cấu hình `0x02000052` (**[CHƯA BIẾT]** tên chế độ cụ thể vì chuỗi hiển thị bị mã hóa qua `0x06000003`). |
| `cmd = 4`, `inBuf[0] = 22` (`0x16`) | `0x06000222 (uint8) -> void` trong `Type 0x02000052` | `IL_003F` | Trước đó gọi `ReadAppSettings(1, 35, 1)` (nếu khác `arg1` thì ghi `WriteAppSettings(1, 35, 1)`), sau đó truyền `inBuf[0]=22, inBuf[1]=arg1` vào `SetDCHU_DataEx(4, ...)`. | **[GIẢ THUYẾT]** Ghi/đặt chế độ tương ứng với sub-command `21` ở trên, đồng bộ với `AppSettings(1, 35, 1)`. |
| `cmd = 4`, `inBuf[0] = 24` (`0x18`) | `0x06000215 () -> void` (`IL_0133`) và `0x06000216 () -> void` (`IL_001F`) trong `Type 0x02000052` | `IL_0133`, `IL_001F` | Truyền `inBuf[0]=24`. Đọc `outBuf[0]`, `outBuf[1]`, `outBuf[2]`: với mỗi byte, nếu bằng `0` thì ẩn (`Visibility.Collapsed`) nút gạt tương ứng, nếu bằng `1` hoặc `2` thì đặt trạng thái `IsChecked` cho 3 `ToggleButton` (`0x040001e7`, `0x040001d8`, `0x040001bb`). | **[ĐÃ XÁC MINH]** Đọc trạng thái hỗ trợ và bật/tắt của bộ 3 công tắc (`ToggleButton`) trong `Type 0x02000052`. (**[CHƯA BIẾT]** tên 3 công tắc do chuỗi bị mã hóa). |
| `cmd = 4`, `inBuf[0] = 25` (`0x19`) | `0x0600021a () -> void` trong `Type 0x02000052` | `IL_00C9` | Đọc trạng thái `IsChecked` của 3 `ToggleButton` (`0x040001e7`, `0x040001d8`, `0x040001bb`), gán `inBuf[0]=25` và `inBuf[1..3]` bằng `1` hoặc `2`, gọi `SetDCHU_DataEx(4, ...)`, đồng thời lưu 3 byte này vào `WriteAppSettings(1, 36, 3, ...)`. | **[ĐÃ XÁC MINH]** Ghi trạng thái của bộ 3 công tắc (`ToggleButton`) xuống DCHU và lưu vào `AppSettings(1, 36, 3)`. |
| `cmd = 4`, `inBuf[0] = 26` (`0x1A`) | `0x06000210 (object, RoutedEventArgs) -> void` (`IL_00AD`) và `0x06000211 () -> void` (`IL_00AD`) trong `Type 0x02000052` | `IL_00AD` | Khi `field_0x04000080 != 0`: truyền `inBuf[0]=26, inBuf[1]=val` (`0` hoặc `1`, lấy từ `ToggleButton 0x04000197` / `AppSettings(1, 33, 1)`). *(Lưu ý: nếu `field_0x04000080 == 0`, hàm gọi `SetDCHU_Data(121, subCmd=45, val)` thay vì `cmd=4, subCmd=26`)*. | **[ĐÃ XÁC MINH]** Bật/tắt cùng một tính năng phần cứng với `SetDCHU_Data(121, 45, val)` nhưng theo nhánh giao thức mới (`field_0x04000080 != 0`). (**[CHƯA BIẾT]** tên tính năng cụ thể). |
| `cmd = 4`, `inBuf[0] = 30` (`0x1E`) | `0x06000215 () -> void` trong `Type 0x02000052` | `IL_0022` | Truyền `inBuf[0]=30`. Đọc `outBuf[0]` -> đặt `ToggleButton 0x040001a7`; duyệt `outBuf[16..31]` nạp các giá trị khác 0 (`int16`) vào `Selector 0x040001aa`; duyệt `outBuf[32..47]` nạp các giá trị khác 0 vào `Selector 0x040001a8`; lấy `outBuf[1]` và `outBuf[2]` làm `SelectedValue` cho 2 Selector đó. | **[GIẢ THUYẾT]** Đọc bảng danh sách mức giới hạn công suất/xung nhịp (ví dụ PL1/PL2 hoặc TCC/cấu hình hiệu năng) và giá trị đang chọn cho 2 thanh chọn `0x040001aa`, `0x040001a8`. |
| `cmd = 4`, `inBuf[0] = 31` (`0x1F`) | `0x0600021e () -> void` trong `Type 0x02000052` | `IL_0071` | Truyền `inBuf[0]=31`, `inBuf[1]` = trạng thái `ToggleButton 0x040001a7` (`0`/`1`), `inBuf[2] = (byte)Selector_0x040001aa.SelectedValue`, `inBuf[3] = (byte)Selector_0x040001a8.SelectedValue`. | **[GIẢ THUYẾT]** Ghi cấu hình của công tắc `0x040001a7` và 2 giá trị chọn `0x040001aa`, `0x040001a8` (cặp ghi của sub-command `30`). |

---

#### Nhóm B: Mã lệnh `cmd = 13` (`0x0D`) — Gọi qua `GetDCHU_Data_Buffer` (Wrapper `0x060000cc`)

| Mã lệnh (`cmd`) | Hàm chứa lời gọi (Method Token & Type Token) | Offset IL | Tham số & Xử lý kết quả (ĐÃ XÁC MINH) | Ý nghĩa & Mức độ xác minh |
|---|---|---|---|---|
| `cmd = 13` (`0x0D`) | `0x06000059 () -> int32` trong `Type 0x02000021` | `IL_001E` | Cấp phát `byte[256]`, gọi `0x060000cc(13, ref buf[0])`, trả về **`buf[15] & 0x0F`** (4 bit thấp của byte thứ 15). Giá trị này được `0x06000054` lưu vào biến tĩnh `0x04000048`. | **[GIẢ THUYẾT]** Đọc mã định danh loại bàn phím LED / số vùng LED hoặc cấu hình phần cứng từ bảng dữ liệu EC/ACPI (được gọi ngay trong hàm khởi tạo hệ thống `0x06000054`). |

---

#### Nhóm C: Mã lệnh `cmd = 16` (`0x10`), `70` (`0x46`), `96` (`0x60`), `122` (`0x7A`) — Gọi qua `GetDCHU_Data_Integer` (Wrappers `0x060000c8`, `0x060000c9`)

- **[ĐÃ XÁC MINH]** Cả 4 mã lệnh này đều đọc một số nguyên 32-bit (`int32`) trong quá trình khởi tạo (`Type 0x02000021`) và chuyển vào hàm giải mã bitmask `0x0600005c(int32 cmd, int32 val)`.

| Mã lệnh (`cmd`) | Hàm chứa lời gọi (Method Token & Type Token) | Offset IL | Các bit được kiểm tra trong `val` (ĐÃ XÁC MINH) | Ý nghĩa & Mức độ xác minh |
|---|---|---|---|---|
| `cmd = 16` (`0x10`) | `0x06000062 (uint8[]) -> void` trong `Type 0x02000021` | `IL_0012` | Gọi `0x060000c9(16)`, truyền `(16, val)` vào `0x0600005c`. Kiểm tra **bit 23** (`(val >> 23) & 1`); nếu bằng `1` thì gán `field_0x04000081 = 1`. | **[GIẢ THUYẾT]** Đọc thanh ghi cờ trạng thái/khả năng hỗ trợ từ BIOS/EC (cùng kiểm tra bit 23 và gán `0x04000081` giống hệt `cmd = 122`). |
| `cmd = 70` (`0x46`) | `0x06000054 () -> void` trong `Type 0x02000021` | `IL_0011` | Gọi `0x060000c9(70)`, truyền `(70, val)` vào `0x0600005c`. Kiểm tra lần lượt **12 bit từ bit 0 đến bit 11** (`& 1`, `& 2`, `& 4`, `& 8`, `& 16`, `& 32`, `& 64`, `& 128`, `& 256`, `& 512`, `>> 10 & 1`, `>> 11 & 1`) để bật các cờ boolean trên đối tượng cấu hình `0x02000042` và thêm chuỗi định danh tính năng vào `ArrayList 0x04000046`. | **[ĐÃ XÁC MINH]** Đọc thanh ghi bitmask tính năng tổng thể của máy (quyết định các mô-đun giao diện/tính năng nào được hiển thị trong Control Center 3.0). |
| `cmd = 96` (`0x60`) | `0x06000062 (uint8[]) -> void` trong `Type 0x02000021` | `IL_0020` | Gọi `0x060000c9(96)`, truyền `(96, val)` vào `0x0600005c`. Kiểm tra **bit 12** (`(val >> 12) & 1` -> gán `field_0x04000082 = 1`) và **bit 13** (`(val >> 13) & 1` -> gán `field_0x04000083 = 1`). | **[GIẢ THUYẾT]** Đọc cờ hỗ trợ tính năng mở rộng (bit 12 và 13) từ BIOS/WMI. |
| `cmd = 122` (`0x7A`) | 1) `0x0600005b () -> int32` (`IL_0006`)<br>2) `0x06000062 (uint8[]) -> void` (`IL_0004`)<br>cùng trong `Type 0x02000021` | `IL_0006`, `IL_0004` | 1) Trong `0x0600005b`: gọi `0x060000c8(122, ref val)`, kiểm tra `(val & 0x800000) == 0x800000` (tức **bit 23** = `8388608`).<br>2) Trong `0x06000062`: gọi `0x060000c9(122)`, truyền `(122, val)` vào `0x0600005c`, kiểm tra **bit 23** (`(val >> 23) & 1`) -> gán `field_0x04000081 = 1`. | **[GIẢ THUYẾT]** Trong giao thức Clevo WMI (`CLEVO_GET`), `0x7A` (`122`) thường là lệnh đọc trạng thái phần cứng/EC (nhánh song song với `cmd = 121` / `0x79` là lệnh ghi). |

---

#### Nhóm D: Mã lệnh `cmd = 17` (`0x11`) — Gọi qua `GetDCHU_Data_Buffer` (Wrapper `0x060000cf`)

- **[ĐÃ XÁC MINH]** Đây là mã lệnh được gọi nhiều nhất (**20 vị trí** trên **11 lớp**). Hàm `0x060000cf(17)` trả về mảng `byte[256]`, và các hàm gọi **chỉ đọc `buf[2]` hoặc `buf[3]`**:

| Hàm chứa lời gọi (Method Token) | Lớp chứa (Type Token) | Offset IL | Byte được đọc từ `buf` (ĐÃ XÁC MINH) | Ý nghĩa & Mức độ xác minh |
|---|---|---|---|---|
| `0x0600005a () -> int32` | `Type 0x02000021` | `IL_0004` | Đọc `buf[2]` | **[GIẢ THUYẾT]** Đọc trạng thái phần cứng/chế độ hiện tại ở bước khởi tạo (`0x06000054` lưu kết quả vào `field_0x04000047`). |
| `0x06000086 () -> uint8` | `Type 0x0200002c` | `IL_0004` | Đọc `buf[2]`. Được gọi bởi `0x06000085`: nếu `ReadAppSettings(1, 2, 1)[0] == 6` và `buf[2] == 5` thì trả về `18`. | **[GIẢ THUYẾT]** Kiểm tra mã trạng thái thiết bị/chế độ (`buf[2] == 5`) kết hợp với cấu hình trong `AppSettings(1, 2, 1)`. |
| Cặp hàm trong 9 lớp UI:<br>- `0x06000115` / `0x06000116`<br>- `0x06000159` / `0x0600015a`<br>- `0x0600018e` / `0x06000197`<br>- `0x060001c3` / `0x060001c4`<br>- `0x0600025d` / `0x0600025e`<br>- `0x0600029e` / `0x0600029f`<br>- `0x060002d9` / `0x060002da`<br>- `0x06000311` / `0x06000312`<br>- `0x0600037c` / `0x0600037d` | Lần lượt thuộc 9 lớp:<br>- `Type 0x0200004a`<br>- `Type 0x0200004d`<br>- `Type 0x02000050`<br>- `Type 0x02000052`<br>- `Type 0x0200005c`<br>- `Type 0x0200005f`<br>- `Type 0x02000062`<br>- `Type 0x02000065`<br>- `Type 0x0200006b` | `IL_0004` ở tất cả 18 hàm | Ở cả 9 lớp: hàm thứ nhất luôn đọc **`buf[2]`**, hàm thứ hai luôn đọc **`buf[3]`**. | **[GIẢ THUYẾT]** Mẫu code dùng chung (copy-paste hoặc kế thừa logic) giữa 9 trang giao diện của ứng dụng để đọc 2 byte trạng thái phần cứng/EC tại offset `2` và `3` của buffer lệnh `17`. (**[CHƯA BIẾT]** ý nghĩa chính xác của `buf[2]` và `buf[3]` khi chưa dịch ngược `InsydeDCHU.dll`). |

---

#### Nhóm E: Mã lệnh `cmd = 121` (`0x79`) — Gọi qua `SetDCHU_Data` (Wrapper `0x060000ca`)

- **[ĐÃ XÁC MINH]** Tất cả **7 lời gọi** tới `SetDCHU_Data` đều đi qua wrapper `0x060000ca(int32 cmd, int32 subCmd, uint32 val)` với **`cmd = 121` (`0x79`)**, và tất cả đều nằm trong lớp **`Type 0x02000052`**.
- **[ĐÃ XÁC MINH]** Cấu trúc gói 4 byte gửi xuống `SetDCHU_Data(121, buf, 4)`:
  - `buf[0] = (byte)(val & 0xFF)`
  - `buf[1] = (byte)((val >> 8) & 0xFF)`
  - `buf[2] = (byte)((val >> 16) & 0xFF)`
  - `buf[3] = (byte)subCmd`

| Mã lệnh (`cmd` / `subCmd` ở `buf[3]`) | Hàm chứa lời gọi (Method Token & Type Token) | Offset IL | Giá trị `val` (`buf[0..2]`) & Các thao tác đi kèm (ĐÃ XÁC MINH) | Ý nghĩa & Mức độ xác minh |
|---|---|---|---|---|
| `cmd = 121` (`0x79`), `subCmd = 1` (`0x01`) | `0x06000226 (uint8 val) -> void` trong `Type 0x02000052` (được gọi bởi `0x06000225 (bool)`) | `IL_0004` | Khi tham số `bool == true`: truyền **`val = 8`** (`buf = [0x08, 0x00, 0x00, 0x01]`) và ghi `WriteAppSettings(4, 9, 1, [1])`.<br>Khi `bool == false`: truyền **`val = 0`** (`buf = [0x00, 0x00, 0x00, 0x01]`) và ghi `WriteAppSettings(4, 9, 1, [0])`. | **[GIẢ THUYẾT]** Bật/tắt một tính năng phần cứng điều khiển qua bit 3 (`val = 8 = 1 << 3`) của sub-command `0x01` trong lệnh WMI `0x79` (đồng bộ với `AppSettings(4, 9, 1)`). (**[CHƯA BIẾT]** tên tính năng cụ thể). |
| `cmd = 121` (`0x79`), `subCmd = 25` (`0x19`) | 1) `0x060001f6 () -> void` (`IL_0089`)<br>2) `0x060001fb (object, RoutedEventArgs) -> void` (`IL_0047`, `IL_0069`)<br>3) `0x0600020d (object, RoutedEventArgs) -> void` (`IL_009D`)<br>trong `Type 0x02000052` | `IL_0089`, `IL_0047`, `IL_0069`, `IL_009D` | - Tại `0x060001f6` (reset/init): gọi `SetDCHU_Data(121, subCmd=25, val=2)` (`0x02`), đồng thời ghi `0` vào `AppSettings(4, 8, 1)`, `(1, 32, 1)`, `(4, 5, 1)`.<br>- Tại `0x060001fb`: khi bật ToggleButton, ghi `AppSettings(1, 32, 1, [1])` và gọi với **`val = 130`** (`0x82 = 2 \| (1 << 7)`); khi tắt, ghi `[0]` và gọi với **`val = 2`** (`0x02`).<br>- Tại `0x0600020d`: tính **`val = 2 \| (flag_4_8 << 6) \| (flag_1_32 << 7)`** (kết hợp bit 1 cố định = `2`, bit 6 từ `AppSettings(4, 8, 1)`, bit 7 từ `AppSettings(1, 32, 1)`) rồi gọi `SetDCHU_Data(121, 25, val)`. | **[ĐÃ XÁC MINH]** Điều khiển thanh ghi phần cứng tại `subCmd = 25 (0x19)` của lệnh `121 (0x79)`, trong đó bit 1 (`0x02`) luôn bật, bit 6 (`0x40`) gắn với công tắc lưu ở `AppSettings(4, 8, 1)` và bit 7 (`0x80`) gắn với công tắc lưu ở `AppSettings(1, 32, 1)`. (**[GIẢ THUYẾT]** Trong hệ thống Clevo WMI `0x79`, sub-command `0x19` thường liên quan đến cấu hình quạt/hiệu năng hoặc tính năng EC; tuy nhiên từ IL của `ControlCenter30.exe` chưa có chuỗi rõ tên nên giữ ở mức GIẢ THUYẾT). |
| `cmd = 121` (`0x79`), `subCmd = 45` (`0x2D`) | 1) `0x06000210 (object, RoutedEventArgs) -> void` (`IL_007F`)<br>2) `0x06000211 () -> void` (`IL_007F`)<br>trong `Type 0x02000052` | `IL_007F` | Khi `field_0x04000080 == 0`: truyền **`val = 0` hoặc `1`** (lấy từ `ToggleButton 0x04000197` / `AppSettings(1, 33, 1)`), tức `buf = [0/1, 0, 0, 45]`. *(Nếu `field_0x04000080 != 0` thì chuyển sang gọi `SetDCHU_DataEx(4, [26, val, ...])`)*. | **[ĐÃ XÁC MINH]** Cặp lệnh tương đương giữa giao thức cũ (`cmd=121, subCmd=45`) và giao thức mới (`cmd=4, subCmd=26`) để bật/tắt công tắc `0x04000197`. (**[CHƯA BIẾT]** tên công tắc trên UI). |

---

### 3. Bảng tổng hợp các tham số gọi `ReadAppSettings` & `WriteAppSettings`

- **[ĐÃ XÁC MINH]** Hai hàm `ReadAppSettings(page, offset, length, ref buf[0])` (`0x060000c4`) và `WriteAppSettings(page, offset, length, ref buf[0])` (`0x060000c5`) được gọi tổng cộng **67 lần** (thông qua các wrapper `0x060000cd`, `0x060000ce` và các lời gọi trực tiếp trong `0x0200003a`, `0x02000052`). Bảng dưới đây nhóm toàn bộ theo tọa độ `(page, offset, length)`:

| `page` | `offset` | `length` | Hành động (Đọc / Ghi) & Hàm chứa lời gọi (ĐÃ XÁC MINH) | Ý nghĩa & Mức độ xác minh |
|---|---|---|---|---|
| `0` | `0` | `2` | **Đọc** tại `0x06000060` (`Type 0x02000021`). | **[GIẢ THUYẾT]** Đọc header/phiên bản vùng nhớ AppSettings. |
| `0` | `4, 5, 6, 7` | `1` (x4) | **Ghi** tại `0x06000057` (`Type 0x02000021`) các hằng số lần lượt là `1`, `7`, `0`, `0` (tương ứng phiên bản `1.07.00`?). | **[GIẢ THUYẾT]** Ghi số phiên bản cấu hình (`1.7.0.0`) vào trang 0 của AppSettings. |
| `1` | `1` | `1` | **Đọc** tại 11 hàm (`0x0600005d`, `0x06000096`, `0x06000122`, `0x06000178`, `0x060001ab`, `0x060001df`, `0x06000288`, `0x060002c3`, `0x060002e6`, `0x06000342`, `0x06000389`). | **[GIẢ THUYẾT]** Cờ trạng thái chung được đọc bởi hầu hết các trang giao diện. |
| `1` | `2` | `1` | **Đọc** tại `0x06000085` (`Type 0x0200002c`), so sánh giá trị với `6`. | **[CHƯA BIẾT]** Cờ cấu hình dùng kết hợp với `GetDCHU_Data_Buffer(17)[2]`. |
| `1` | `7` | `1` | **Ghi & Đọc lại** tại 11 hàm (`0x06000058`, `0x06000095`, `0x06000145`, `0x0600017a`, `0x060001a2`, `0x060001e1`, `0x0600028a`, `0x060002c5`, `0x060002fd`, `0x06000344`, `0x060003a6`). | **[GIẢ THUYẾT]** Lưu mã chế độ/trang hiện hành giữa các cửa sổ UI. |
| `1` | `17` | `1` | **Ghi** (`0x060000d2`) / **Đọc** (`0x060000d3`) trong `Type 0x0200003a` (0 caller). | **[CHƯA BIẾT]** |
| `1` | `18` | `4` | **Ghi** `uint32` (`0x060000d4`) / **Đọc** `int32` (`0x060000d6`) trong `Type 0x0200003a` (0 caller). | **[CHƯA BIẾT]** |
| `1` | `22` | `4` | **Ghi** `float32` (`0x060000d5`) / **Đọc** `float32` (`0x060000d7`) trong `Type 0x0200003a` (0 caller). | **[CHƯA BIẾT]** |
| `1` | `27` | `1` | **Đọc** tại `0x060001c0` (`Type 0x02000052`). | **[CHƯA BIẾT]** |
| `1` | `28` | `1` | **Đọc & Ghi** tại `0x060001f7`, `0x060001f8`, `0x060001fa`, `0x06000236` (`Type 0x02000052`). | **[CHƯA BIẾT]** |
| `1` | `30` | `1` | **Ghi** (`0x0600005e`) / **Đọc** (`0x0600005f`) trong `Type 0x02000021`. | **[CHƯA BIẾT]** |
| `1` | `32` | `1` | **Đọc & Ghi** tại `0x060001f6`, `0x060001fb`, `0x0600020d` (`Type 0x02000052`). | **[ĐÃ XÁC MINH]** Lưu trạng thái bit 7 (`0x80`) của lệnh `SetDCHU_Data(121, subCmd=25, val)`. |
| `1` | `33` | `1` | **Đọc & Ghi** tại `0x06000210`, `0x06000211` (`Type 0x02000052`). | **[ĐÃ XÁC MINH]** Lưu trạng thái công tắc truyền vào `SetDCHU_Data(121, subCmd=45, val)` / `SetDCHU_DataEx(4, [26, val])`. |
| `1` | `34` | `1` | **Đọc** tại `0x06000215` (`IL_03C6`) và **Ghi** tại `0x06000223` (`IL_008E`, `Type 0x02000052`). Trong `0x06000223`, hàm gọi `0x060000fd(double)` (hàm này gọi Win32 API `gdi32.dll!SetDeviceGammaRamp`), sau đó tính `(int)(val * 10.0 - 10.0)` và lưu vào `(1, 34, 1)`. | **[ĐÃ XÁC MINH]** Lưu mức cấu hình **Gamma / màu màn hình** (`SetDeviceGammaRamp`). |
| `1` | `35` | `1` | **Đọc** tại `0x060001f6` và **Đọc/Ghi trực tiếp P/Invoke** tại `0x06000222` (`Type 0x02000052`). | **[ĐÃ XÁC MINH]** Lưu giá trị chế độ truyền vào `SetDCHU_DataEx(4, [22, arg1])`. |
| `1` | `36` | `3` | **Ghi 3 byte** tại `0x0600021a` (`Type 0x02000052`). | **[ĐÃ XÁC MINH]** Lưu trạng thái 3 `ToggleButton` truyền vào `SetDCHU_DataEx(4, [25, b1, b2, b3])`. |
| `4` | `5` | `1` | **Đọc & Ghi** tại `0x060001f6`, `0x0600020d` (`Type 0x02000052`). | **[CHƯA BIẾT]** Cờ phụ đi kèm trong nhóm sự kiện của `0x0600020d`. |
| `4` | `8` | `1` | **Đọc & Ghi** tại `0x060001f6`, `0x0600020d` (`Type 0x02000052`). | **[ĐÃ XÁC MINH]** Lưu trạng thái bit 6 (`0x40`) của lệnh `SetDCHU_Data(121, subCmd=25, val)`. |
| `4` | `9` | `1` | **Đọc & Ghi** tại `0x060001f9`, `0x06000225` (`Type 0x02000052`). | **[ĐÃ XÁC MINH]** Lưu trạng thái bật/tắt (`1`/`0`) của lệnh `SetDCHU_Data(121, subCmd=1, val=8/0)`. |
| `6` | `253` | `1` | **Đọc** tại `0x060000d0`; **Ghi** tại `0x060000d1` và **18 hàm** trải khắp 9 lớp giao diện (`0x0600013e`, `0x06000155`, `0x06000169`, `0x0600018a`, `0x060001a3`, `0x060001bc`, `0x060001d8`, `0x0600023e`, `0x0600026d`, `0x0600029a`, `0x060002ae`, `0x060002d5`, `0x060002f6`, `0x0600030d`, `0x06000321`, `0x06000354`, `0x0600039f`, `0x060003b6`). | **[GIẢ THUYẾT]** Cờ đồng bộ/thông báo trạng thái giữa giao diện `ControlCenter30.exe` và dịch vụ/ứng dụng nền thông qua bộ nhớ chia sẻ/Registry của `InsydeDCHU.dll`. |

> **Nhận xét quan trọng từ kết quả phân tích IL (ĐÃ XÁC MINH):**
> Trong `ControlCenter30.exe`, toàn bộ các lệnh điều khiển phần cứng trực tiếp (`SetDCHU_Data` với `cmd=121` và `SetDCHU_DataEx` với `cmd=4`) chỉ tập trung ở 2 lớp: lớp khởi tạo `Type 0x02000021` và lớp cấu hình `Type 0x02000052`. 9 lớp giao diện còn lại hoàn toàn **không gọi `SetDCHU_Data` hay `SetDCHU_DataEx`**, mà chỉ đọc `GetDCHU_Data_Buffer(17)`, ghi `WriteAppSettings((1, 7, 1), (6, 253, 1))`, ghi `EventLog` và gọi `Windows.System.Launcher::LaunchUriAsync` để mở các ứng dụng/thành phần phụ hoặc giao tiếp với dịch vụ nền.

---

### 4. Kết quả kiểm kê Driver DCHU / Insyde / Clevo đang cài trên máy (CHỈ ĐỌC)

**[ĐÃ XÁC MINH]** Kết quả chạy `pnputil /enum-drivers` và `Get-CimInstance Win32_PnPSignedDriver` (lọc theo `Insyde`, `DCHU`, `Clevo`) phát hiện **2 gói driver ACPI Bridge** đang được cài đặt trên máy:

| Thuộc tính | Driver 1 (`oem3.inf`) | Driver 2 (`oem24.inf`) |
|---|---|---|
| **Published Name (trong DriverStore)** | `oem3.inf` | `oem24.inf` |
| **Original INF Name** | `acpibridge.inf` | `acpibridge1.inf` |
| **Device Name / Description** | `Acpi Bridge` | `Acpi Bridge1` |
| **Provider Name** | `Insyde` | `CLEVO` |
| **Manufacturer** | `Insyde` | `CLV` |
| **Class Name / GUID** | `System` (`{4d36e97d-e325-11ce-bfc1-08002be10318}`) | `System` (`{4d36e97d-e325-11ce-bfc1-08002be10318}`) |
| **Driver Version** | `1.0.0.7` | `1.0.40.0` |
| **Driver Date** | `09/01/2021` | `09/17/2021` |
| **Attributes** | `Universal` (DCH/DCHU) | `Declarative` (DCH/DCHU) |
| **ACPI DeviceID** | `ACPI\CLV0001\1` | `ACPI\CLV0002\1` |
| **Hardware ID** | `ACPI\VEN_CLV&DEV_0001` | `ACPI\VEN_CLV&DEV_0002` |
| **Signer Name** | Microsoft Windows Hardware Compatibility Publisher | Microsoft Windows Hardware Compatibility Publisher |

- **[GIẢ THUYẾT]** Hai thiết bị `ACPI\VEN_CLV&DEV_0001` (`acpibridge.inf` của Insyde) và `ACPI\VEN_CLV&DEV_0002` (`acpibridge1.inf` của CLEVO) chính là cầu nối kernel/ACPI ở tầng dưới mà `InsydeDCHU.dll` (hoặc dịch vụ đi kèm trong gói driver `oem3.inf` / `oem24.inf` trong `C:\Windows\System32\DriverStore\FileRepository\`) giao tiếp để thực thi các lệnh `GetDCHU_Data_*`, `SetDCHU_Data*` và `Read/WriteAppSettings`.


---

## Giai đoạn 2b: Kiểm kê Gói Store & Dịch vụ Windows, Đối chiếu Giao thức URI và Xác định Thành phần Điều khiển Thực tế

**Phạm vi & Tuân thủ quy tắc:**
- Chỉ đọc (`Get-AppxPackage`, `Get-Service` / `Get-CimInstance Win32_Service`, đọc trực tiếp `AppxManifest.xml` tại chỗ, và phân tích tĩnh bằng REA CLI).
- Không chạy bất kỳ file thực thi nào của ứng dụng, không cài đặt thêm phần mềm, không gắn công cụ vào tiến trình đang chạy, không thay đổi quyền thư mục nào, không sao chép file.

---

### 1. Danh sách các gói Microsoft Store (`Get-AppxPackage`) và Dịch vụ Windows (`Get-Service`) của CLEVO / Gigabyte / Insyde / DCHU

#### 1.1. Các gói Microsoft Store đang cài đặt trên máy (`[ĐÃ XÁC MINH]`)

| STT | Tên gói (`Name`) | Tên hiển thị (`DisplayName`) | Phiên bản (`Version`) | Đường dẫn cài đặt (`InstallLocation`) |
|---|---|---|---|---|
| 1 | `CLEVOCO.ControlCenter3.0` | Control Center 3.0 | `7.68.1.0` | `C:\Program Files\WindowsApps\CLEVOCO.ControlCenter3.0_7.68.1.0_x64__6h6z29zh29qx0` |
| 2 | `CLEVOCO.FnhotkeysandOSD` | Fn hot keys and OSD | `7.101.0.0` | `C:\Program Files\WindowsApps\CLEVOCO.FnhotkeysandOSD_7.101.0.0_x64__6h6z29zh29qx0` |
| 3 | `CLEVOCO.LedKeyboardSetting` | Led Keyboard Setting | `7.68.0.0` | `C:\Program Files\WindowsApps\CLEVOCO.LedKeyboardSetting_7.68.0.0_x64__6h6z29zh29qx0` |
| 4 | `CLEVOCO.504814C03D814` | Fan Speed Setting | `7.87.0.0` | `C:\Program Files\WindowsApps\CLEVOCO.504814C03D814_7.87.0.0_x64__6h6z29zh29qx0` |
| 5 | `CLEVOCO.Flexikey` | Flexikey | `6.17.4.0` | `C:\Program Files\WindowsApps\CLEVOCO.Flexikey_6.17.4.0_x64__6h6z29zh29qx0` |

> **Ghi chú bổ sung (`[ĐÃ XÁC MINH]`):** Trong thư mục bộ cài gốc `C:\Program Files (x86)\ControlCenter\AppInstall` (`Control Center3.0 Package v3.72`) có tổng cộng **9 gói `.appxbundle`**, gồm 5 gói đã cài ở trên và 4 gói không được cài trên máy này (`BatteryUtility` -> `CLEVOCO.BatteryPackUtility`, `CPU_OC` -> `CLEVOCO.CPUOverclocking`, `EnergySave` -> `CLEVOCO.EnergySaveUtility`, `GPUOverclocking` -> `CLEVOCO.GPUOverclocking`).

#### 1.2. Các dịch vụ Windows (`Get-Service` / `Win32_Service`) liên quan (`[ĐÃ XÁC MINH]`)

| Tên dịch vụ (`Name`) | Tên hiển thị (`DisplayName`) | Trạng thái / Khởi động | Phiên bản file | Đường dẫn thực thi (`PathName`) |
|---|---|---|---|---|
| `CCDCHUService` | Control Center Hotkey Service | `Running` / `Auto` | `1.0.0.36` | `C:\WINDOWS\System32\DriverStore\FileRepository\acpibridge1.inf_amd64_cedafa39846f03cf\DCHUService.exe` |
| `HKClipSvc` | HotKey Clipboard Service | `Running` / `Auto` | `2.1.0.6` | `C:\Program Files (x86)\ControlCenter\Driver\x64\HKClipSvc.exe` |

---

### 2. Đọc `AppxManifest.xml` tại chỗ và Đối chiếu Giao thức URI (`windows.protocol`)

- **[ĐÃ XÁC MINH]** Cả 5 file `AppxManifest.xml` trong `C:\Program Files\WindowsApps\...` đều cho phép đọc trực tiếp tại chỗ (không bị từ chối quyền). Kết quả trích xuất:

| Gói ứng dụng (`Identity Name`) | File thực thi chính (`Executable`) | Giao thức URI đăng ký (`uap:Protocol Name`) | Ràng buộc Driver / Quyền đặc biệt trong Manifest (`ĐÃ XÁC MINH`) |
|---|---|---|---|
| `CLEVOCO.ControlCenter3.0` | `ControlCenter30\ControlCenter30.exe` | **`clevocc30`** | `runFullTrust`, `unvirtualizedResources`, `Clevo.BiosDchuDriver_6h6z29zh29qx0` |
| `CLEVOCO.FnhotkeysandOSD` | `FnKey\FnKey.exe` | **`clevofnkey`** | `runFullTrust`, `unvirtualizedResources`, `Clevo.keyboardMouseFilter_6h6z29zh29qx0`, và `<uap5:DriverConstraint Name="CLEVO-acpibridge1.inf" MinVersion="1.0.40.0" MinDate="2021-09-14" />` |
| `CLEVOCO.LedKeyboardSetting` | `CC\LedKeyboardSetting.exe` | **`clevokeyboard`** | `internetClient`, `runFullTrust` |
| `CLEVOCO.504814C03D814` | `FanSpeedSetting\FanSpeedSetting.exe` | **`clevofan`** | `runFullTrust` (`ResourceGroup="CC30"`) |
| `CLEVOCO.Flexikey` | `LaunchFlexikey\LaunchFlexikey.exe` | **`clevoflexikey`** | `internetClient`, `runFullTrust` |

#### Đối chiếu với `clevocc30:` và cơ chế gọi liên ứng dụng của `ControlCenter30.exe`:
1. **[ĐÃ XÁC MINH]** `clevocc30:` là giao thức do chính **`CLEVOCO.ControlCenter3.0` (`ControlCenter30.exe`) đăng ký làm trình xử lý (handler)** để các thành phần khác (như `FnKey.exe` hoặc phím cứng Control Center) gọi mở cửa sổ chính Control Center 3.0.
2. **[ĐÃ XÁC MINH]** Khi người dùng bấm vào các mục chức năng trên giao diện `ControlCenter30.exe`, 9 lớp giao diện (`0x0200004a`, `0x0200004d`, `0x02000050`, `0x02000056`, `0x0200005c`, `0x0200005f`, `0x02000062`, `0x02000065`, `0x0200006b`) sử dụng 2 cơ chế để kích hoạt các gói UWP vệ tinh ở trên:
   - **Cơ chế 1 (Gọi trực tiếp URI scheme):** Gọi `Windows.System.Launcher::LaunchUriAsync(Uri)` tới các giao thức tương ứng của từng gói (`clevokeyboard:`, `clevofan:`, `clevoflexikey:`, `clevofnkey:`, ...).
   - **Cơ chế 2 (Ủy quyền qua EventLog cho `CCDCHUService`):** Ghi chuỗi lệnh dạng `"w_arg253^launchapp^<AppName>^<PackageFamilyName>^..."` vào Windows EventLog `PowerBiosServerLog` (nguồn `PowerBiosServerSource`). Dịch vụ `CCDCHUService` (`DCHUService.exe`, hàm `DCHUService.Service1.inlog_EntryWritten` `0x0600005f` và `LaunchAppFromCMD` `0x06000063`) bắt sự kiện này và thực thi `explorer.exe shell:appsFolder\<PackageFamilyName>!App` (ví dụ `explorer.exe shell:appsFolder\CLEVOCO.FnhotkeysandOSD_6h6z29zh29qx0!App`).

---

### 3. Xác định thành phần thực sự điều khiển Quạt, Đèn bàn phím, Chế độ hiệu năng (Kèm bằng chứng REA)

#### 3.1. Phát hiện đặc biệt từ `DCHUService.exe` (Bản .NET KHÔNG bị làm rối tên)
- **[ĐÃ XÁC MINH]** File dịch vụ `C:\WINDOWS\System32\DriverStore\FileRepository\acpibridge1.inf_amd64_cedafa39846f03cf\DCHUService.exe` (SHA-256: `f0f66063562971747430bc7001ca98a9f06c3d8038b07f8b6bb93aa1c178dff2`, MVID: `ae1d86e0-d466-4d6c-9ac8-b4b26780b4f6`, REA Evidence ID: `ev_673664ff4680b4882fc940406d74b1c1c5348aa65f07449ab4beda381717d02e`) là một assembly .NET **không bị obfuscate**.
- **[ĐÃ XÁC MINH]** Trong `DCHUService.exe`, lớp `HotkeyService.Talk2Wmi` (hàm `InitHotkey` `0x06000002` và `ExecuteWMI` `0x0600000d`) kết nối tới `root\WMI` -> `CLEVO_GET.InstanceName='ACPI\PNP0C14\0_0'` và chứa bảng `switch` ánh xạ trực tiếp **mã lệnh số (`cmd`) sang tên hàm WMI/EC gốc**:
  - **Các mã lệnh từng gặp trong `ControlCenter30.exe` (Giai đoạn 2a) nay đã có bằng chứng tên hàm trong `DCHUService.exe` (`[ĐÃ XÁC MINH]`):**
    - `cmd = 4`: Trong `Talk2Wmi.ExecuteWMI` (`IL_12D5`) ánh xạ tới **`GetCPUFANState`** *(Lưu ý: đó là khi gọi qua WMI `CLEVO_GET`; còn khi gọi qua `SetDCHU_DataEx(4, inBuf, 256, outBuf)` thì `cmd = 4` là kênh truyền gói dữ liệu mở rộng 256-byte xuống BIOS/ACPI, nên ý nghĩa từng `subCmd` `7, 8, 21, 22, 24, 25, 26, 30, 31` của `SetDCHU_DataEx(4, ...)` vẫn giữ nguyên mức xác minh như Giai đoạn 2a).*
    - `cmd = 13`: Trong `Talk2Wmi.ExecuteWMI` (`IL_1377`) ánh xạ tới **`GetVGA1tempThermalIC`** *(Lưu ý: trong `ControlCenter30.exe`, `cmd = 13` được gọi qua `GetDCHU_Data_Buffer(13)` để lấy `buf[15] & 0x0F`, nên ý nghĩa của `buf[15] & 0x0F` trong buffer 256-byte vẫn để ở mức `[CHƯA BIẾT / GIẢ THUYẾT]` cho đến khi dịch ngược `InsydeDCHU.dll`).*
    - `cmd = 16`: Trong `Talk2Wmi.ExecuteWMI` (`IL_13AD`) ánh xạ tới **`GetCPUPerformance`**.
    - `cmd = 17`: Trong `Talk2Wmi.InitHotkey` (`IL_0433`) và `ExecuteWMI` (`IL_13BF`) ánh xạ tới **`GetCPUFANControl`**.
    - `cmd = 70`: Trong `Talk2Wmi.InitHotkey` (`IL_03BE`) và `ExecuteWMI` (`IL_16E6`) ánh xạ tới **`GetAP`** (đọc bitmask các tính năng AP hỗ trợ).
    - `cmd = 96`: Trong `Talk2Wmi.ExecuteWMI` (`IL_18B2`) ánh xạ tới **`GetTP_SW`**.
    - `cmd = 121`: Trong `Talk2Wmi.ExecuteWMI` (`IL_1A7A`) ánh xạ tới **`SystemControlFunction`** (hàm điều khiển hệ thống tổng hợp; các `subCmd = 1, 25, 45` truyền ở byte thứ 4 vẫn chưa có tên chuỗi tường minh trong `DCHUService.exe` nên không gán nghĩa bừa).
    - `cmd = 122`: Trong `Talk2Wmi.InitHotkey` (`IL_008A`) và `ExecuteWMI` (`IL_1A8A`) ánh xạ tới **`BiosSpecialFeature`**.
  - **Các mã lệnh WMI khác liên quan trực tiếp đến Quạt, Đèn bàn phím, Hiệu năng trong `Talk2Wmi.ExecuteWMI` (`0x0600000d`) (`[ĐÃ XÁC MINH]`):**
    - **Quạt & Nhiệt độ:** `cmd 2` (`GetCPUtemp`), `cmd 3` (`GetCPUtempThermalIC`), `cmd 4` (`GetCPUFANState`), `cmd 12` (`GetVGA1temp`), `cmd 13` (`GetVGA1tempThermalIC`), `cmd 14` (`GetVGA2temp`), `cmd 15` (`GetVGA2tempThermalIC`), `cmd 17` (`GetCPUFANControl`), `cmd 30` (`SetCPUFANControl`), `cmd 53` (`GetCPUFANDuty`), `cmd 54` (`GetVGA1FANDuty`), `cmd 55` (`GetVGA2FANDuty`), `cmd 56` (`GetFANCount`), `cmd 97` (`GetFanStatus`), `cmd 99` (`Fan1Info`), `cmd 100` (`Fan2Info`), `cmd 104` (`SetFanDuty`), `cmd 105` (`SetFanAutoDuty`), `cmd 110` (`Fan3Info`), `cmd 111` (`Fan4Info`), `cmd 112` (`GetFan12RPM`), `cmd 113` (`GetFan34RPM`).
    - **Đèn bàn phím & LED:** `cmd 39` (`SetWhiteLedKB`), `cmd 61` (`GetWhiteLedKB`), `cmd 68` (`GetVolumeLED`), `cmd 77` (`SetColorKey`), `cmd 103` (`SetKBLED`), `cmd 108` (`SetCCDLED`).
    - **Hiệu năng:** `cmd 16` (`GetCPUPerformance`), `cmd 29` (`SetCPUPerformance`), `cmd 121` (`SystemControlFunction`), `cmd 122` (`BiosSpecialFeature`).
- **[ĐÃ XÁC MINH]** Ngoài ra, hàm `DCHUService.DCHU.DoEventWork` (`0x0600004b`) trong `DCHUService.exe` mở trực tiếp thiết bị kernel **`\\?\ACPI#CLV0001#1#{86994c74-ad43-4812-b7e7-0c420b5c5fd7}`** (driver `AcpiBridge.sys` từ `oem3.inf`) bằng `CreateFile` và gọi `DeviceIoControl` với 2 mã IOCTL:
  - `0x322404` (`3286020` thập phân — `IOCTL_ACPIBIOS_WAIT_EVENT`)
  - `0x322408` (`3286024` thập phân — `IOCTL_ACPIBIOS_GET_NOTIFY_VALUE`)

---

#### 3.2. Phân định trách nhiệm từng thành phần đối với Quạt, Đèn bàn phím, Chế độ hiệu năng

| Chức năng | Thành phần thực hiện chính (`[ĐÃ XÁC MINH]`) | Bằng chứng kỹ thuật cụ thể (`[ĐÃ XÁC MINH]`) |
|---|---|---|
| **1. Điều khiển Quạt (Fan Control)** | **Ứng dụng chính:** Gói `CLEVOCO.504814C03D814` -> **`FanSpeedSetting\FanSpeedSetting.exe`** (URI: `clevofan:`, SHA-256: `43e3e17f285039c68b3aab1ce546da8d9b5547e449b93f4afb3d185294c2c5d0`, REA Evidence ID: `ev_27da548849c3588b148558c2d5a4a666fa3ee0b35444c5f3859b000a82e8150c`).<br>**Phối hợp nền:** `FnKey\FnKey.exe` (`CLEVOCO.FnhotkeysandOSD`) và `DCHUService.exe` (`CCDCHUService`). | 1) `FanSpeedSetting.exe` khai báo P/Invoke tới **3 cụm `InsydeDCHU.dll`** (`0x06000050`..`0x06000055`, `0x06000184`..`0x06000188`, `0x0600021d`..`0x06000221` gồm `GetDCHU_Data_Integer`, `SetDCHU_Data`, `SetDCHU_DataEx`, `GetDCHU_Data_Buffer`, `ReadAppSettings`, `WriteAppSettings`), `DataAddress.dll!DataAddress` (`0x0600010a`), `kernel32.dll!CreateFile/DeviceIoControl`, và **43 hàm của `NVGPU_DLL.dll`** (`0x060001f0`..`0x0600021a`, gồm `Get_GPU_Temp`, `CheckGPU_Thermal`, `Get_GPU_defaultMaxTemp`, ...).<br>2) File `FanSpeedSetting\oem.ini` chứa cấu hình quạt: `SupportXTUFanTable=1`, `FanMode=Default ;0:Auto 1:Max 3:Silent 5:MAXQ 6:Custom`, `SupportFanSpeedOffset=1`. |
| **2. Điều khiển Đèn bàn phím (Keyboard LED)** | **Ứng dụng chính:** Gói `CLEVOCO.LedKeyboardSetting` -> **`CC\LedKeyboardSetting.exe`** (URI: `clevokeyboard:`, SHA-256: `2b50e58e64ac30c4aca16be554665c539c31a3ff9312c51815e3f24194211570`, REA Evidence ID: `ev_8078598e5c659e672d53b5fd6d4430bfeb3e7c3779fcf30d06340bad8b6aaf94`).<br>**Phối hợp Per-key / Macro / Hotkey:**<br>- `CLEVOCO.Flexikey` (`LaunchFlexikey\CC.exe`, URI `clevoflexikey:`)<br>- `CLEVOCO.FnhotkeysandOSD` (`FnKey\FnKey.exe`, URI `clevofnkey:`) | 1) `LedKeyboardSetting.exe` P/Invoke trực tiếp:<br>- **`InsydeDCHU.dll`** (`0x06000064`..`0x06000069`, `0x0600022e`..`0x0600022f`)<br>- **`perkey_api.dll`**: `InitPerkeyIo`, `SetLEDStatus`, `GetLedData` (`0x060000c9`..`0x060000cb` và `0x06000290`..`0x06000292`)<br>- **`LineLEDAPI.dll`**: `InitLineLEDIo`, `SetLightBarData62` (`0x06000230`..`0x06000231`)<br>- **`DataAddress.dll`**: `DataAddress` (`0x0600014f`).<br>2) `FnKey.exe` (REA Evidence ID: `ev_1c6bc314ae6790a10b497943c7691f0d98397aee0afed7e03e9c12cccf459499`) P/Invoke `\Device_HID\perkey\HID_Device.dll` (`Init_HIDdevice`, `WriteData`, `ReadData` tại `0x0600060d`..`0x0600060f`) và `InsydeDCHU.dll` để xử lý phím tắt `Fn` tăng/giảm/đổi màu LED bàn phím. |
| **3. Điều khiển Chế độ hiệu năng (Performance / Power Mode)** | **Phối hợp giữa 3 thành phần:**<br>1) **`ControlCenter30\ControlCenter30.exe`** (`CLEVOCO.ControlCenter3.0`, lớp `Type 0x02000052`)<br>2) **`FnKey\FnKey.exe` + `FnKey\powerlife.dll`** (`CLEVOCO.FnhotkeysandOSD`)<br>3) **`FanSpeedSetting\FanSpeedSetting.exe`** (`CLEVOCO.504814C03D814`) + **`DCHUService.exe`** (`CCDCHUService`) | 1) Trong `ControlCenter30.exe`, lớp `Type 0x02000052` là lớp giao diện duy nhất gọi trực tiếp `SetDCHU_Data(121, ...)` và `SetDCHU_DataEx(4, ...)`. Đồng thời trong `DCHUService.DCHU` (`0x06000035`..`0x06000047`), các hàm không bị làm rối tên (`Get/SetPowerLimit1CurrentValue`, `Get/SetPowerLimit2CurrentValue`, `Get/SetPowerLimitTimeCurrentValue`, `Get/SetCoreRatio`, `Get/SetCoreVoltage`, `Get/SetGraphicsVoltage`) đọc/ghi cấu hình giới hạn điện năng CPU (PL1/PL2) và xung nhịp qua `Read/WriteAppSettings` ở `page = 6` (`offset = 32, 33, 37, 41, 49, 53..60, 61, 65, 69, 73..76`).<br>2) `FnKey.exe` P/Invoke trực tiếp **`powrprof.dll`** (`PowerEnumerate`, `PowerGetActiveScheme`, `PowerWriteACValueIndex`, `PowerWriteDCValueIndex`, `PowerSetActiveScheme` tại `0x060002b3`, `0x060005a3`..`0x060005a8`) và **`powerlife.dll`** (export `CreatePowerPlan`, `DeletePowerPlan`, `DeletePowerPlan_Performance`, `SetActivePowerPlan`, `SetPROCESSOR_PROCTHROTTLE`, REA Evidence ID: `ev_8e8e6da4e1aa2c91ce39923c12043b7b8c68d34a87c41dbddec31288c3e72c66`) cùng `InsydeDCHU.dll` (`0x060001f8`..`0x060001fc`, `0x06000748`..`0x0600074d`).<br>3) `FanSpeedSetting\oem.ini` định nghĩa 4 chế độ tình huống/hiệu năng: `SituationalMode=3 ;0:Quiet 1:power saving 2:performance 3:Entertainment` và `FanSpeedSetting.exe` gọi `NVGPU_DLL.dll` (`Set_GPU_OVERCLOCK`, `Set_CoreOC`, `Set_MEMOC`) để điều chỉnh xung GPU theo chế độ. |


---

## Giai đoạn 2c: Sao chép 4 Gói UWP + Thư mục DCHUService và Bảng Ánh xạ Đầy đủ Mã lệnh `cmd` -> WMI trong `DCHUService.exe`

**Thời gian thực hiện**: 2026-04-20
**Phương pháp**:
- Sao chép chỉ-đọc (`Copy-Item -Recurse -Force`) 4 gói UWP và thư mục driver/service chứa `DCHUService.exe` vào `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\`.
- Phân tích tĩnh metadata và IL bytecode của `DCHUService.exe` bằng REA (`inspect_managed_artifact`, `inspect_managed_members`, `inspect_managed_native_boundaries`, và giải mã toàn bộ bảng nhảy `switch` trong `HotkeyService.Talk2Wmi::ExecuteWMI`, `InitHotkey`, `ExecuteAutoColorWmi`, `DCHUService.Service1::inlog_EntryWritten`, cùng các hàm bọc `DCHUService.DCHU`).
- **Evidence IDs (REA)**:
  - `DCHUService.exe` boundaries: `ev_ddd4ea87131a4547b76e09374e694a53cd450d0010574752c4616c02d0c8bc29`
  - `DCHUService.exe` members: `ev_673664ff4680b4882fc940406d74b1c1c5348aa65f07449ab4beda381717d02e`
- **Tuân thủ quy tắc**: Không thực thi bất kỳ file nào trong thư mục ứng dụng/service, không cài đặt phần mềm, không thay đổi quyền (ACL) thư mục nguồn hay đích.

---

### 1. Kết quả sao chép 4 gói UWP và thư mục `DCHUService` vào `src\installed\`

> **[ĐÃ XÁC MINH]** Toàn bộ 5 thư mục đã được sao chép nguyên vẹn (chỉ đọc từ nguồn) vào `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\` mà không gặp bất kỳ lỗi từ chối quyền (`Access Denied`) nào:

| STT | Tên thư mục đích trong `src\installed\` | Đường dẫn nguồn (chỉ đọc) | Đường dẫn đích | Số lượng file | Trạng thái |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `FnhotkeysandOSD` | `C:\Program Files\WindowsApps\CLEVOCO.FnhotkeysandOSD_7.101.0.0_x64__6h6z29zh29qx0` | `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\FnhotkeysandOSD` | **416** | **[ĐÃ XÁC MINH]** |
| 2 | `LedKeyboardSetting` | `C:\Program Files\WindowsApps\CLEVOCO.LedKeyboardSetting_7.68.0.0_x64__6h6z29zh29qx0` | `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\LedKeyboardSetting` | **19** | **[ĐÃ XÁC MINH]** |
| 3 | `504814C03D814` *(Fan Control)* | `C:\Program Files\WindowsApps\CLEVOCO.504814C03D814_7.87.0.0_x64__6h6z29zh29qx0` | `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\504814C03D814` | **18** | **[ĐÃ XÁC MINH]** |
| 4 | `Flexikey` | `C:\Program Files\WindowsApps\CLEVOCO.Flexikey_6.17.4.0_x64__6h6z29zh29qx0` | `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\Flexikey` | **71** | **[ĐÃ XÁC MINH]** |
| 5 | `DCHUService` | `C:\WINDOWS\System32\DriverStore\FileRepository\acpibridge1.inf_amd64_cedafa39846f03cf` | `D:\03_Videcoding\REA-ControlCenterGiGaByte-LinuxNoBara\src\installed\DCHUService` | **15** | **[ĐÃ XÁC MINH]** |

---

### 2. Kiến trúc thực thi WMI trong `DCHUService.exe`

> **[ĐÃ XÁC MINH]** (`DCHUService.exe`, Version `1.0.0.36`, SHA-256 `f0f66063562971747430bc7001ca98a9f06c3d8038b07f8b6bb93aa1c178dff2`, MVID `ae1d86e0-d466-4d6c-9ac8-b4b26780b4f6`):

1. **Đối tượng WMI mục tiêu (`HotkeyService.Talk2Wmi`, `TypeDef 0x02000002`)**:
   - Trong constructor `Talk2Wmi..ctor(EventLog)` (`0x06000001`), `DCHUService.exe` khởi tạo `ManagementObject` (`field classInstance`, `0x04000001`) kết nối vào:
     - **WMI Namespace**: `"root\\WMI"`
     - **WMI Object Path**: `"CLEVO_GET.InstanceName='ACPI\\PNP0C14\\0_0'"`
   - Trong `Talk2Wmi.WatchWMI()` (`0x0600000a`), dịch vụ đăng ký `ManagementEventWatcher` (`field watcher`, `0x04000002`) tại `"root\\WMI"` với truy vấn `"SELECT * FROM CLEVO_EVENT"` (xử lý sự kiện phím nóng/EC trong `Talk2Wmi.HandleEvent` `0x06000007`), đồng thời theo dõi `"Win32_PowerManagementEvent"` và `"Win32_ComputerShutdownEvent"` tại `"root\\CIMV2"`.

2. **5 cơ chế gọi hàm WMI trong `HotkeyService.Talk2Wmi` (`ĐÃ XÁC MINH` từ IL bytecode)**:
   - **`ExecMethod(string strNumber, string strMethodName) -> bool` (`0x06000010`) — Đọc WMI (0 tham số đầu vào)**:
     - Gọi `this.classInstance.InvokeMethod(strMethodName, null, null)`.
     - Đọc giá trị trả về từ `outParams["Data"].ToString()`, lưu vào trường `this._strGetData` (`0x0400000a`).
     - Ghi vào Windows EventLog `outlog` (`PowerBiosSystemLog`) chuỗi `"s^r_arg" + strNumber + "^" + outParams["Data"]`.
   - **`ExecMethod2(RegistryKey regKey, string strNumber, string strMethodName) -> string` (`0x06000011`) — Đọc WMI khi khởi tạo và lưu Registry**:
     - Gọi `this.classInstance.InvokeMethod(strMethodName, null, null)` (0 tham số đầu vào).
     - Đọc `outParams["Data"].ToString()`, ghi vào `HKLM\SOFTWARE\ControlCenterAP` với tên giá trị là `strNumber` (`regKey.SetValue(strNumber, text)`), và trả về chuỗi kết quả (`"0"` nếu có ngoại lệ).
   - **`InvokeMethod(string strNumber, string strData, string strMethodName) -> bool` (`0x0600000e`) — Ghi WMI (1 tham số đầu vào kiểu `UInt32`)**:
     - Chuyển `strData` sang số nguyên không dấu 32-bit: `uint num = Convert.ToUInt32(strData);`.
     - Lấy bộ tham số đầu vào `ManagementBaseObject inParams = this.classInstance.GetMethodParameters(strMethodName);`.
     - Gán **`inParams["Data"] = (uint32)num`** (`box System.UInt32`), sau đó gọi `this.classInstance.InvokeMethod(strMethodName, inParams, null)`.
     - Ghi vào EventLog `outlog` (`PowerBiosSystemLog`) chuỗi `"s^w_arg" + strNumber + "^" + strData`.
   - **`InvokeMethod2(string strNumber, string strData, string strMethodName) -> bool` (`0x0600000f`) — Ghi WMI không ghi log `s^w_arg`**:
     - Giống hệt `InvokeMethod` (`inParams["Data"] = Convert.ToUInt32(strData)`), nhưng **không** ghi `"s^w_arg..."` ra `outlog`. Chỉ được gọi bởi `ExecuteAutoColorWmi(string strNumber, string strData)` (`0x0600000c`) cho mã lệnh `103` (`"SetKBLED"`).
   - **Đọc khối 256 byte qua `"Package1"` trong `InitHotkey()` (`0x06000002`, `IL_00A0`..`IL_03B5`)**:
     - Khi khởi tạo, `InitHotkey()` gọi `ExecMethod2(regKey, "122", "BiosSpecialFeature")` và ép kiểu sang `int32` (`loc6`).
     - **Nhánh 1 (`(loc6 & 0x20000000) == 0x20000000`, bit 29 bật)**: Khởi tạo mảng `byte[255] loc10` (bật các bit tại chỉ số `0, 1, 2, 7, 8, 10, 14, 15`), gán `inParams["Bytes"] = (byte[])loc10`, gọi WMI method **`"Package1"`** (`IL_01BE`), đọc `((ManagementBaseObject)outParams["Data"]).GetPropertyValue("bytes")` kiểu `byte[256]` vào `this.numbers` (`0x0400000c`), lưu mảng `"Package1"` vào Registry `HKLM\SOFTWARE\ControlCenterAP`, rồi trích xuất 10 mã lệnh (`"122"`, `"17"`, `"6"`, `"68"`, `"70"`, `"82"`, `"61"`, `"84"`, `"9"`, `"119"`) từ mảng `this.numbers` bằng `ConvertArrayToData(int32 index, int32 length) -> ulong` (`0x06000003`).
     - **Nhánh 2 (`(loc6 & 0x20000000) == 0`, bit 29 tắt, `IL_03BA`..`IL_04D5`)**: Gọi trực tiếp `ExecMethod2` cho từng hàm WMI riêng lẻ (`"70"`, `"82"`, `"6"`, `"9"`, `"17"`, `"61"`, `"119"`, `"68"`, `"84"`).

3. **Các kênh tiếp nhận sự kiện và luồng gọi đến `ExecuteWMI` (`ĐÃ XÁC MINH`)**:
   - **Kênh sự kiện WMI `CLEVO_EVENT` & đính chính sai lệch**:
     - *Đính chính*: Thông tin trước đây gán cho `DCHUService.Service1::ManagementEventWatcher_EventArrived` với token `0x06000073` là sai (token `0x06000073` trong `Service1` thực chất là phương thức WinForms sinh tự động `InitializeComponent`).
     - *Kiến trúc xác minh chuẩn xác*: Sự kiện WMI `CLEVO_EVENT` được xử lý thông qua `HotkeyService.Talk2Wmi::watcher_EventArrived` (`0x0600000b`) -> chuyển tiếp vào `HotkeyService.Talk2Wmi::HandleEvent` (`0x06000007`) để điều phối và xử lý sự kiện phím nóng/EC.
   - **Kênh sự kiện ACPI phần cứng (Driver Kernel DeviceIoControl)**:
     - Được xử lý trong luồng worker `DCHUService.DCHU::DoEventWork` (`0x0600004b`).
     - Mở thiết bị phần cứng ACPI `\\?\ACPI#CLV0001#1#{86994c74-ad43-4812-b7e7-0c420b5c5fd7}` bằng Win32 `CreateFile` (`0x06000023`).
     - Gửi `DeviceIoControl` định kỳ với 2 mã IOCTL chuyên dụng:
       - IOCTL **`3286020`** (`0x322404` — `IOCTL_ACPIBIOS_WAIT_EVENT`) tại `IL_008F`: Chờ driver ACPI báo có sự kiện mới.
       - IOCTL **`3286024`** (`0x322408` — `IOCTL_ACPIBIOS_GET_NOTIFY_VALUE`) tại `IL_00E4`: Lấy giá trị notify sự kiện phần cứng trả về.
   - **Đường EventLog (`DCHUService.Service1::inlog_EntryWritten`, `0x0600005f`)**:
     - Lắng nghe Windows EventLog `PowerBiosServerLog`. Khi nhận bản tin dạng `"c^w_arg<cmd>^<data>"` hoặc `"c^r_arg<cmd>^<data>"`:
       - Nếu `<cmd>` là `"255"`, `"254"`, `"253"`, `"252"`: xử lý khởi chạy tiến trình tại `inlog_EntryWritten` (`IL_0043`..`IL_02CC`).
       - Nếu `<cmd> == "103"` và tiền tố là `"c^s_arg"`: gọi `this.wmi.ExecuteAutoColorWmi(cmd, data)` (`IL_02FF`).
       - Các trường hợp còn lại: gọi `this.wmi.ExecuteWMI(cmd, data)` (`IL_02DF`).

---

### 3. Bảng ánh xạ đầy đủ Mã lệnh `cmd` -> Tên hàm WMI, Kiểu tham số và Nơi gọi trong `DCHUService.exe`

> **[ĐÃ XÁC MINH]** Bảng dưới đây liệt kê **toàn bộ 117 nhánh mã lệnh (`cmd`)** có mặt trong câu lệnh `switch` của `HotkeyService.Talk2Wmi::ExecuteWMI(string strNumber, string strData)` (`0x0600000d`, từ `IL_0023` đến `IL_1AC8`), đối chiếu với `Talk2Wmi::InitHotkey()` (`0x06000002`), `Talk2Wmi::ExecuteAutoColorWmi()` (`0x0600000c`), và `DCHUService.Service1::inlog_EntryWritten()` (`0x0600005f`). Không có bất kỳ suy đoán nào ngoài bằng chứng IL:

| Mã `cmd` (Thập phân / Hex) | Tên hàm WMI (`root\WMI` -> `CLEVO_GET`) hoặc Hành động nội bộ | Cơ chế gọi & Kiểu tham số WMI | Nơi gọi trong `DCHUService.exe` (Method, Token, IL Offset) | Đối chiếu nơi gọi từ các gói App (nếu đã có bằng chứng) | Trạng thái |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`0`** (`0x00`) | *(Không gọi hàm `CLEVO_GET`)* — Gọi `this.WatchWMI()` để đăng ký `ManagementEventWatcher` (`SELECT * FROM CLEVO_EVENT`, `Win32_PowerManagementEvent`, `Win32_ComputerShutdownEvent`) | Nội bộ: 0 tham số WMI (`strData` không dùng) | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"0"` @ `IL_1299`) | — | **[ĐÃ XÁC MINH]** |
| **`1`** (`0x01`) | *(Không gọi hàm `CLEVO_GET`)* — Gọi `this.StopWatchWmi()` (`watcher.Stop()`) | Nội bộ: 0 tham số WMI (`strData` không dùng) | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"1"` @ `IL_12A5`) | — | **[ĐÃ XÁC MINH]** |
| **`2`** (`0x02`) | **`GetCPUtemp`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"2"` @ `IL_12B1`) | — | **[ĐÃ XÁC MINH]** |
| **`3`** (`0x03`) | **`GetCPUtempThermalIC`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"3"` @ `IL_12C3`) | — | **[ĐÃ XÁC MINH]** |
| **`4`** (`0x04`) | **`GetCPUFANState`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"4"` @ `IL_12D5`) | — | **[ĐÃ XÁC MINH]** |
| **`5`** (`0x05`) | **`GetRadioStateForWirless`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"5"` @ `IL_12E7`) | — | **[ĐÃ XÁC MINH]** |
| **`6`** (`0x06`) | **`GetPowerStateForCamera`** *(hoặc trích byte tại `offset=37, len=1` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"6"` @ `IL_12F9`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_023F`, `ExecMethod2` @ `IL_040D`) | `ControlCenter30.exe` (`#vQb.#d8b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`7`** (`0x07`) | **`GetPowerStateForBluetooth`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"7"` @ `IL_130B`) | — | **[ĐÃ XÁC MINH]** |
| **`8`** (`0x08`) | **`GetSRSState`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"8"` @ `IL_131D`) | — | **[ĐÃ XÁC MINH]** |
| **`9`** (`0x09`) | **`GetTouchPadState`** *(hoặc trích byte tại `offset=40, len=1` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"9"` @ `IL_132F`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02EC`, `ExecMethod2` @ `IL_0420`) | `ControlCenter30.exe` (`#vQb.#e8b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`10`** (`0x0A`) | **`GetPowerStateFor3G`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"10"` @ `IL_1341`) | — | **[ĐÃ XÁC MINH]** |
| **`11`** (`0x0B`) | **`GetPowerStateForODD`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"11"` @ `IL_1353`) | — | **[ĐÃ XÁC MINH]** |
| **`12`** (`0x0C`) | **`GetVGA1temp`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"12"` @ `IL_1365`) | — | **[ĐÃ XÁC MINH]** |
| **`13`** (`0x0D`) | **`GetVGA1tempThermalIC`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"13"` @ `IL_1377`) | — | **[ĐÃ XÁC MINH]** |
| **`14`** (`0x0E`) | **`GetVGA2temp`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"14"` @ `IL_1389`) | — | **[ĐÃ XÁC MINH]** |
| **`15`** (`0x0F`) | **`GetVGA2tempThermalIC`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"15"` @ `IL_139B`) | — | **[ĐÃ XÁC MINH]** |
| **`16`** (`0x10`) | **`GetCPUPerformance`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"16"` @ `IL_13AD`) | — | **[ĐÃ XÁC MINH]** |
| **`17`** (`0x11`) | **`GetCPUFANControl`** *(hoặc trích byte tại `offset=48, len=1` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"17"` @ `IL_13BF`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0223`, `ExecMethod2` @ `IL_0433`) | `ControlCenter30.exe` (`#vQb.#b9b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`18`** (`0x12`) | **`GetLCDAutoDimmer`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"18"` @ `IL_13D1`) | — | **[ĐÃ XÁC MINH]** |
| **`19`** (`0x13`) | **`SetAirplaneOsd`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"19"` @ `IL_13E3`) | — | **[ĐÃ XÁC MINH]** |
| **`21`** (`0x15`) | **`SetTenKey`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"21"` @ `IL_13F6`) | — | **[ĐÃ XÁC MINH]** |
| **`26`** (`0x1A`) | **`ResetUsbHub`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"26"` @ `IL_1409`) | — | **[ĐÃ XÁC MINH]** |
| **`27`** (`0x1B`) | **`SetEmailLEDOFF`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"27"` @ `IL_141C`) | — | **[ĐÃ XÁC MINH]** |
| **`28`** (`0x1C`) | **`SetEmailLEDON`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"28"` @ `IL_142F`) | — | **[ĐÃ XÁC MINH]** |
| **`29`** (`0x1D`) | **`SetCPUPerformance`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"29"` @ `IL_1442`) | — | **[ĐÃ XÁC MINH]** |
| **`30`** (`0x1E`) | **`SetCPUFANControl`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"30"` @ `IL_1455`) | — | **[ĐÃ XÁC MINH]** |
| **`31`** (`0x1F`) | **`SetLCDAutoDimmer`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"31"` @ `IL_1468`) | — | **[ĐÃ XÁC MINH]** |
| **`32`** (`0x20`) | **`SetWLan`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"32"` @ `IL_147B`) | — | **[ĐÃ XÁC MINH]** |
| **`33`** (`0x21`) | **`SetBT`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"33"` @ `IL_148E`) | — | **[ĐÃ XÁC MINH]** |
| **`34`** (`0x22`) | **`SetCamera`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"34"` @ `IL_14A1`) | `ControlCenter30.exe` (`#vQb.#38b` @ `IL_010D`) | **[ĐÃ XÁC MINH]** |
| **`38`** (`0x26`) | **`SetGPIO12`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"38"` @ `IL_14B4`) | — | **[ĐÃ XÁC MINH]** |
| **`39`** (`0x27`) | **`SetWhiteLedKB`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"39"` @ `IL_14C7`) | `ControlCenter30.exe` (`#vQb.#h9b` @ `IL_00EA`) | **[ĐÃ XÁC MINH]** |
| **`40`** (`0x28`) | **`SetYearMonth`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"40"` @ `IL_14DA`) | — | **[ĐÃ XÁC MINH]** |
| **`41`** (`0x29`) | **`SetDayHour`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"41"` @ `IL_14ED`) | — | **[ĐÃ XÁC MINH]** |
| **`42`** (`0x2A`) | **`SetTP`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"42"` @ `IL_1500`) | `ControlCenter30.exe` (`#vQb.#28b` @ `IL_0157`) | **[ĐÃ XÁC MINH]** |
| **`43`** (`0x2B`) | **`SetupRotationdegree`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"43"` @ `IL_1513`) | — | **[ĐÃ XÁC MINH]** |
| **`44`** (`0x2C`) | **`ReturnHDTemp`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"44"` @ `IL_1526`) | — | **[ĐÃ XÁC MINH]** |
| **`45`** (`0x2D`) | **`ReturnPopupMode`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"45"` @ `IL_1539`) | — | **[ĐÃ XÁC MINH]** |
| **`46`** (`0x2E`) | **`SetRFID`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"46"` @ `IL_154C`) | — | **[ĐÃ XÁC MINH]** |
| **`47`** (`0x2F`) | **`SetGPS`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"47"` @ `IL_155F`) | — | **[ĐÃ XÁC MINH]** |
| **`48`** (`0x30`) | **`SetBarCode`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"48"` @ `IL_1572`) | — | **[ĐÃ XÁC MINH]** |
| **`49`** (`0x31`) | **`SetVolumeLED`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"49"` @ `IL_1585`) | — | **[ĐÃ XÁC MINH]** |
| **`50`** (`0x32`) | **`GetBatteryDesignCpacity`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"50"` @ `IL_1598`) | — | **[ĐÃ XÁC MINH]** |
| **`51`** (`0x33`) | **`GetBatteryAverageTimeToFullCharge`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"51"` @ `IL_15AA`) | — | **[ĐÃ XÁC MINH]** |
| **`52`** (`0x34`) | **`GetBatteryAverageTimeToEmpty`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"52"` @ `IL_15BC`) | — | **[ĐÃ XÁC MINH]** |
| **`53`** (`0x35`) | **`GetCPUFANDuty`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"53"` @ `IL_15CE`) | — | **[ĐÃ XÁC MINH]** |
| **`54`** (`0x36`) | **`GetVGA1FANDuty`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"54"` @ `IL_15E0`) | — | **[ĐÃ XÁC MINH]** |
| **`55`** (`0x37`) | **`GetVGA2FANDuty`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"55"` @ `IL_15F2`) | — | **[ĐÃ XÁC MINH]** |
| **`56`** (`0x38`) | **`GetFANCount`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"56"` @ `IL_1604`) | — | **[ĐÃ XÁC MINH]** |
| **`57`** (`0x39`) | *(Nhánh rỗng / No-op trong `ExecuteWMI`: nhảy thẳng tới `IL_1AC2`)* | Không gọi WMI | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"57"` @ `IL_1616`) | — | **[ĐÃ XÁC MINH]** |
| **`58`** (`0x3A`) | *(Nhánh rỗng / No-op trong `ExecuteWMI`: nhảy thẳng tới `IL_1AC2`)* | Không gọi WMI | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"58"` @ `IL_161B`) | — | **[ĐÃ XÁC MINH]** |
| **`59`** (`0x3B`) | **`GetLCDResolution`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"59"` @ `IL_1620`) | — | **[ĐÃ XÁC MINH]** |
| **`60`** (`0x3C`) | **`GetHDMIport`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"60"` @ `IL_1632`) | — | **[ĐÃ XÁC MINH]** |
| **`61`** (`0x3D`) | **`GetWhiteLedKB`** *(hoặc trích byte tại `offset=98, len=1` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"61"` @ `IL_1644`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02B3`, `ExecMethod2` @ `IL_045A`) | `ControlCenter30.exe` (`#vQb.#f8b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`62`** (`0x3E`) | **`GetGSensorMode`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"62"` @ `IL_1656`) | — | **[ĐÃ XÁC MINH]** |
| **`63`** (`0x3F`) | **`GetHDPollingTime`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"63"` @ `IL_1668`) | — | **[ĐÃ XÁC MINH]** |
| **`64`** (`0x40`) | **`GetRFID`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"64"` @ `IL_167A`) | — | **[ĐÃ XÁC MINH]** |
| **`65`** (`0x41`) | **`GetGPS`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"65"` @ `IL_168C`) | — | **[ĐÃ XÁC MINH]** |
| **`66`** (`0x42`) | **`GetBarCode`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"66"` @ `IL_169E`) | — | **[ĐÃ XÁC MINH]** |
| **`67`** (`0x43`) | **`GetBIOS_SF`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"67"` @ `IL_16B0`) | `ControlCenter30.exe` (`#vQb.#g9b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`68`** (`0x44`) | **`GetVolumeLED`** *(hoặc trích byte tại `offset=106, len=1` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"68"` @ `IL_16C2`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_025B`, `ExecMethod2` @ `IL_0494`) | — | **[ĐÃ XÁC MINH]** |
| **`69`** (`0x45`) | **`GetCurrentBrightness`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"69"` @ `IL_16D4`) | — | **[ĐÃ XÁC MINH]** |
| **`70`** (`0x46`) | **`GetAP`** *(hoặc trích tại `offset=107, len=16` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"70"` @ `IL_16E6`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0278`, `ExecMethod2` @ `IL_03BE`) | `ControlCenter30.exe` (`#vQb.#d9b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`71`** (`0x47`) | **`SetFactoryMode`** | **Đọc/Gọi 0 tham số** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` *(mặc dù tên bắt đầu bằng `Set`, IL gọi `ExecMethod`)* | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"71"` @ `IL_16F8`) | — | **[ĐÃ XÁC MINH]** |
| **`72`** (`0x48`) | **`OS_S3_S4`** | **Đọc/Gọi 0 tham số** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"72"` @ `IL_170A`) | — | **[ĐÃ XÁC MINH]** |
| **`74`** (`0x4A`) | **`RapidStarMode`** | **Đọc/Gọi 0 tham số** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"74"` @ `IL_171C`) | — | **[ĐÃ XÁC MINH]** |
| **`75`** (`0x4B`) | **`SetXPBrightness`** *(Ghi xong đọc lại)* | **Ghi + Đọc kép**:<br>1. `InvokeMethod("75", strData, "SetXPBrightness")` (`inParams["Data"] = UInt32`)<br>2. `ExecMethod("75", "SetXPBrightness")` (0 tham số vào) | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"75"` @ `IL_172E`..`IL_173D`) | — | **[ĐÃ XÁC MINH]** |
| **`76`** (`0x4C`) | **`Set3G`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"76"` @ `IL_174E`) | — | **[ĐÃ XÁC MINH]** |
| **`77`** (`0x4D`) | **`SetColorKey`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"77"` @ `IL_1761`) | — | **[ĐÃ XÁC MINH]** |
| **`78`** (`0x4E`) | **`SetSensor`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"78"` @ `IL_1774`) | — | **[ĐÃ XÁC MINH]** |
| **`79`** (`0x4F`) | **`SetEnergyStar`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"79"` @ `IL_1787`) | `ControlCenter30.exe` (`#vQb.#l9b` @ `IL_0107`) | **[ĐÃ XÁC MINH]** |
| **`80`** (`0x50`) | **`GetACmA`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"80"` @ `IL_179A`) | — | **[ĐÃ XÁC MINH]** |
| **`81`** (`0x51`) | **`GetDCmAmV`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"81"` @ `IL_17AC`) | — | **[ĐÃ XÁC MINH]** |
| **`82`** (`0x52`) | **`BIOS_special_feature_list`** *(hoặc trích tại `offset=138, len=16` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"82"` @ `IL_17BE`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0296`, `ExecMethod2` @ `IL_03D2`) | `ControlCenter30.exe` (`#vQb.#e9b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`83`** (`0x53`) | **`GetLux`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"83"` @ `IL_17D0`) | — | **[ĐÃ XÁC MINH]** |
| **`84`** (`0x54`) | **`Aero`** *(hoặc trích byte tại `offset=155, len=1` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"84"` @ `IL_17E2`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_02D3`, `ExecMethod2` @ `IL_04C3`) | `ControlCenter30.exe` (`#vQb.#f9b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`85`** (`0x55`) | **`SetOS`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"85"` @ `IL_17F4`) | — | **[ĐÃ XÁC MINH]** |
| **`86`** (`0x56`) | **`SetNVIDIA`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"86"` @ `IL_1807`) | — | **[ĐÃ XÁC MINH]** |
| **`87`** (`0x57`) | **`SetMuteButton`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"87"` @ `IL_181A`) | — | **[ĐÃ XÁC MINH]** |
| **`88`** (`0x58`) | **`SetDocking`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"88"` @ `IL_182D`) | — | **[ĐÃ XÁC MINH]** |
| **`89`** (`0x59`) | **`SetMenu`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"89"` @ `IL_1840`) | — | **[ĐÃ XÁC MINH]** |
| **`90`** (`0x5A`) | **`EmulatedButton`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"90"` @ `IL_1853`) | — | **[ĐÃ XÁC MINH]** |
| **`91`** (`0x5B`) | **`USB`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"91"` @ `IL_1866`) | `ControlCenter30.exe` (`#vQb.#j9b` @ `IL_0107`) | **[ĐÃ XÁC MINH]** |
| **`92`** (`0x5C`) | **`SetBrightnessLevel`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"92"` @ `IL_1879`) | — | **[ĐÃ XÁC MINH]** |
| **`93`** (`0x5D`) | **`SetBrightnessLevel`** *(cùng gọi `SetBrightnessLevel` như mã `92`)* | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"93"` @ `IL_188C`) | — | **[ĐÃ XÁC MINH]** |
| **`94`** (`0x5E`) | **`SetBacklightOff`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"94"` @ `IL_189F`) | — | **[ĐÃ XÁC MINH]** |
| **`96`** (`0x60`) | **`GetTP_SW`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"96"` @ `IL_18B2`) | — | **[ĐÃ XÁC MINH]** |
| **`97`** (`0x61`) | **`GetFanStatus`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"97"` @ `IL_18C4`) | — | **[ĐÃ XÁC MINH]** |
| **`98`** (`0x62`) | **`RapidStar`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"98"` @ `IL_18D6`) | — | **[ĐÃ XÁC MINH]** |
| **`99`** (`0x63`) | **`Fan1Info`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"99"` @ `IL_18E8`) | — | **[ĐÃ XÁC MINH]** |
| **`100`** (`0x64`) | **`Fan2Info`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"100"` @ `IL_18FA`) | — | **[ĐÃ XÁC MINH]** |
| **`103`** (`0x67`) | **`SetKBLED`** | **Ghi** (`InvokeMethod` hoặc `InvokeMethod2`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"103"` @ `IL_190C`)<br>- `Talk2Wmi::ExecuteAutoColorWmi` (`0x0600000c` @ `IL_0016` qua `InvokeMethod2`) | `ControlCenter30.exe` (`#vQb.#i9b` @ `IL_00C4`) | **[ĐÃ XÁC MINH]** |
| **`104`** (`0x68`) | **`SetFanDuty`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"104"` @ `IL_191F`) | — | **[ĐÃ XÁC MINH]** |
| **`105`** (`0x69`) | **`SetFanAutoDuty`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"105"` @ `IL_1932`) | — | **[ĐÃ XÁC MINH]** |
| **`106`** (`0x6A`) | **`SetECResumerTimer`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"106"` @ `IL_1945`) | — | **[ĐÃ XÁC MINH]** |
| **`107`** (`0x6B`) | **`SetH2RAMIndex`** + **`GetH2RAMData`** *(Ghi chỉ số H2RAM rồi đọc dữ liệu H2RAM)* | **Ghi + Đọc kép**:<br>1. `InvokeMethod("107", strData, "SetH2RAMIndex")` (`inParams["Data"] = UInt32`)<br>2. `ExecMethod("107", "GetH2RAMData")` (0 tham số vào -> trả về `Data`) | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"107"` @ `IL_1958`..`IL_1967`) | — | **[ĐÃ XÁC MINH]** |
| **`108`** (`0x6C`) | **`SetCCDLED`** *(Lưu ý: `108` trong bảng `Talk2Wmi::ExecuteWMI` là `SetCCDLED`, khác với mã `108` của `Insyde_DCHUEvent` dùng để đóng gói bản tin DCHU)* | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"108"` @ `IL_1978`) | — | **[ĐÃ XÁC MINH]** |
| **`109`** (`0x6D`) | **`AirplaneButton`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"109"` @ `IL_198B`) | — | **[ĐÃ XÁC MINH]** |
| **`110`** (`0x6E`) | **`Fan3Info`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"110"` @ `IL_199D`) | — | **[ĐÃ XÁC MINH]** |
| **`111`** (`0x6F`) | **`Fan4Info`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"111"` @ `IL_19AF`) | — | **[ĐÃ XÁC MINH]** |
| **`112`** (`0x70`) | **`GetFan12RPM`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"112"` @ `IL_19C1`) | — | **[ĐÃ XÁC MINH]** |
| **`113`** (`0x71`) | **`GetFan34RPM`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"113"` @ `IL_19D3`) | — | **[ĐÃ XÁC MINH]** |
| **`115`** (`0x73`) | **`GetH2RAMData`** | **Đọc** (`ExecMethod`): 0 tham số vào -> đọc `outParams["Data"]` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"115"` @ `IL_19E5`) | — | **[ĐÃ XÁC MINH]** |
| **`116`** (`0x74`) | **`TalkECVolume`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"116"` @ `IL_19F7`) | — | **[ĐÃ XÁC MINH]** |
| **`117`** (`0x75`) | **`SetH2RAMIndex`** + **`WritetH2RAM`** *(Tách `uint32 v = Convert.ToUInt32(strData)` thành 16 bit cao `loc1 = v >> 16` và 16 bit thấp `loc2 = v & 0xFFFF`)* | **Ghi kép 2 lần `UInt32`**:<br>1. `InvokeMethod("117", (v >> 16).ToString(), "SetH2RAMIndex")`<br>2. `InvokeMethod("117", (v & 0xFFFF).ToString(), "WritetH2RAM")` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"117"` @ `IL_1A0A`..`IL_1A39`) | — | **[ĐÃ XÁC MINH]** |
| **`118`** (`0x76`) | **`TalkECTime`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"118"` @ `IL_1A4B`) | — | **[ĐÃ XÁC MINH]** |
| **`119`** (`0x77`) | **`GetChargingStatus`** *(hoặc trích tại `offset=223, len=3` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"119"` @ `IL_1A5B`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `Package1` @ `IL_0308`, `ExecMethod2` @ `IL_0481`) | `ControlCenter30.exe` (`#vQb.#Z8b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`120`** (`0x78`) | **`TalkBIOS3G`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"120"` @ `IL_1A6A`) | — | **[ĐÃ XÁC MINH]** |
| **`121`** (`0x79`) | **`SystemControlFunction`** | **Ghi** (`InvokeMethod`): `inParams["Data"] = (uint32)Convert.ToUInt32(strData)` | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"121"` @ `IL_1A7A`) | `ControlCenter30.exe` (`#vQb.#a9b`, `#c9b`, `#k9b`, `#m9b`, `#08b`) | **[ĐÃ XÁC MINH]** |
| **`122`** (`0x7A`) | **`BiosSpecialFeature`** *(hoặc trích tại `offset=228, len=16` từ WMI **`Package1`**)* | **Đọc** (`ExecMethod` / `ExecMethod2`): 0 tham số vào -> đọc `outParams["Data"]` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"122"` @ `IL_1A8A`)<br>- `Talk2Wmi::InitHotkey` (`0x06000002`, `ExecMethod2` @ `IL_008A`, `Package1` @ `IL_0209`) | `ControlCenter30.exe` (`#vQb.#c8b` @ `IL_0055`) | **[ĐÃ XÁC MINH]** |
| **`248`** (`0xF8`) | *(Nhánh rỗng / No-op trong `ExecuteWMI`: nhảy thẳng tới `IL_1AC2`)* | Không gọi WMI | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"248"` @ `IL_1A99`) | — | **[ĐÃ XÁC MINH]** |
| **`249`** (`0xF9`) | *(Nhánh rỗng / No-op trong `ExecuteWMI`: nhảy thẳng tới `IL_1AC2`)* | Không gọi WMI | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"249"` @ `IL_1A9B`) | — | **[ĐÃ XÁC MINH]** |
| **`251`** (`0xFB`) | *(Nhánh rỗng / No-op trong `ExecuteWMI`: nhảy thẳng tới `IL_1AC2`)* | Không gọi WMI | `Talk2Wmi::ExecuteWMI` (`0x0600000d`, case `"251"` @ `IL_1A9D`) | — | **[ĐÃ XÁC MINH]** |
| **`252`** (`0xFC`) | - Trong `ExecuteWMI`: No-op (`IL_1A9F`)<br>- Trong `Service1::inlog_EntryWritten`: gọi `StartProcessAndBypassUACAsExplorerSessionId(strData)` (`0x0600006a`) | IPC qua EventLog `PowerBiosServerLog`: tham số chuỗi đường dẫn lệnh `strData` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1A9F`)<br>- `Service1::inlog_EntryWritten` (`0x0600005f` @ `IL_02BF`) | — | **[ĐÃ XÁC MINH]** |
| **`253`** (`0xFD`) | - Trong `ExecuteWMI`: No-op (`IL_1AA1`)<br>- Trong `Service1::inlog_EntryWritten`:<br>  + Nếu `strData == "launchfnkey"`: gọi `LaunchFnKeyFromCMD()` (`0x06000062`)<br>  + Nếu `strData` chứa `"launchapp^..."`: gọi `LaunchAppFromCMD(appName, pkgFamilyName, killOther, procName)` (`0x06000063`)<br>  + Ngược lại: gọi `StartProcessAndBypassUACAsExplorerSessionId(strData)` (`0x0600006a`) | IPC qua EventLog `PowerBiosServerLog`: tham số chuỗi `strData` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1AA1`)<br>- `Service1::inlog_EntryWritten` (`0x0600005f` @ `IL_00BA`..`IL_02AA`) | — | **[ĐÃ XÁC MINH]** |
| **`254`** (`0xFE`) | - Trong `ExecuteWMI`: No-op (`IL_1AA3`)<br>- Trong `Service1::inlog_EntryWritten`: gọi `StartProcessAndByPassUAC(strData)` (`0x0600006b`) | IPC qua EventLog `PowerBiosServerLog`: tham số chuỗi `strData` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1AA3`)<br>- `Service1::inlog_EntryWritten` (`0x0600005f` @ `IL_009E`) | — | **[ĐÃ XÁC MINH]** |
| **`255`** (`0xFF`) | - Trong `ExecuteWMI`: gọi `Talk2Wmi::ExecuteProcess(strData)` (`0x06000012`)<br>- Trong `Service1::inlog_EntryWritten`: gọi `Service1::ExecuteProcess(strData)` (`0x0600006d`) | Thực thi tiến trình (`Process.Start`): tham số chuỗi `strData` | - `Talk2Wmi::ExecuteWMI` (`0x0600000d` @ `IL_1AA5`)<br>- `Service1::inlog_EntryWritten` (`0x0600005f` @ `IL_0082`) | — | **[ĐÃ XÁC MINH]** |

---

### 4. Bảng các hàm bọc `ReadAppSettings` / `WriteAppSettings` trong lớp `DCHUService.DCHU` (`TypeDef 0x02000003`)

> **[ĐÃ XÁC MINH]** Ngoài bảng `ExecuteWMI` ở trên, lớp `DCHUService.DCHU` (`TypeDef 0x02000003`) trong `DCHUService.exe` định nghĩa các hàm có tên tường minh (không bị làm rối tên) gọi xuống `InsydeDCHU.dll!ReadAppSettings` và `WriteAppSettings`. Toàn bộ 19 hàm từ token `0x06000035` đến `0x06000047` đều thao tác trên **`page = 6`** (khớp chính xác với phát hiện tại dòng phân tích 420 trong mục 2b), điều khiển công suất PL1/PL2, điện áp và xung nhịp CPU/GPU:

| Tên hàm trong `DCHUService.DCHU` | Metadata Token | Hàm `InsydeDCHU.dll` được gọi | Tọa độ `(page, offset, length)` | Kiểu dữ liệu & Chuyển đổi trong IL | Trạng thái |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GetPowerLimit1CurrentValue()` | `0x06000035` | `ReadAppSettings` | `page = 6, offset = 33, length = 4` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetPowerLimitTimeValue()` | `0x06000036` | `ReadAppSettings` | `page = 6, offset = 41, length = 4` | `float32` / `Single` (`BitConverter.ToSingle(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetPowerLimit2CurrentValue()` | `0x06000037` | `ReadAppSettings` | `page = 6, offset = 37, length = 4` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetCPUVRAuto()` | `0x06000038` | `ReadAppSettings` | `page = 6, offset = 74, length = 1` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetCPUVRCurrentValue()` | `0x06000039` | `ReadAppSettings` | `page = 6, offset = 49, length = 4` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetCPUVoltageOffset()` | `0x0600003a` | `ReadAppSettings` | `page = 6, offset = 61, length = 4` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetGraphicsVoltage()` | `0x0600003b` | `ReadAppSettings` | `page = 6, offset = 69, length = 4` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetOverrideCurrentValue()` | `0x0600003c` | `ReadAppSettings` | `page = 6, offset = 65, length = 4` | `float32` / `Single` (`BitConverter.ToSingle(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetCPUCoreRatioCurrentValue(int core)` | `0x0600003d` | `ReadAppSettings` | `page = 6, offset = 53..60 (core 0..7), 75..76 (core 8..9), length = 1` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `GetCPUVoltageMode()` | `0x0600003e` | `ReadAppSettings` | `page = 6, offset = 73, length = 1` | `int32` (`BitConverter.ToInt32(buf, 0)`) | **[ĐÃ XÁC MINH]** |
| `SetCPUVoltageMode(int mode)` | `0x0600003f` | `WriteAppSettings` | `page = 6, offset = 73, length = 1` | `int32` -> `byte` (`BitConverter.GetBytes(int32)`, ghi `length = 1`) | **[ĐÃ XÁC MINH]** |
| `SetCoreRatio(int core, int ratio)` | `0x06000040` | `WriteAppSettings` | `page = 6, offset = 53..60 (core 0..7), 75..76 (core 8..9), length = 1` | `int32` -> `byte` (`BitConverter.GetBytes(int32)`, ghi `length = 1`) | **[ĐÃ XÁC MINH]** |
| `SetIsSavedFlag(int v)` | `0x06000041` | `WriteAppSettings` | `page = 6, offset = 32, length = 1` | `int32` -> `byte` (`BitConverter.GetBytes(int32)`, ghi `length = 1`) | **[ĐÃ XÁC MINH]** |
| `SetPowerLimit1CurrentValue(int PL1)` | `0x06000042` | `WriteAppSettings` | `page = 6, offset = 33, length = 4` | `int32` (`BitConverter.GetBytes(int32)`, ghi `length = 4`) | **[ĐÃ XÁC MINH]** |
| `SetPowerLimitTimeCurrentValue(float PL_Time)` | `0x06000043` | `WriteAppSettings` | `page = 6, offset = 41, length = 4` | `float32` / `Single` (`BitConverter.GetBytes(single)`, ghi `length = 4`) | **[ĐÃ XÁC MINH]** |
| `SetPowerLimit2CurrentValue(int PL2)` | `0x06000044` | `WriteAppSettings` | `page = 6, offset = 37, length = 4` | `int32` (`BitConverter.GetBytes(int32)`, ghi `length = 4`) | **[ĐÃ XÁC MINH]** |
| `SetCPUVR(int VR_Limit)` | `0x06000045` | `WriteAppSettings` | `page = 6, offset = 49, length = 4` | `int32` (`BitConverter.GetBytes(int32)`, ghi `length = 4`) | **[ĐÃ XÁC MINH]** |
| `SetCoreVoltage(int voltage)` | `0x06000046` | `WriteAppSettings` | `page = 6, offset = 61, length = 4` | `int32` (`BitConverter.GetBytes(int32)`, ghi `length = 4`) | **[ĐÃ XÁC MINH]** |
| `SetGraphicsVoltage(int voltage)` | `0x06000047` | `WriteAppSettings` | `page = 6, offset = 69, length = 4` | `int32` (`BitConverter.GetBytes(int32)`, ghi `length = 4`) | **[ĐÃ XÁC MINH]** |
