# hSignerBridge

**USB Token Signing Bridge** — cầu nối cho phép trình duyệt ký số PDF qua USB Token (ePass2003, SafeNet, VNPT-CA, Viettel-CA, YubiKey...) **hoàn toàn tại chỗ**, không upload PDF lên server.

## Tại sao cần?

Trình duyệt web (Chrome/Firefox/Edge) **không được phép truy cập trực tiếp USB Token** vì lý do bảo mật sandbox. hSignerBridge là ứng dụng nhỏ gọn chạy ngầm trên máy, làm cầu nối **localhost WebSocket** giữa trang web và Windows Smart Card KSP/CSP.

```
Trình duyệt  ◄── WebSocket wss://localhost:9505 ──►  hSignerBridge.exe  ◄──►  USB Token
```

- **PDF không rời khỏi máy** — toàn bộ xử lý client-side
- **Chỉ lắng nghe localhost** — không mở port ra internet
- **File đã code-sign** bằng chứng thư EV SSL.com
- **Không lưu PIN, không cache cert**

## Cài đặt (cho người dùng cuối)

### 1. Cài .NET 8 Desktop Runtime (~55 MB, nếu chưa có)

```powershell
winget install Microsoft.DotNet.DesktopRuntime.8
```

Hoặc tải từ: https://dotnet.microsoft.com/download/dotnet/8.0

### 2. Tải và chạy hSignerBridge.exe (~200 KB)

Tải [`hSignerBridge.exe`](./hSignerBridge.exe) và chạy. Icon Shield sẽ xuất hiện trong khay hệ thống. Ứng dụng chạy ngầm, lắng nghe cổng `9505`.

### 3. Chấp nhận SSL self-signed

Mở https://localhost:9505 trong trình duyệt → "Advanced" → "Proceed" để accept cert tự ký (chỉ cần làm 1 lần).

### 4. Cắm USB Token và dùng

Vào trang web có tích hợp plugin ký số → trang sẽ tự động kết nối bridge.

## Tích hợp (cho developer)

### Quick start

```html
<div id="pdfsign" style="width:100%;height:100vh"></div>
<script src="pdfsignclient.js"></script>
<script>
    new PdfSignClient({ container: '#pdfsign' });
</script>
```

Chỉ cần 1 file `pdfsignclient.js` (đã embed `hSignerBridge.exe` base64 — user tải exe trực tiếp từ modal hướng dẫn trong plugin).

Xem [`web/demo.html`](./web/demo.html) để biết thêm chi tiết.

### Full config

```javascript
new PdfSignClient({
    // ========== BẮT BUỘC ==========
    container: '#pdfsign',                  // selector hoặc HTMLElement

    // ========== TIÊU ĐỀ & GIAO DIỆN ==========
    title: 'hSignerBridge',                 // tiêu đề hiển thị trên header

    // ========== BRIDGE ==========
    bridgeUrl: 'wss://localhost:9505',              // default WSS
    bridgeUrlFallback: 'ws://localhost:9506',       // fallback nếu WSS fail
    bridgeDownloadUrl:                              // link tải exe trong modal hướng dẫn
        'https://github.com/haoquangviet/hSignerBridge/releases/latest/download/hSignerBridge.exe',
    bridgeHttpsUrl: 'https://localhost:9505',       // URL để user accept cert tự ký (Firefox)
    connectTimeout: 5000,                           // ms — hiện modal install nếu không kết nối trong thời gian này

    // ========== PDF NGUỒN — chọn 1 ==========
    allowFileOpen: true,                    // hiện nút "Mở PDF"
    pdfBase64: 'JVBERi0xL...',              // hoặc preload base64
    pdfBytes: new Uint8Array(...),          // hoặc Uint8Array

    // ========== OUTPUT ==========
    filename: 'document.pdf',               // → 'signed_document.pdf'
    autoDownload: true,                     // tự tải về sau khi ký

    // ========== CALLBACKS ==========
    onSigned: (blob, filename, bytes, base64) => {
        // blob    — Blob object (upload qua FormData)
        // bytes   — Uint8Array raw
        // base64  — chuỗi base64 (JSON / REST API / DB save)
    },
    onError: (err) => { /* xử lý lỗi */ },
    onClose: () => { /* nếu có → hiện nút ✕ ở header, gọi khi bấm */ },

    // ========== TUỲ BIẾN GIAO DIỆN ==========
    colors: {                               // chỉ override khoá cần đổi, còn lại dùng default
        primary: '#FF791D',     secondary: '#174785',
        success: '#348D00',     danger: '#ED542C',
        bg: '#1a1a2e',          sidebar: '#16213e',
        pdfPanel: '#2a2a3e',    text: '#e0e0e0',
        textMuted: '#8aa0c0',
    },
    sidePanelWidth: 340,                    // px — rộng side panel công cụ
    maxWidth: null,                         // null = full container; hoặc số px
    zIndex: 'auto',                         // z-index root container
    modalZIndex: 10000,                     // z-index modal (phải > zIndex)

    // ========== TUỲ BIẾN TEXT (labels) ==========
    labels: {                               // chỉ override khoá cần đổi
        // Header & status
        connecting: 'Đang kết nối...',
        connected: 'Đã kết nối',
        disconnected: 'Chưa kết nối — bấm để xem hướng dẫn',

        // Toolbar PDF
        openBtn: 'Mở PDF',
        pagesSuffix: 'trang',
        placeholderMain: 'Chọn file PDF để bắt đầu ký số',
        placeholderSub: 'Hỗ trợ ký số trực tiếp từ trình duyệt qua USB Token',

        // Tạo chữ ký
        createSigTitle: 'Tạo chữ ký',
        tabDraw: 'Vẽ',
        tabType: 'Gõ',
        tabUpload: 'Tải ảnh',
        clearBtn: 'Xóa',
        typePlaceholder: 'Nhập tên...',
        uploadText: 'Chọn ảnh chữ ký (PNG/JPG)',
        placeSigBtn: 'Đặt chữ ký lên PDF',

        // Ký số
        signTitle: 'Ký số',                 // ví dụ đổi thành 'Ký và lưu'
        signHint: 'Khi nhấn "Ký số", Windows sẽ hiện hộp thoại chọn chứng thư số và nhập PIN cho USB Token.',
        signBtn: 'Ký số & Tải về',          // ví dụ đổi thành 'Ký và lưu'
        signingDefault: 'Đang ký số...',

        // Modal chọn cert
        certPickerTitle: 'Chọn chứng thư số',
        certPickerOk: 'Ký số',
        certPickerCancel: 'Huỷ',

        // Footer
        helpBtn: 'Hướng dẫn cài đặt hSignerBridge',
    },
});
```

### API

```javascript
const client = new PdfSignClient({...});

client.loadPdfBase64('JVBERi0xLjQK...');
client.loadPdfBytes(new Uint8Array([...]));
client.sign();  // trigger ký số programmatically
```

## Tính năng

- **Plugin JS (~330 KB)** tự chứa: UI, logic, hSignerBridge.exe embed base64
- **Render PDF đa trang cuộn dọc** (không phải xem 1 trang 1 lần)
- **3 kiểu chữ ký**: vẽ tay (perfect-freehand mượt như bút mực), gõ chữ (font Caveat), tải ảnh
- **3 màu mực**: đen, xanh bút bi `#0033A0`, đỏ mực `#B91C1C`
- **Kéo thả chữ ký** lên vị trí bất kỳ, resize, giữ aspect ratio
- **Composite tự động**: ghép chữ ký + "Ký bởi: [CN]" + timestamp trước khi nhúng PDF
- **Modal chọn cert** hiển thị token type, CN, Issuer, HSD, Key algorithm
- **Modal hướng dẫn cài đặt** tự hiện khi chưa kết nối được bridge
- **Tuỳ biến màu thương hiệu** qua CSS variables

## Chuẩn chữ ký

- PKCS#7/CMS detached (Adobe PPKLite `adbe.pkcs7.detached`)
- SHA-256 digest
- RSA (PKCS#1 v1.5) hoặc ECDSA (DER-encoded `Rfc3279DerSequence`)
- ByteRange padded leading zeros (10 chữ số)
- Certificate chain đầy đủ (leaf → intermediate → root)

Adobe Reader / Foxit verify được chữ ký là **VALID**, hiển thị tên người ký và certificate chain.

## Token đã test

| Token | Provider | Key | Trạng thái |
|-------|----------|-----|------------|
| YubiKey | Microsoft Smart Card KSP | RSA / ECDSA | ✅ |
| ePass2003 | EnterSafe CSP | RSA | ✅ |
| SafeNet eToken | SafeNet CSP/KSP | RSA | ✅ |
| VNPT-CA | VNPT-CA SmartCard CSP | RSA | ✅ |
| Viettel-CA | Viettel-CA CSP | RSA | ✅ |

## Yêu cầu hệ thống

- **Máy người ký**: Windows 10/11 x64 + .NET 8 Desktop Runtime + USB Token
- **Trình duyệt**: Chrome 90+ / Edge 90+ / Firefox 95+ (hỗ trợ WebSocket, WebCrypto, File API, `getCoalescedEvents`, dynamic `import()`)

## Build từ source (optional)

File [`web/pdfsignclient.js`](./web/pdfsignclient.js) trong repo đã embed sẵn `hSignerBridge.exe` dưới dạng base64 — **sẵn sàng dùng ngay**, không cần build lại.

Chỉ build từ source nếu bạn sửa C# source hoặc muốn replace exe bằng bản tự ký:

```bash
# 1. Build exe (Windows, yêu cầu .NET 8 SDK)
dotnet publish src/hSignerBridge.csproj -c Release -r win-x64 \
    --self-contained false -p:PublishSingleFile=true -o publish-bridge

# 2. Re-inject exe mới vào plugin
cp publish-bridge/hSignerBridge.exe web/
python web/build.py
```

## License & Support

© 2026 HQV Software — haoquangviet.com

- Issues: https://github.com/HQVSoftware/hSignerBridge/issues
- Email: hqv@haoquangviet.com
