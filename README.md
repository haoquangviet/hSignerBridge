# hSignerBridge

**USB Token Signing Bridge** — cầu nối cho phép trình duyệt ký số PDF qua USB Token (ePass2003, SafeNet, VNPT-CA, Viettel-CA, YubiKey...) **hoàn toàn tại chỗ**, không upload PDF lên server.

## Tại sao cần?

Trình duyệt web (Chrome/Firefox/Edge) **không được phép truy cập trực tiếp USB Token** vì lý do bảo mật sandbox. hSignerBridge là ứng dụng nhỏ gọn chạy ngầm trên máy, làm cầu nối **localhost WebSocket** giữa trang web và Windows Smart Card KSP/CSP.

```
Trình duyệt  ◄── wss://localhost:9505 (hoặc HTTPS POST /rpc) ──►  hSignerBridge.exe  ◄──►  USB Token
```

- **PDF không rời khỏi máy** — toàn bộ xử lý client-side
- **Chỉ lắng nghe localhost** — bind 127.0.0.1 và ::1, không mở port ra internet
- **TLS tự phục vụ trong tiến trình** (`TcpListener` + `SslStream`) — không cần quyền administrator
- **File đã code-sign** bằng chứng thư EV SSL.com
- **Không lưu PIN, không cache cert**

## Cài đặt (cho người dùng cuối)

### 1. Cài .NET 8 Desktop Runtime (~55 MB, nếu chưa có)

```powershell
winget install Microsoft.DotNet.DesktopRuntime.8
```

Hoặc tải từ: https://dotnet.microsoft.com/download/dotnet/8.0

### 2. Tải và chạy hSignerBridge.exe (~200 KB)

Tải [`hSignerBridge.exe`](https://github.com/haoquangviet/hSignerBridge/releases/latest/download/hSignerBridge.exe) và chạy. Icon Shield sẽ xuất hiện trong khay hệ thống. Ứng dụng chạy ngầm, lắng nghe cổng `9505`.

### 3. Chấp nhận SSL self-signed (nếu trình duyệt hỏi)

hSignerBridge tạo Root CA riêng và import vào Trusted Root của user, nên thường không cần bước này. Nếu trình duyệt
vẫn cảnh báo, mở https://localhost:9505 → "Advanced" → "Proceed" (chỉ cần làm 1 lần).

### 3b. Chrome 141 trở lên: cho phép "Local network access"

Chrome chặn trang web truy cập ứng dụng chạy trên máy bạn cho tới khi bạn cấp quyền. Khi trang ký hỏi, chọn **Allow**;
hoặc bấm biểu tượng bên trái thanh địa chỉ → **Site settings** → **Local network access** → **Allow** → tải lại trang.
Firefox và Edge không cần bước này.

### 4. Cắm USB Token và dùng

Vào trang web có tích hợp plugin ký số → trang sẽ tự động kết nối bridge.

## Dùng qua CDN

Plugin là **một tệp JS duy nhất, không phụ thuộc thư viện ngoài** — nạp thẳng từ CDN là chạy:

```html
<div id="pdfsign"></div>
<script src="https://cdn.jsdelivr.net/gh/haoquangviet/hSignerBridge@v1.2.0/web/pdfsignclient.js"></script>
<script>
  new PdfSignClient({ container: '#pdfsign', allowFileOpen: true });
</script>
```

| CDN | URL |
|---|---|
| jsDelivr (GitHub) | `https://cdn.jsdelivr.net/gh/haoquangviet/hSignerBridge@v1.2.0/web/pdfsignclient.js` |
| jsDelivr (minify tự động) | `https://cdn.jsdelivr.net/gh/haoquangviet/hSignerBridge@v1.2.0/web/pdfsignclient.min.js` |
| jsDelivr (npm) | `https://cdn.jsdelivr.net/npm/hsignerbridge@1.2.0/web/pdfsignclient.js` |
| unpkg (npm) | `https://unpkg.com/hsignerbridge@1.2.0/web/pdfsignclient.js` |
| npm | `npm i hsignerbridge` |

**Nên ghim theo tag** (`@v1.2.0`) thay vì `@main`/`@latest`: đây là plugin ký số, tệp đổi bất ngờ là rủi ro.
Kèm SRI để trình duyệt tự kiểm tra toàn vẹn:

```html
<script src="https://cdn.jsdelivr.net/gh/haoquangviet/hSignerBridge@v1.2.0/web/pdfsignclient.js"
        integrity="sha384-vNY2fBEvxkWOd5ShUl1+esK7A5+cs2MNzF/RDf2AEhcXmCOPK9haTT1eTzp4wDUl"
        crossorigin="anonymous"></script>
```

Nếu trang có Content-Security-Policy, nhớ cho phép `script-src https://cdn.jsdelivr.net` và
`connect-src https://localhost:9505 wss://localhost:9505`.

Demo online: **https://haoquangviet.github.io/hSignerBridge/**

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

## Trình duyệt

| Trình duyệt | Kênh dùng | Ghi chú |
|---|---|---|
| Chrome / Edge 141+ | HTTPS `POST /rpc` | Chrome chặn WebSocket tới localhost (`ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`) kể cả khi đã cấp quyền, nhưng cho phép `fetch()`. Plugin tự chuyển kênh. |
| Firefox | WebSocket `wss://localhost:9505` | |
| Trang chạy `http://localhost` | WebSocket, fallback `ws://localhost:9506` | |

Bridge phục vụ **cùng một bộ lệnh** (`ping`, `list-certificates`, `sign`, `sign-cms`) trên cả hai kênh, kèm header
`Access-Control-Allow-Private-Network` / `Access-Control-Allow-Local-Network-Access` cho preflight của Chrome.

> **Lưu ý:** đặt tên miền công khai trỏ về `127.0.0.1` **không** vượt qua được chặn của Chrome — Chrome phân loại theo
> địa chỉ IP sau khi phân giải, nên vẫn thuộc "local network".

## Tính năng

**Xem & đặt chữ ký**
- **Xem PDF nhiều trang**: cuộn tất cả trang hoặc chuyển chế độ **từng trang**, nút trang trước/sau, zoom −/+/Fit, kéo để di chuyển khi zoom lớn
- **Đặt chữ ký bằng kéo-thả** lên đúng vị trí mong muốn, đổi kích thước bằng nút góc, ô mờ theo con trỏ để canh trước khi thả
- **3 kiểu chữ ký**: vẽ tay (perfect-freehand), gõ chữ (font Caveat), tải ảnh — kèm 3 màu mực
- `signatureAppearance`: chỉ ảnh chữ ký, hoặc ghép thêm "Ký bởi \[CN\]" + thời gian

**Biểu mẫu & nhiều người ký** (tuỳ chọn, cho hệ thống eSign)
- `prepareMode` + `fieldsEditable`: kéo-thả các trường **Chữ ký / Văn bản / Checkbox / Radio / Danh sách chọn** lên trang, gán cho từng người ký
- `signers`: nhiều người ký, mỗi người một màu và một bộ trường riêng
- Panel **"Cần hoàn tất"** liệt kê các trường phải điền, bấm là nhảy tới, có nút tới/lui; `autoFill` + `linkSameLabel` điền hàng loạt các trường cùng nhãn
- `lockedPosition`: khoá vị trí ô ký để người nhận không di chuyển được

**Cách ký**
- **Ký bằng USB Token** ngay trên máy (mặc định) — PDF không rời khỏi trình duyệt
- `deferred`: ký kiểu deferred (server chuẩn bị placeholder → Bridge ký CMS → server nhúng) cho luồng nhiều người ký
- `imageSign`: ký điện tử không cần token (server đóng dấu + seal), `serverSign`: gửi vị trí về server ký bằng profile

**Kết nối**
- Tự chọn kênh: `wss://localhost:9505`, hoặc **HTTPS `POST /rpc`** khi trình duyệt chặn WebSocket (Chrome 141+)
- Plugin một tệp JS, không phụ thuộc thư viện ngoài, đã nhúng sẵn hSignerBridge.exe base64
- Tuỳ biến màu thương hiệu qua CSS variables, đổi toàn bộ nhãn qua `labels`


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
