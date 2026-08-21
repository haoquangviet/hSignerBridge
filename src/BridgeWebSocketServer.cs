using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace hSignerBridge;

/// <summary>
/// WebSocket server trên wss://localhost:9505.
/// Nhận request từ trình duyệt (list-certificates, sign hash) → trả kết quả.
/// Hỗ trợ cả WSS (HTTPS) và WS (HTTP) fallback.
/// </summary>
public class BridgeWebSocketServer
{
    private readonly int _port;
    // TLS is terminated in-process (TcpListener + SslStream) instead of HttpListener/http.sys:
    // binding a certificate to http.sys needs "netsh http add sslcert", i.e. administrator rights, so for a
    // normal user wss://localhost never came up and browsers fell back to ws:// — which Chrome now refuses
    // (ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS) for a page served from a public site.
    private readonly List<TcpListener> _listeners = new();
    private CancellationTokenSource? _cts;
    private readonly Form _mainForm; // để Invoke PIN dialog trên UI thread
    private readonly ConcurrentDictionary<string, WebSocket> _clients = new();
    private X509Certificate2? _sslCert;

    public event Action<string>? OnLog;

    private static readonly string LogFile = Path.Combine(Path.GetTempPath(), "hSignerBridge.log");
    private void Log(string msg)
    {
        try { File.AppendAllText(LogFile, $"[{DateTime.Now:HH:mm:ss.fff}] {msg}\r\n"); } catch { }
        OnLog?.Invoke(msg);
    }
    public int ConnectedClients => _clients.Count;

    public BridgeWebSocketServer(int port, Form mainForm)
    {
        _port = port;
        _mainForm = mainForm;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();

        try
        {
            _sslCert = SslCertificateManager.GetOrCreateLocalhostCert();
            Log("SSL certificate ready for wss://localhost:" + _port);
        }
        catch (Exception ex)
        {
            Log($"Warning: SSL cert error: {ex.Message}. WSS disabled, only ws:// will be available.");
        }

        // wss://localhost:<port> (loopback only) + plain ws://localhost:<port+1> as a local fallback
        if (_sslCert != null) StartListener(_port, secure: true);
        StartListener(_port + 1, secure: false);

        if (_listeners.Count == 0) Log("Server failed: no listener could be started");
    }

    private void StartListener(int port, bool secure)
    {
        foreach (var ip in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            TcpListener? l = null;
            try
            {
                l = new TcpListener(ip, port);
                l.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
                l.Start();
                _listeners.Add(l);
                Log($"Server started on {(secure ? "wss" : "ws")}://{(ip.Equals(IPAddress.Loopback) ? "localhost" : "[::1]")}:{port}");
                var listener = l;
                _ = Task.Run(() => AcceptLoop(listener, secure, _cts!.Token));
            }
            catch (Exception ex)
            {
                try { l?.Stop(); } catch { }
                Log($"Cannot listen on {ip}:{port} — {ex.Message}");
            }
        }
    }

    /// <summary>Khởi động lại listener (dùng sau khi phát hành lại chứng thư SSL).</summary>
    public void Restart()
    {
        Stop();
        System.Threading.Thread.Sleep(300);
        _sslCert = null;
        Start();
    }

    public void Stop()
    {
        _cts?.Cancel();
        foreach (var l in _listeners) { try { l.Stop(); } catch { } }
        _listeners.Clear();
        foreach (var kv in _clients)
        {
            try { kv.Value.CloseAsync(WebSocketCloseStatus.NormalClosure, "Server shutdown",
                CancellationToken.None).Wait(1000); }
            catch { }
        }
        _clients.Clear();
    }

    private async Task AcceptLoop(TcpListener listener, bool secure, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { break; }
            catch (Exception ex) { Log($"Accept error: {ex.Message}"); continue; }

            _ = Task.Run(() => HandleConnection(client, secure, ct), ct);
        }
    }

    private async Task HandleConnection(TcpClient client, bool secure, CancellationToken ct)
    {
        Stream stream = client.GetStream();
        try
        {
            client.NoDelay = true;
            if (secure)
            {
                var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                handshakeCts.CancelAfter(TimeSpan.FromSeconds(10));
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _sslCert,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, handshakeCts.Token);
                stream = ssl;
            }

            var (requestLine, headers) = await ReadHttpHeadersAsync(stream, ct);
            if (requestLine == null) { client.Close(); return; }

            var method = requestLine.Split(' ')[0].ToUpperInvariant();
            headers.TryGetValue("origin", out var origin);

            // Chrome sends a Private Network Access preflight before letting a public page reach localhost.
            if (method == "OPTIONS")
            {
                await WriteAsync(stream,
                    "HTTP/1.1 204 No Content\r\n" + CorsHeaders(origin) +
                    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
                    "Access-Control-Allow-Headers: *\r\n" +
                    "Access-Control-Max-Age: 600\r\n" +
                    "Content-Length: 0\r\nConnection: close\r\n\r\n", ct);
                client.Close();
                return;
            }

            // Request/response channel. Chrome >= 141 refuses WebSockets from a public page to localhost
            // (ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS) even after the user granted the permission, while
            // fetch() is allowed — so the same commands are also served over a plain POST.
            if (method == "POST")
            {
                string reply;
                try
                {
                    var len = headers.TryGetValue("content-length", out var cl) && int.TryParse(cl, out var n) ? n : 0;
                    if (len <= 0 || len > 32 * 1024 * 1024) throw new InvalidOperationException("Invalid Content-Length");
                    var body = new byte[len];
                    var read = 0;
                    while (read < len)
                    {
                        var got = await stream.ReadAsync(body.AsMemory(read, len - read), ct);
                        if (got <= 0) break;
                        read += got;
                    }
                    reply = await Dispatch(Encoding.UTF8.GetString(body, 0, read));
                }
                catch (Exception ex)
                {
                    reply = JsonSerializer.Serialize(new WsSignResponse { Success = false, Error = ex.Message });
                }
                var replyBytes = Encoding.UTF8.GetBytes(reply);
                await WriteAsync(stream,
                    "HTTP/1.1 200 OK\r\n" + CorsHeaders(origin) +
                    "Content-Type: application/json\r\n" +
                    $"Content-Length: {replyBytes.Length}\r\nConnection: close\r\n\r\n", ct);
                await stream.WriteAsync(replyBytes, ct);
                await stream.FlushAsync(ct);
                client.Close();
                return;
            }

            var isUpgrade = headers.TryGetValue("upgrade", out var up) && up.Contains("websocket", StringComparison.OrdinalIgnoreCase);
            if (!isUpgrade)
            {
                // Status endpoint: GET / → JSON (also used by the web plugin to detect the bridge)
                var json = JsonSerializer.Serialize(new WsPongResponse());
                var body = Encoding.UTF8.GetBytes(json);
                await WriteAsync(stream,
                    "HTTP/1.1 200 OK\r\n" + CorsHeaders(origin) +
                    "Content-Type: application/json\r\n" +
                    $"Content-Length: {body.Length}\r\nConnection: close\r\n\r\n", ct);
                await stream.WriteAsync(body, ct);
                await stream.FlushAsync(ct);
                client.Close();
                return;
            }

            if (!headers.TryGetValue("sec-websocket-key", out var key) || string.IsNullOrWhiteSpace(key))
            {
                await WriteAsync(stream, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", ct);
                client.Close();
                return;
            }

            var accept = Convert.ToBase64String(SHA1.HashData(
                Encoding.ASCII.GetBytes(key.Trim() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            await WriteAsync(stream,
                "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
                $"Sec-WebSocket-Accept: {accept}\r\n" + CorsHeaders(origin) + "\r\n", ct);

            var ws = WebSocket.CreateFromStream(stream, isServer: true, subProtocol: null,
                keepAliveInterval: TimeSpan.FromSeconds(15));
            var clientId = Guid.NewGuid().ToString("N")[..8];
            _clients.TryAdd(clientId, ws);
            Log($"Client connected: {clientId}{(secure ? " (wss)" : " (ws)")}");
            await HandleClient(clientId, ws, ct);
        }
        catch (Exception ex)
        {
            Log($"Connection error: {ex.Message}");
        }
        finally
        {
            try { client.Close(); } catch { }
        }
    }

    /// <summary>CORS + Private Network Access headers. Chrome requires Access-Control-Allow-Private-Network
    /// on the preflight (and accepts it on the handshake) before a public page may talk to localhost.</summary>
    private static string CorsHeaders(string? origin) =>
        $"Access-Control-Allow-Origin: {(string.IsNullOrEmpty(origin) ? "*" : origin)}\r\n" +
        "Access-Control-Allow-Private-Network: true\r\n" +          // Chrome <= 140 (Private Network Access)
        "Access-Control-Allow-Local-Network-Access: true\r\n" +     // Chrome >= 141 (Local Network Access)
        "Access-Control-Allow-Credentials: true\r\n";

    private static async Task WriteAsync(Stream s, string text, CancellationToken ct)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        await s.WriteAsync(bytes, ct);
        await s.FlushAsync(ct);
    }

    /// <summary>Read the request line + headers (max 16 KB) without consuming any WebSocket payload.</summary>
    private static async Task<(string? requestLine, Dictionary<string, string> headers)> ReadHttpHeadersAsync(Stream stream, CancellationToken ct)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var buf = new byte[1];
        var sb = new StringBuilder();
        int total = 0;
        using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        readCts.CancelAfter(TimeSpan.FromSeconds(10));
        while (total < 16 * 1024)
        {
            int n;
            try { n = await stream.ReadAsync(buf, readCts.Token); }
            catch { return (null, headers); }
            if (n == 0) return (null, headers);
            sb.Append((char)buf[0]);
            total++;
            if (sb.Length >= 4 && sb[^1] == '\n' && sb[^2] == '\r' && sb[^3] == '\n' && sb[^4] == '\r') break;
        }
        var lines = sb.ToString().Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0) return (null, headers);
        foreach (var line in lines.Skip(1))
        {
            var i = line.IndexOf(':');
            if (i > 0) headers[line[..i].Trim()] = line[(i + 1)..].Trim();
        }
        return (lines[0], headers);
    }

    private async Task HandleClient(string clientId, WebSocket ws, CancellationToken ct)
    {
        var buffer = new byte[64 * 1024]; // 64KB buffer
        // Idle timeout: nếu 5 phút không có message, đóng kết nối
        var idleTimeout = TimeSpan.FromMinutes(5);

        try
        {
            while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                idleCts.CancelAfter(idleTimeout);

                WebSocketReceiveResult result;
                try
                {
                    result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), idleCts.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // Idle timeout — đóng client
                    Log($"Client {clientId} idle 5m -> closing");
                    try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "idle timeout", ct); } catch { }
                    break;
                }

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", ct);
                    break;
                }

                if (result.MessageType == WebSocketMessageType.Text)
                {
                    // Đọc toàn bộ message (có thể lớn hơn buffer)
                    var msgBytes = new MemoryStream();
                    msgBytes.Write(buffer, 0, result.Count);
                    while (!result.EndOfMessage)
                    {
                        result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                        msgBytes.Write(buffer, 0, result.Count);
                    }

                    var msgText = Encoding.UTF8.GetString(msgBytes.ToArray());
                    await ProcessMessage(clientId, ws, msgText);
                }
            }
        }
        catch (WebSocketException) { /* client disconnected */ }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Client {clientId} error: {ex.Message}");
        }
        finally
        {
            _clients.TryRemove(clientId, out _);
            OnLog?.Invoke($"Client disconnected: {clientId}");
        }
    }

    private async Task ProcessMessage(string clientId, WebSocket ws, string msgText)
    {
        var response = await Dispatch(msgText);
        if (response != null) await SendMessage(ws, response);
    }

    /// <summary>Runs one command (ping / list-certificates / sign / sign-cms) and returns the JSON reply.
    /// Shared by the WebSocket channel and the HTTPS POST channel.</summary>
    private async Task<string> Dispatch(string msgText)
    {
        try
        {
            var request = JsonSerializer.Deserialize<WsRequest>(msgText);
            if (request == null)
                return JsonSerializer.Serialize(new WsSignResponse { Success = false, Error = "Empty request" });

            string response;

            switch (request.Action?.ToLower())
            {
                case "ping":
                    response = JsonSerializer.Serialize(new WsPongResponse());
                    break;

                case "list-certificates":
                    response = HandleListCertificates();
                    break;

                case "sign":
                    Log($"Received sign request {request.RequestId}");
                    response = await HandleSign(request);
                    Log($"Sign request {request.RequestId} done");
                    break;

                case "sign-cms":
                    Log($"Received sign-cms request {request.RequestId}");
                    response = HandleSignCms(request);
                    Log($"Sign-cms request {request.RequestId} done");
                    break;

                default:
                    response = JsonSerializer.Serialize(new WsSignResponse
                    {
                        Success = false,
                        Error = $"Unknown action: {request.Action}"
                    });
                    break;
            }

            return response;
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Process error: {ex.Message}");
            return JsonSerializer.Serialize(new WsSignResponse { Success = false, Error = ex.Message });
        }
    }

    private string HandleListCertificates()
    {
        var certs = CertificateHelper.ListSigningCertificates();
        OnLog?.Invoke($"Listed {certs.Count} certificates");
        return JsonSerializer.Serialize(new WsCertificatesResponse { Certificates = certs });
    }

    private Task<string> HandleSign(WsRequest request)
    {
        if (string.IsNullOrEmpty(request.HashBase64))
            return Task.FromResult(JsonSerializer.Serialize(new WsSignResponse
            {
                RequestId = request.RequestId, Success = false, Error = "hashBase64 is required"
            }));

        // Client phải chọn cert trước (qua list-certificates + picker trong web)
        X509Certificate2? cert = null;
        if (!string.IsNullOrEmpty(request.CertificateSerial))
            cert = CertificateHelper.FindCertificate(request.CertificateSerial);
        else if (!string.IsNullOrEmpty(request.CertificateThumbprint))
            cert = CertificateHelper.FindCertificateByThumbprint(request.CertificateThumbprint);

        if (cert == null)
        {
            return Task.FromResult(JsonSerializer.Serialize(new WsSignResponse
            {
                RequestId = request.RequestId, Success = false,
                Error = "Certificate not found. Please select a certificate first."
            }));
        }

        var hash = Convert.FromBase64String(request.HashBase64);

        // Windows tự hiện PIN dialog khi SignHash trên smart card cert (native, luôn foreground)
        Log($"Signing with cert: {cert.Subject}");
        var result = TokenSigner.SignHashWithCert(hash, request.HashAlgorithm, cert);

        if (result.Success)
        {
            Log("Signing successful");
            return Task.FromResult(JsonSerializer.Serialize(new WsSignResponse
            {
                RequestId = request.RequestId, Success = true,
                SignatureBase64 = Convert.ToBase64String(result.Signature!),
                CertificateChainBase64 = result.CertificateChain?
                    .Select(c => Convert.ToBase64String(c)).ToList()
            }));
        }
        Log($"Signing failed: {result.Error}");
        return Task.FromResult(JsonSerializer.Serialize(new WsSignResponse
        {
            RequestId = request.RequestId, Success = false, Error = result.Error
        }));
    }

    private string HandleSignCms(WsRequest request)
    {
        if (string.IsNullOrEmpty(request.ContentBase64))
            return JsonSerializer.Serialize(new WsCmsResponse
            {
                RequestId = request.RequestId, Success = false, Error = "contentBase64 is required"
            });

        X509Certificate2? cert = null;
        if (!string.IsNullOrEmpty(request.CertificateSerial))
            cert = CertificateHelper.FindCertificate(request.CertificateSerial);
        else if (!string.IsNullOrEmpty(request.CertificateThumbprint))
            cert = CertificateHelper.FindCertificateByThumbprint(request.CertificateThumbprint);

        if (cert == null)
            return JsonSerializer.Serialize(new WsCmsResponse
            {
                RequestId = request.RequestId, Success = false, Error = "Certificate not found"
            });

        var content = Convert.FromBase64String(request.ContentBase64);
        Log($"Building CMS for {content.Length} bytes with cert {cert.Subject}");
        var result = TokenSigner.SignCms(content, cert);

        if (result.Success)
        {
            Log($"CMS signed OK, size={result.Cms!.Length}");
            return JsonSerializer.Serialize(new WsCmsResponse
            {
                RequestId = request.RequestId, Success = true,
                CmsBase64 = Convert.ToBase64String(result.Cms)
            });
        }
        Log($"CMS sign failed: {result.Error}");
        return JsonSerializer.Serialize(new WsCmsResponse
        {
            RequestId = request.RequestId, Success = false, Error = result.Error
        });
    }

    private static async Task SendMessage(WebSocket ws, string message)
    {
        if (ws.State != WebSocketState.Open) return;
        var bytes = Encoding.UTF8.GetBytes(message);
        await ws.SendAsync(new ArraySegment<byte>(bytes),
            WebSocketMessageType.Text, true, CancellationToken.None);
    }
}
