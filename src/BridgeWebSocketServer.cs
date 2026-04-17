using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
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
    private HttpListener? _listener;
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

        // Tạo SSL cert cho WSS
        try
        {
            _sslCert = SslCertificateManager.GetOrCreateLocalhostCert();
            OnLog?.Invoke("SSL certificate ready for wss://localhost:" + _port);
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Warning: SSL cert error: {ex.Message}. Using HTTP fallback.");
        }

        _listener = new HttpListener();
        // Dùng HTTPS nếu có cert, fallback HTTP
        var scheme = _sslCert != null ? "https" : "http";
        _listener.Prefixes.Add($"{scheme}://localhost:{_port}/");
        // Thêm HTTP prefix luôn (cho trường hợp test local)
        if (_sslCert != null)
            _listener.Prefixes.Add($"http://localhost:{_port + 1}/");

        try
        {
            _listener.Start();
            OnLog?.Invoke($"Server started on {scheme}://localhost:{_port}");
            Task.Run(() => AcceptLoop(_cts.Token));
        }
        catch (HttpListenerException ex)
        {
            OnLog?.Invoke($"Cannot start server: {ex.Message}");
            // Fallback: thử HTTP only
            try
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://localhost:{_port}/");
                _listener.Start();
                OnLog?.Invoke($"Fallback: HTTP server on http://localhost:{_port}");
                Task.Run(() => AcceptLoop(_cts.Token));
            }
            catch (Exception ex2)
            {
                OnLog?.Invoke($"Server failed: {ex2.Message}");
            }
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        foreach (var kv in _clients)
        {
            try { kv.Value.CloseAsync(WebSocketCloseStatus.NormalClosure, "Server shutdown",
                CancellationToken.None).Wait(1000); }
            catch { }
        }
        _clients.Clear();
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var context = await _listener!.GetContextAsync();

                // CORS headers
                context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
                context.Response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                context.Response.Headers.Add("Access-Control-Allow-Headers", "*");

                if (context.Request.HttpMethod == "OPTIONS")
                {
                    context.Response.StatusCode = 204;
                    context.Response.Close();
                    continue;
                }

                if (context.Request.IsWebSocketRequest)
                {
                    // Accept với keepalive 15s — phát hiện client chết nhanh, tránh WS rò rỉ
                    var wsContext = await context.AcceptWebSocketAsync(
                        subProtocol: null,
                        receiveBufferSize: 16384,
                        keepAliveInterval: TimeSpan.FromSeconds(15));
                    var clientId = Guid.NewGuid().ToString("N")[..8];
                    _clients.TryAdd(clientId, wsContext.WebSocket);
                    OnLog?.Invoke($"Client connected: {clientId}");
                    _ = Task.Run(() => HandleClient(clientId, wsContext.WebSocket, ct));
                }
                else
                {
                    // HTTP status endpoint: GET / → JSON status
                    await HandleHttpRequest(context);
                }
            }
            catch (ObjectDisposedException) { break; }
            catch (HttpListenerException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                OnLog?.Invoke($"Accept error: {ex.Message}");
            }
        }
    }

    private async Task HandleHttpRequest(HttpListenerContext context)
    {
        var json = JsonSerializer.Serialize(new WsPongResponse());
        var bytes = Encoding.UTF8.GetBytes(json);
        context.Response.ContentType = "application/json";
        context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
        await context.Response.OutputStream.WriteAsync(bytes);
        context.Response.Close();
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
                    Log($"Client {clientId} idle 5m → đóng");
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
        try
        {
            var request = JsonSerializer.Deserialize<WsRequest>(msgText);
            if (request == null) return;

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
                    response = await HandleSign(ws, request);
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

            await SendMessage(ws, response);
        }
        catch (Exception ex)
        {
            OnLog?.Invoke($"Process error: {ex.Message}");
            var errorResponse = JsonSerializer.Serialize(new WsSignResponse
            {
                Success = false,
                Error = ex.Message
            });
            await SendMessage(ws, errorResponse);
        }
    }

    private string HandleListCertificates()
    {
        var certs = CertificateHelper.ListSigningCertificates();
        OnLog?.Invoke($"Listed {certs.Count} certificates");
        return JsonSerializer.Serialize(new WsCertificatesResponse { Certificates = certs });
    }

    private Task<string> HandleSign(WebSocket ws, WsRequest request)
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
                Error = "Không tìm thấy chứng thư số. Vui lòng chọn cert trước."
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
                RequestId = request.RequestId, Success = false, Error = "Không tìm thấy chứng thư số"
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
