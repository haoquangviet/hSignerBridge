using System.Text.Json.Serialization;

namespace hSignerBridge;

// ==================== WebSocket Messages ====================

public class WsRequest
{
    [JsonPropertyName("action")]
    public string Action { get; set; } = "";

    [JsonPropertyName("requestId")]
    public string? RequestId { get; set; }

    [JsonPropertyName("certificateSerial")]
    public string? CertificateSerial { get; set; }

    [JsonPropertyName("certificateThumbprint")]
    public string? CertificateThumbprint { get; set; }

    [JsonPropertyName("hashAlgorithm")]
    public string HashAlgorithm { get; set; } = "SHA-256";

    [JsonPropertyName("hashBase64")]
    public string? HashBase64 { get; set; }

    [JsonPropertyName("contentBase64")]
    public string? ContentBase64 { get; set; }

    [JsonPropertyName("pin")]
    public string? Pin { get; set; }
}

public class WsCmsResponse
{
    [JsonPropertyName("action")]
    public string Action { get; set; } = "sign-cms-result";

    [JsonPropertyName("requestId")]
    public string? RequestId { get; set; }

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("cmsBase64")]
    public string? CmsBase64 { get; set; }
}

public class WsPongResponse
{
    [JsonPropertyName("action")]
    public string Action { get; set; } = "pong";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "ready";
}

public class WsCertificatesResponse
{
    [JsonPropertyName("action")]
    public string Action { get; set; } = "certificates";

    [JsonPropertyName("certificates")]
    public List<CertInfo> Certificates { get; set; } = new();
}

public class WsSignResponse
{
    [JsonPropertyName("action")]
    public string Action { get; set; } = "sign-result";

    [JsonPropertyName("requestId")]
    public string? RequestId { get; set; }

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("signatureBase64")]
    public string? SignatureBase64 { get; set; }

    [JsonPropertyName("certificateChainBase64")]
    public List<string>? CertificateChainBase64 { get; set; }
}

public class WsPinRequiredResponse
{
    [JsonPropertyName("action")]
    public string Action { get; set; } = "pin-required";

    [JsonPropertyName("requestId")]
    public string? RequestId { get; set; }

    [JsonPropertyName("certificateSubject")]
    public string? CertificateSubject { get; set; }
}

// ==================== Certificate Info ====================

public class CertInfo
{
    [JsonPropertyName("serial")]
    public string Serial { get; set; } = "";

    [JsonPropertyName("subject")]
    public string Subject { get; set; } = "";

    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = "";

    [JsonPropertyName("notBefore")]
    public string NotBefore { get; set; } = "";

    [JsonPropertyName("notAfter")]
    public string NotAfter { get; set; } = "";

    [JsonPropertyName("thumbprint")]
    public string Thumbprint { get; set; } = "";

    [JsonPropertyName("keyAlgorithm")]
    public string KeyAlgorithm { get; set; } = "RSA";

    [JsonPropertyName("tokenType")]
    public string TokenType { get; set; } = "Unknown";

    [JsonPropertyName("hasPrivateKey")]
    public bool HasPrivateKey { get; set; }

    [JsonPropertyName("certBase64")]
    public string CertBase64 { get; set; } = "";
}

// ==================== Sign Result ====================

public class SignResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public byte[]? Signature { get; set; }
    public List<byte[]>? CertificateChain { get; set; }

    public static SignResult Ok(byte[] signature, List<byte[]> chain) => new()
    {
        Success = true,
        Signature = signature,
        CertificateChain = chain
    };

    public static SignResult Fail(string error) => new()
    {
        Success = false,
        Error = error
    };
}
