using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace hSignerBridge;

/// <summary>
/// Tạo và quản lý self-signed Root CA + localhost cert cho WSS.
/// Root CA được import vào Trusted Root store để trình duyệt tin tưởng wss://localhost.
/// </summary>
public static class SslCertificateManager
{
    private const string RootCaSubject = "CN=hSignerBridge Root CA, O=HQV Software";
    private const string LocalhostSubject = "CN=localhost";
    /// <summary>Extra DNS names for the certificate. Empty on purpose: a public hostname resolving to 127.0.0.1
    /// buys nothing, because Chrome's Local Network Access check looks at the resolved IP, not the name.</summary>
    private static readonly string[] ExtraDnsNames = System.Array.Empty<string>();
    /// <summary>Bump when the certificate contents change so existing installs re-issue it.</summary>
    private const int CertVersion = 2;

    private static string CertFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "hSignerBridge");

    private static string RootCaPath => Path.Combine(CertFolder, "rootca.pfx");
    private static string LocalhostCertPath => Path.Combine(CertFolder, $"localhost.v{CertVersion}.pfx");
    private const string CertPassword = "hSignerBridge2024";

    /// <summary>
    /// Lấy hoặc tạo localhost certificate cho WSS server.
    /// Tự động tạo Root CA → sign localhost cert → import Root CA vào Trusted Root store.
    /// </summary>
    public static X509Certificate2 GetOrCreateLocalhostCert()
    {
        Directory.CreateDirectory(CertFolder);

        // Root CA phải được GIỮ NGUYÊN giữa các lần chạy/nâng cấp: nếu sinh root mới trong khi trình duyệt vẫn
        // tin root cũ (trùng Subject, khác khoá) thì Firefox báo SEC_ERROR_BAD_SIGNATURE.
        var rootCa = GetOrCreateRootCa();

        if (File.Exists(LocalhostCertPath))
        {
            try
            {
                var existing = new X509Certificate2(LocalhostCertPath, CertPassword,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                if (existing.NotAfter > DateTime.Now.AddDays(30) && IsIssuedBy(existing, rootCa))
                {
                    ImportRootCaToStore(rootCa);      // đảm bảo root vẫn nằm trong Trusted Root
                    return existing;
                }
            }
            catch { /* hỏng file → phát hành lại */ }
        }

        var localhostCert = CreateLocalhostCert(rootCa);
        File.WriteAllBytes(LocalhostCertPath, localhostCert.Export(X509ContentType.Pfx, CertPassword));
        ImportRootCaToStore(rootCa);
        return localhostCert;
    }

    /// <summary>Đọc lại rootca.pfx nếu còn dùng được, chỉ tạo mới khi chưa có / sắp hết hạn.</summary>
    private static X509Certificate2 GetOrCreateRootCa()
    {
        if (File.Exists(RootCaPath))
        {
            try
            {
                var existing = new X509Certificate2(RootCaPath, CertPassword,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                if (existing.NotAfter > DateTime.Now.AddDays(60) && existing.HasPrivateKey)
                    return existing;
            }
            catch { /* hỏng file → tạo lại */ }
        }

        var rootCa = CreateRootCa();
        File.WriteAllBytes(RootCaPath, rootCa.Export(X509ContentType.Pfx, CertPassword));
        return rootCa;
    }

    /// <summary>Chữ ký của leaf có verify được bằng khoá công khai của root không.</summary>
    private static bool IsIssuedBy(X509Certificate2 leaf, X509Certificate2 root)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.ExtraStore.Add(root);
            chain.Build(leaf);
            return chain.ChainElements.Count > 1 &&
                   string.Equals(chain.ChainElements[^1].Certificate.Thumbprint, root.Thumbprint, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>Trạng thái chứng thư hiện tại — dùng cho menu chẩn đoán.</summary>
    public static string Diagnose()
    {
        var sb = new System.Text.StringBuilder();
        var baseCn = RootCaSubject.Split(',')[0].Trim();
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var mine = new List<X509Certificate2>();
            foreach (var c in store.Certificates)
                if (c.Subject.StartsWith(baseCn, StringComparison.OrdinalIgnoreCase)) mine.Add(c);

            sb.AppendLine($"Root CA trong Trusted Root: {mine.Count}");
            foreach (var c in mine) sb.AppendLine($"  - {c.Subject.Split(',')[0]}  [{c.Thumbprint?[..8]}…]  hết hạn {c.NotAfter:dd/MM/yyyy}");
        }
        catch (Exception ex) { sb.AppendLine("Không đọc được Trusted Root: " + ex.Message); }

        try
        {
            if (File.Exists(LocalhostCertPath))
            {
                var leaf = new X509Certificate2(LocalhostCertPath, CertPassword, X509KeyStorageFlags.EphemeralKeySet);
                sb.AppendLine($"Chứng thư localhost: hết hạn {leaf.NotAfter:dd/MM/yyyy}, cấp bởi {leaf.Issuer.Split(',')[0]}");
                if (File.Exists(RootCaPath))
                {
                    var root = new X509Certificate2(RootCaPath, CertPassword, X509KeyStorageFlags.EphemeralKeySet);
                    sb.AppendLine("Khớp với Root CA đang lưu: " + (IsIssuedBy(leaf, root) ? "có" : "KHÔNG"));
                }
            }
            else sb.AppendLine("Chưa có chứng thư localhost.");
        }
        catch (Exception ex) { sb.AppendLine("Không đọc được chứng thư localhost: " + ex.Message); }

        return sb.ToString();
    }

    /// <summary>Xoá sạch Root CA + chứng thư cũ của ứng dụng rồi phát hành lại (dùng khi trình duyệt báo
    /// SEC_ERROR_BAD_SIGNATURE / ERR_CERT_AUTHORITY_INVALID vì máy còn root cũ trùng tên).</summary>
    public static X509Certificate2 Repair()
    {
        var baseCn = RootCaSubject.Split(',')[0].Trim();
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            foreach (var c in store.Certificates)
                if (c.Subject.StartsWith(baseCn, StringComparison.OrdinalIgnoreCase)) store.Remove(c);
        }
        catch { /* không xoá được thì vẫn tiếp tục phát hành cert mới */ }

        try { if (File.Exists(LocalhostCertPath)) File.Delete(LocalhostCertPath); } catch { }
        try { if (File.Exists(RootCaPath)) File.Delete(RootCaPath); } catch { }

        return GetOrCreateLocalhostCert();
    }

    private static X509Certificate2 CreateRootCa()
    {
        using var rsa = RSA.Create(2048);
        // Thêm id ngẫu nhiên vào CN: nếu máy còn root cũ cùng tên (khác khoá), trình duyệt sẽ không chọn nhầm
        // rồi báo "Peer's certificate has an invalid signature".
        var uniqueSubject = RootCaSubject.Replace("Root CA", "Root CA " + Guid.NewGuid().ToString("N")[..6].ToUpperInvariant());
        var req = new CertificateRequest(uniqueSubject, rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));

        // Export và re-import để có exportable private key
        return new X509Certificate2(cert.Export(X509ContentType.Pfx, CertPassword), CertPassword,
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 CreateLocalhostCert(X509Certificate2 rootCa)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(LocalhostSubject, rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Subject Alternative Names: localhost + 127.0.0.1
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        foreach (var extra in ExtraDnsNames) sanBuilder.AddDnsName(extra);
        sanBuilder.AddIpAddress(IPAddress.Loopback);        // 127.0.0.1
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);    // ::1
        req.CertificateExtensions.Add(sanBuilder.Build());

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, // Server Authentication
            false));

        var serialNumber = new byte[16];
        RandomNumberGenerator.Fill(serialNumber);

        var cert = req.Create(rootCa, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5), serialNumber);

        // Combine with private key
        var certWithKey = cert.CopyWithPrivateKey(rsa);
        return new X509Certificate2(certWithKey.Export(X509ContentType.Pfx, CertPassword), CertPassword,
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
    }

    private static void ImportRootCaToStore(X509Certificate2 rootCa)
    {
        try
        {
            // Import vào CurrentUser Trusted Root (không cần admin)
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Xoá mọi Root CA cũ của ứng dụng (trùng tên nhưng khác khoá) — nguồn gốc lỗi SEC_ERROR_BAD_SIGNATURE
            var baseCn = RootCaSubject.Split(',')[0].Trim();          // "CN=... Root CA"
            foreach (var existing in store.Certificates)
            {
                if (existing.Subject.StartsWith(baseCn, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(existing.Thumbprint, rootCa.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    store.Remove(existing);
            }

            // Chỉ import public cert (không private key)
            var publicCert = new X509Certificate2(rootCa.Export(X509ContentType.Cert));
            store.Add(publicCert);
        }
        catch (Exception ex)
        {
            // Nếu không import được, WSS vẫn hoạt động nhưng trình duyệt sẽ cảnh báo
            Console.Error.WriteLine($"Warning: Cannot import Root CA to Trusted Root store: {ex.Message}");
        }
    }
}
