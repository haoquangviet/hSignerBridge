using System;
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

    private static string CertFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "hSignerBridge");

    private static string RootCaPath => Path.Combine(CertFolder, "rootca.pfx");
    private static string LocalhostCertPath => Path.Combine(CertFolder, "localhost.pfx");
    private const string CertPassword = "hSignerBridge2024";

    /// <summary>
    /// Lấy hoặc tạo localhost certificate cho WSS server.
    /// Tự động tạo Root CA → sign localhost cert → import Root CA vào Trusted Root store.
    /// </summary>
    public static X509Certificate2 GetOrCreateLocalhostCert()
    {
        Directory.CreateDirectory(CertFolder);

        // Nếu đã có cert và còn hạn → dùng lại
        if (File.Exists(LocalhostCertPath))
        {
            try
            {
                var existing = new X509Certificate2(LocalhostCertPath, CertPassword,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                if (existing.NotAfter > DateTime.Now.AddDays(30))
                    return existing;
            }
            catch { /* cert bị lỗi, tạo lại */ }
        }

        // Tạo Root CA
        var rootCa = CreateRootCa();
        File.WriteAllBytes(RootCaPath, rootCa.Export(X509ContentType.Pfx, CertPassword));

        // Tạo localhost cert ký bởi Root CA
        var localhostCert = CreateLocalhostCert(rootCa);
        File.WriteAllBytes(LocalhostCertPath, localhostCert.Export(X509ContentType.Pfx, CertPassword));

        // Import Root CA vào Trusted Root (cần admin lần đầu)
        ImportRootCaToStore(rootCa);

        return localhostCert;
    }

    private static X509Certificate2 CreateRootCa()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(RootCaSubject, rsa, HashAlgorithmName.SHA256,
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

            // Xoá Root CA cũ nếu có
            foreach (var existing in store.Certificates)
            {
                if (existing.Subject == RootCaSubject)
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
