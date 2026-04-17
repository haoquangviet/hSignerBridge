using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace hSignerBridge;

/// <summary>
/// Liệt kê chứng thư số, detect token type, lấy certificate chain.
/// Logic tái sử dụng từ hAutoSigner CertificateManager.
/// </summary>
public static class CertificateHelper
{
    // Known CSP/KSP provider names for token type detection
    private static readonly Dictionary<string, string> KnownProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        { "eToken Base Cryptographic Provider", "SafeNet" },
        { "SafeNet RSA CSP", "SafeNet" },
        { "SafeNet Smart Card Key Storage Provider", "SafeNet" },
        { "Microsoft Smart Card Key Storage Provider", "SmartCard" },
        { "Microsoft Base Smart Card Crypto Provider", "SmartCard" },
        { "EnterSafe ePass2003", "ePass2003" },
        { "VNPT-CA CSP", "VNPT-CA" },
        { "Viettel-CA CSP", "Viettel-CA" },
        { "Microsoft Enhanced RSA and AES Cryptographic Provider", "Software" },
        { "Microsoft Software Key Storage Provider", "Software" },
        { "Microsoft RSA SChannel Cryptographic Provider", "Software" },
        { "Microsoft Enhanced Cryptographic Provider v1.0", "Software" },
    };

    /// <summary>
    /// Liệt kê tất cả cert có private key trong CurrentUser + LocalMachine store.
    /// </summary>
    public static List<CertInfo> ListSigningCertificates()
    {
        var results = new List<CertInfo>();
        var seenSerials = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly);
                foreach (var cert in store.Certificates)
                {
                    if (!cert.HasPrivateKey) continue;
                    if (cert.NotAfter < DateTime.Now) continue;
                    if (!seenSerials.Add(cert.SerialNumber)) continue;

                    results.Add(ToCertInfo(cert));
                }
            }
            catch { /* skip inaccessible store */ }
        }

        return results;
    }

    /// <summary>
    /// Tìm certificate theo serial number.
    /// </summary>
    public static X509Certificate2? FindCertificate(string serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber)) return null;

        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(
                    X509FindType.FindBySerialNumber, serialNumber, false);
                if (found.Count > 0) return found[0];
            }
            catch { }
        }

        return null;
    }

    /// <summary>
    /// Tìm certificate theo thumbprint.
    /// </summary>
    public static X509Certificate2? FindCertificateByThumbprint(string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint)) return null;

        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(
                    X509FindType.FindByThumbprint, thumbprint, false);
                if (found.Count > 0) return found[0];
            }
            catch { }
        }

        return null;
    }

    /// <summary>
    /// Lấy certificate chain (leaf → intermediate → root).
    /// </summary>
    public static List<byte[]> GetCertificateChain(X509Certificate2 cert)
    {
        var result = new List<byte[]>();
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.Build(cert);

        foreach (var element in chain.ChainElements)
        {
            result.Add(element.Certificate.RawData);
        }

        return result;
    }

    /// <summary>
    /// Set PIN cho USB token. Hỗ trợ CSP (SafeNet, ePass2003) và CNG/KSP (YubiKey).
    /// </summary>
    public static void SetTokenPin(X509Certificate2 cert, string pin)
    {
        var rsaKey = cert.GetRSAPrivateKey();

        if (rsaKey is RSACryptoServiceProvider rsaCsp)
        {
            // Legacy CSP (SafeNet, ePass2003)
            SetCspPin(rsaCsp, pin);
        }
        else if (rsaKey is RSACng rsaCng)
        {
            // CNG/KSP (YubiKey, Smart Card KSP)
            SetCngKeyPin(rsaCng.Key, pin);
        }
        else
        {
            // Try ECDSA
            var ecdsaKey = cert.GetECDsaPrivateKey();
            if (ecdsaKey is ECDsaCng ecdsaCng)
            {
                SetCngKeyPin(ecdsaCng.Key, pin);
            }
        }
    }

    private static void SetCspPin(RSACryptoServiceProvider rsa, string pin)
    {
        var pinBytes = System.Text.Encoding.ASCII.GetBytes(pin + "\0");
        var cspInfo = rsa.CspKeyContainerInfo;

        IntPtr hProv;
        var provHandleProp = cspInfo.GetType().GetProperty("HCryptProv",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        if (provHandleProp != null)
        {
            hProv = (IntPtr)provHandleProp.GetValue(cspInfo)!;
        }
        else
        {
            if (!CryptAcquireContext(out hProv, cspInfo.KeyContainerName,
                cspInfo.ProviderName, cspInfo.ProviderType, 0))
            {
                throw new CryptographicException("Cannot acquire CSP context for PIN setting");
            }
        }

        // PP_SIGNATURE_PIN = 33, PP_KEYEXCHANGE_PIN = 32
        if (!CryptSetProvParam(hProv, 33, pinBytes, 0))
        {
            if (!CryptSetProvParam(hProv, 32, pinBytes, 0))
            {
                var error = Marshal.GetLastWin32Error();
                throw new CryptographicException($"CryptSetProvParam failed with error {error}");
            }
        }
    }

    private static void SetCngKeyPin(CngKey key, string pin)
    {
        var pinBytes = System.Text.Encoding.Unicode.GetBytes(pin);
        var pinProperty = new CngProperty("SmartCardPin", pinBytes, CngPropertyOptions.None);
        key.SetProperty(pinProperty);
    }

    private static CertInfo ToCertInfo(X509Certificate2 cert)
    {
        // Đọc provider name qua CERT_KEY_PROV_INFO_PROP_ID — KHÔNG mở key handle
        // (tránh popup "Smart Card PIN" khi enumerate cert trên USB token)
        var providerName = GetProviderNameSafe(cert);

        // Detect key algorithm từ public key OID (không đụng private key)
        var keyAlgorithm = cert.PublicKey.Oid.Value switch
        {
            "1.2.840.113549.1.1.1" => "RSA",
            "1.2.840.10045.2.1" => "ECDSA",
            _ => cert.PublicKey.Oid.FriendlyName ?? "Unknown"
        };

        return new CertInfo
        {
            Serial = cert.SerialNumber,
            Subject = cert.Subject,
            Issuer = cert.Issuer.Split(',')[0].Trim(),
            NotBefore = cert.NotBefore.ToString("yyyy-MM-dd"),
            NotAfter = cert.NotAfter.ToString("yyyy-MM-dd"),
            Thumbprint = cert.Thumbprint,
            KeyAlgorithm = keyAlgorithm,
            TokenType = DetectTokenType(providerName),
            HasPrivateKey = cert.HasPrivateKey,
            CertBase64 = Convert.ToBase64String(cert.RawData)
        };
    }

    /// <summary>
    /// Lấy provider name từ CERT_KEY_PROV_INFO_PROP_ID mà không mở key handle.
    /// An toàn với USB token: không trigger PIN prompt.
    /// </summary>
    private static string GetProviderNameSafe(X509Certificate2 cert)
    {
        const int CERT_KEY_PROV_INFO_PROP_ID = 2;
        int cbData = 0;

        if (!CertGetCertificateContextProperty(cert.Handle, CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref cbData))
            return "";
        if (cbData == 0) return "";

        var buffer = Marshal.AllocHGlobal(cbData);
        try
        {
            if (!CertGetCertificateContextProperty(cert.Handle, CERT_KEY_PROV_INFO_PROP_ID, buffer, ref cbData))
                return "";

            // CRYPT_KEY_PROV_INFO: pwszContainerName, pwszProvName, dwProvType, ...
            var provNamePtr = Marshal.ReadIntPtr(buffer, IntPtr.Size);
            return provNamePtr == IntPtr.Zero ? "" : Marshal.PtrToStringUni(provNamePtr) ?? "";
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string DetectTokenType(string providerName)
    {
        if (string.IsNullOrEmpty(providerName)) return "Unknown";

        foreach (var kv in KnownProviders)
        {
            if (providerName.Contains(kv.Key, StringComparison.OrdinalIgnoreCase))
                return kv.Value;
        }

        if (providerName.Contains("Smart Card", StringComparison.OrdinalIgnoreCase))
            return "SmartCard";
        if (providerName.Contains("eToken", StringComparison.OrdinalIgnoreCase) ||
            providerName.Contains("SafeNet", StringComparison.OrdinalIgnoreCase))
            return "SafeNet";

        return "Software";
    }

    // P/Invoke
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CryptSetProvParam(
        IntPtr hProv, int dwParam, byte[] pbData, int dwFlags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CryptAcquireContext(
        out IntPtr hProv, string? pszContainer, string? pszProvider,
        int dwProvType, int dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertGetCertificateContextProperty(
        IntPtr pCertContext, int dwPropId, IntPtr pvData, ref int pcbData);
}
