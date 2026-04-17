using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace hSignerBridge;

/// <summary>
/// Ký hash bằng private key của certificate trên USB token.
/// Windows tự show PIN dialog khi truy cập private key.
/// </summary>
public static class TokenSigner
{
    /// <summary>
    /// Ký hash bằng certificate đã chọn. Windows sẽ tự hiện PIN dialog.
    /// </summary>
    public static SignResult SignHashWithCert(byte[] hash, string? hashAlgorithm, X509Certificate2 cert)
    {
        try
        {
            if (!cert.HasPrivateKey)
                return SignResult.Fail("Chứng thư số không có private key");

            var algName = (hashAlgorithm?.ToUpper()) switch
            {
                "SHA-384" or "SHA384" => HashAlgorithmName.SHA384,
                "SHA-512" or "SHA512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256,
            };

            byte[] signature;
            var rsaKey = cert.GetRSAPrivateKey();
            if (rsaKey != null)
            {
                signature = rsaKey.SignHash(hash, algName, RSASignaturePadding.Pkcs1);
            }
            else
            {
                var ecdsaKey = cert.GetECDsaPrivateKey();
                if (ecdsaKey != null)
                    // CMS/PKCS#7 yêu cầu ECDSA signature ở định dạng DER SEQUENCE {r, s}
                    // (không phải IEEE P1363 raw r||s — mặc định của SignHash(hash))
                    signature = ecdsaKey.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
                else
                    return SignResult.Fail("Không tìm thấy private key RSA hoặc ECDSA");
            }

            var chain = CertificateHelper.GetCertificateChain(cert);
            return SignResult.Ok(signature, chain);
        }
        catch (CryptographicException ex)
        {
            return SignResult.Fail($"Lỗi mật mã: {ex.Message}");
        }
        catch (Exception ex)
        {
            return SignResult.Fail($"Lỗi: {ex.Message}");
        }
    }

    /// <summary>
    /// Build detached CMS/PKCS#7 signature cho PDF.
    /// Dùng .NET SignedCms (chuẩn DER, tương thích Adobe Reader).
    /// Windows tự pop PIN dialog khi ComputeSignature trên smart card.
    /// </summary>
    public static CmsResult SignCms(byte[] content, X509Certificate2 cert)
    {
        try
        {
            if (!cert.HasPrivateKey)
                return CmsResult.Fail("Chứng thư số không có private key");

            // Lấy private key explicit để truyền vào CmsSigner
            // Tránh lỗi "Invalid type specified" với Smart Card KSP (CNG)
            AsymmetricAlgorithm? privateKey = cert.GetRSAPrivateKey();
            if (privateKey == null) privateKey = cert.GetECDsaPrivateKey();
            if (privateKey == null)
                return CmsResult.Fail("Không truy cập được private key (RSA/ECDSA)");

            var contentInfo = new ContentInfo(content);
            var cms = new SignedCms(contentInfo, detached: true);

            // Overload nhận privateKey explicit — khắc phục lỗi CNG/Smart Card
            var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert, privateKey)
            {
                IncludeOption = X509IncludeOption.WholeChain,
                DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"), // SHA-256
            };

            // signedAttrs sẽ tự thêm (contentType, messageDigest)
            // ComputeSignature trigger Windows PIN dialog cho smart card cert
            cms.ComputeSignature(signer, silent: false);

            return CmsResult.Ok(cms.Encode());
        }
        catch (CryptographicException ex)
        {
            return CmsResult.Fail($"Lỗi mật mã: {ex.Message}");
        }
        catch (Exception ex)
        {
            return CmsResult.Fail($"Lỗi: {ex.Message}");
        }
    }
}

public class CmsResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public byte[]? Cms { get; set; }

    public static CmsResult Ok(byte[] cms) => new() { Success = true, Cms = cms };
    public static CmsResult Fail(string error) => new() { Success = false, Error = error };
}
