using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using ISession = Net.Pkcs11Interop.HighLevelAPI.ISession;

namespace hSignerBridge;

/// <summary>Raised when the token refused the PIN (wrong / locked / expired). Callers must NOT retry the same PIN through
/// another path (CSP, KSP…): every attempt burns one of the token's few retries.</summary>
public sealed class Pkcs11PinException : CryptographicException
{
    public Pkcs11PinException(string message) : base(message) { }
}

/// <summary>
/// Signs with a USB token through the token vendor's own PKCS#11 module, the PIN going straight into C_Login.
/// <para>Why: Windows CSP/KSP drivers decide by themselves whether to honour a PIN handed in by the app. Viettel-CA V6's
/// KSP ignores it and pops up its PIN dialog on every signature. The PKCS#11 module that ships in the same driver
/// (most Vietnamese CA tokens are Feitian EnterSafe rebrands: <c>viettel-ca_v6.dll</c>, <c>fca_v1.dll</c>,
/// <c>vnptca_p11_v8.dll</c>… next to the <c>*_s.dll</c> CSP shell) takes the PIN without any UI.</para>
/// Module order: explicit path from the profile → module derived from the CSP the certificate is registered under →
/// known vendor modules (Vietnamese CAs + common global tokens/HSMs) → OpenSC. The first module whose token holds this
/// exact certificate wins; nothing is logged in on any other token, so no PIN is ever tried on the wrong device.
/// Requires the interactive user session, like every other smart-card path (Session 0 has no PC/SC access).
/// </summary>
public static class Pkcs11KeyProvider
{
    /// <summary>File names searched in System32 (or the absolute path, when given).</summary>
    private static readonly string[] KnownModules =
    {
        // Vietnamese public CAs (NEAC-licensed) — the token driver installs these in System32
        "viettel-ca_v6.dll", "viettel-ca_v5.dll", "viettel-ca_v4.dll", "viettel-ca_v3.dll", "viettel-ca_v2.dll",
        "viettel-ca_v1.dll", "viettel-ca.dll",
        "fca_v1.dll",                                                     // FastCA
        "vnptca_p11_v10.dll", "vnptca_p11_v8.dll", "vnpt-ca_cl_v1.dll", "vnpt-ca_v4.dll", "vnpt-ca_v34.dll", "vnpt-ca_csp11.dll",
        "fpt-ca_v5.dll", "fpt-ca_v4.dll", "fpt-ca.dll",
        "BkavCA.dll", "BkavCAv2S.dll", "st3csp11.dll",                    // BKAV-CA (SecureMetric)
        "ncca_csp11_v1.dll", "CA2_csp11.dll", "CA2_v34.dll",              // Nacencomm CA2 / NCCA
        "Safe-ca_v2.dll", "Safe-ca_v1.dll",
        "efy-ca_v1.dll",
        "vina-ca_v5.dll", "vina-ca_v3.dll", "vina-ca_v1.dll",             // SmartSign (Vina-CA)
        "newca_v4.dll",                                                   // Newtel-CA
        "misaca_csp11_v2.dll",
        // Global tokens / HSMs
        "eps2003csp11.dll", "eps2003csp11v2.dll", "ShuttleCsp11_3003.dll", // Feitian ePass2003 / 3003
        "eTPKCS11.dll",                                                   // SafeNet / Aladdin eToken
        "IDPrimePKCS1164.dll",                                            // Thales / Gemalto IDPrime
        "bit4xpki.dll",                                                   // Bit4id
        "acospkcs11.dll",                                                 // ACS ACOS5
        "WDPKCS.dll",                                                     // Watchdata
        "aetpkss1.dll",                                                   // AET SafeSign
        "cryst32.dll",                                                    // Chrysalis
        "pkcs201n.dll", "dkck201.dll", "dkck232.dll",                     // Datakey / Entrust / iKey
        "sadaptor.dll",                                                   // Eutron
        "pk2priv.dll",                                                    // Gemplus
        "cryptoki.dll",                                                   // IBM
        "micardoPKCS11.dll",                                              // Orga Micardo
        "slbck.dll",                                                      // Schlumberger
        "SpyPK11.dll",                                                    // Spyrus
        "cknfast.dll",                                                    // nCipher
    };

    /// <summary>Modules installed under Program Files (relative to it).</summary>
    private static readonly string[] KnownProgramFilesModules =
    {
        @"Yubico\Yubico PIV Tool\bin\libykcs11.dll",
        @"SafeNet\LunaClient\cryptoki.dll",
        @"nCipher\nfast\toolkits\pkcs11\cknfast.dll",
        @"Vasco\DIGIPASS CertiID\VdsPKCS1164.dll",
        @"Bkav Corporation\BkavCA Token Manager\st3csp11.dll",
    };

    private const string OpenScModule = @"OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll";

    internal static readonly Pkcs11InteropFactories Factories = new();
    private static readonly object Gate = new();
    // Loaded modules stay loaded for the life of the process: some vendor modules misbehave on repeated C_Finalize/C_Initialize.
    private static readonly Dictionary<string, IPkcs11Library?> Libraries = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<(string, ulong), int> LoginRefs = new();

    /// <summary>
    /// True when this certificate should be signed through PKCS#11: a module path is configured, or the key belongs to a
    /// third-party token CSP/KSP. Microsoft providers (software keys, Smart Card KSP/minidriver), SafeNet eToken (its KSP
    /// honours the PIN), YubiKey (own PIV path) and cloud KSPs keep the existing path.
    /// </summary>
    public static bool ShouldTry(X509Certificate2 cert, string? explicitModule)
    {
        if (!string.IsNullOrWhiteSpace(explicitModule)) return true;
        var prov = GetKeyProvider(cert)?.Provider;
        if (string.IsNullOrEmpty(prov)) return false;
        string[] keep = { "Microsoft", "eToken", "SafeNet", "eSigner", "Yubi" };
        return !keep.Any(k => prov.StartsWith(k, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Candidate modules in priority order (existing files only, right bitness, exporting C_GetFunctionList).</summary>
    public static List<string> CandidateModules(X509Certificate2 cert, string? explicitModule)
    {
        var list = new List<string>();
        void Add(string? p)
        {
            if (string.IsNullOrWhiteSpace(p)) return;
            p = Environment.ExpandEnvironmentVariables(p.Trim().Trim('"'));
            if (!Path.IsPathRooted(p)) p = Path.Combine(Environment.SystemDirectory, p);
            if (list.Contains(p, StringComparer.OrdinalIgnoreCase) || !IsPkcs11Module(p)) return;
            list.Add(p);
        }

        Add(explicitModule);
        foreach (var derived in DerivedModules(cert)) Add(derived);
        foreach (var m in KnownModules) Add(m);
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        foreach (var m in KnownProgramFilesModules) Add(Path.Combine(pf, m));
        Add(Path.Combine(pf, OpenScModule));
        return list;
    }

    /// <summary>
    /// Opens the token key for <paramref name="cert"/> through PKCS#11 and logs in with <paramref name="pin"/>.
    /// Returns an <see cref="RSA"/> / <see cref="ECDsa"/> that signs on the token, or null when no module holds this
    /// certificate. Throws <see cref="Pkcs11PinException"/> when the token rejects the PIN.
    /// </summary>
    public static AsymmetricAlgorithm? TryOpen(X509Certificate2 cert, string pin, string? explicitModule, bool ecdsa, Action<string>? log = null)
    {
        var raw = cert.RawData;
        foreach (var path in CandidateModules(cert, explicitModule))
        {
            var lib = Load(path, log);
            if (lib == null) continue;
            List<ISlot> slots;
            try { slots = lib.GetSlotList(SlotsType.WithTokenPresent); }
            catch (Exception ex) { log?.Invoke($"PKCS#11 {Path.GetFileName(path)}: slot list failed ({ex.Message})"); continue; }

            foreach (var slot in slots)
            {
                ISession? session = null;
                try
                {
                    session = slot.OpenSession(SessionType.ReadOnly);
                    var id = FindCertificateId(session, raw);
                    if (id == null) { session.CloseSession(); session = null; continue; }

                    var slotKey = (path, slot.SlotId);
                    LoginUser(session, pin, slotKey);
                    try
                    {
                        var key = FindPrivateKey(session, id)
                            ?? throw new CryptographicException("The token holds the certificate but no matching private key");
                        var alwaysAuth = ReadBool(session, key, CKA.CKA_ALWAYS_AUTHENTICATE);
                        AsymmetricAlgorithm pub = ecdsa
                            ? cert.GetECDsaPublicKey() ?? throw new CryptographicException("Certificate has no ECDSA public key")
                            : cert.GetRSAPublicKey() ?? throw new CryptographicException("Certificate has no RSA public key");
                        var handle = new Pkcs11KeyHandle(session, key, slotKey, alwaysAuth ? pin : null);
                        log?.Invoke($"PKCS#11 key opened via {Path.GetFileName(path)} (slot {slot.SlotId}{(alwaysAuth ? ", context-specific PIN" : "")})");
                        return ecdsa ? new Pkcs11ECDsa(handle, (ECDsa)pub) : new Pkcs11Rsa(handle, (RSA)pub);
                    }
                    catch
                    {
                        ReleaseLogin(session, slotKey);
                        session = null;
                        throw;
                    }
                }
                catch (Pkcs11PinException) { try { session?.CloseSession(); } catch { } throw; }
                catch (Exception ex)
                {
                    log?.Invoke($"PKCS#11 {Path.GetFileName(path)} slot {slot.SlotId}: {ex.Message}");
                    try { session?.CloseSession(); } catch { }
                }
            }
        }
        return null;
    }

    // ---- module discovery ---------------------------------------------------------------------------------------

    private sealed record KeyProvider(string Provider, int ProvType);

    private static KeyProvider? GetKeyProvider(X509Certificate2 cert)
    {
        uint cb = 0;
        if (!CertGetCertificateContextProperty(cert.Handle, 2 /* CERT_KEY_PROV_INFO_PROP_ID */, IntPtr.Zero, ref cb) || cb == 0) return null;
        var buf = Marshal.AllocHGlobal((int)cb);
        try
        {
            if (!CertGetCertificateContextProperty(cert.Handle, 2, buf, ref cb)) return null;
            var kpi = Marshal.PtrToStructure<CRYPT_KEY_PROV_INFO>(buf);
            return string.IsNullOrEmpty(kpi.pwszProvName) ? null : new KeyProvider(kpi.pwszProvName, (int)kpi.dwProvType);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    /// <summary>The PKCS#11 module that ships with the certificate's CSP/KSP: EnterSafe-style drivers register
    /// <c>X_s.dll</c> as the CSP and put the PKCS#11 module in <c>X.dll</c> beside it (often the same DLL exports both).</summary>
    private static IEnumerable<string> DerivedModules(X509Certificate2 cert)
    {
        var kp = GetKeyProvider(cert);
        if (kp == null) yield break;
        var images = new List<string>();
        try
        {
            if (kp.ProvType != 0)
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Cryptography\Defaults\Provider\{kp.Provider}");
                if (k?.GetValue("Image Path") is string img) images.Add(img);
            }
            else
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Control\Cryptography\Providers\{kp.Provider}\UM");
                foreach (var sub in k?.GetSubKeyNames() ?? Array.Empty<string>())
                {
                    using var s = k!.OpenSubKey(sub);
                    if (s?.GetValue("Image") is string img) images.Add(img);
                }
            }
        }
        catch { }

        foreach (var img in images)
        {
            var full = Environment.ExpandEnvironmentVariables(img);
            if (!Path.IsPathRooted(full)) full = Path.Combine(Environment.SystemDirectory, full);
            var name = Path.GetFileNameWithoutExtension(full);
            var dir = Path.GetDirectoryName(full)!;
            if (name.EndsWith("_s", StringComparison.OrdinalIgnoreCase))
                yield return Path.Combine(dir, name[..^2] + ".dll");
            yield return full;
        }
    }

    /// <summary>Reads the PE header instead of LoadLibrary-ing arbitrary DLLs: same machine type as this process and an
    /// exported <c>C_GetFunctionList</c>.</summary>
    internal static bool IsPkcs11Module(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var d = File.ReadAllBytes(path);
            int pe = BitConverter.ToInt32(d, 0x3c);
            if (pe <= 0 || pe + 24 > d.Length || BitConverter.ToUInt32(d, pe) != 0x4550) return false;
            ushort machine = BitConverter.ToUInt16(d, pe + 4);
            ushort want = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => 0x8664, Architecture.X86 => 0x14c, Architecture.Arm64 => 0xaa64, _ => 0
            };
            if (machine != want) return false;
            ushort magic = BitConverter.ToUInt16(d, pe + 24);
            int dd = pe + 24 + (magic == 0x20b ? 112 : 96);
            uint expRva = BitConverter.ToUInt32(d, dd);
            if (expRva == 0) return false;
            int nsec = BitConverter.ToUInt16(d, pe + 6), sh = pe + 24 + BitConverter.ToUInt16(d, pe + 20);
            int Off(uint rva)
            {
                for (int i = 0; i < nsec; i++)
                {
                    int s = sh + i * 40;
                    uint vs = BitConverter.ToUInt32(d, s + 8), va = BitConverter.ToUInt32(d, s + 12);
                    uint rs = BitConverter.ToUInt32(d, s + 16), ra = BitConverter.ToUInt32(d, s + 20);
                    if (rva >= va && rva < va + Math.Max(vs, rs)) return (int)(rva - va + ra);
                }
                return -1;
            }
            int e = Off(expRva);
            if (e < 0) return false;
            int n = BitConverter.ToInt32(d, e + 24), names = Off(BitConverter.ToUInt32(d, e + 32));
            if (names < 0) return false;
            var target = "C_GetFunctionList"u8;
            for (int i = 0; i < n; i++)
            {
                int o = Off(BitConverter.ToUInt32(d, names + 4 * i));
                if (o >= 0 && o + target.Length < d.Length && d.AsSpan(o, target.Length).SequenceEqual(target) && d[o + target.Length] == 0)
                    return true;
            }
            return false;
        }
        catch { return false; }
    }

    private static IPkcs11Library? Load(string path, Action<string>? log)
    {
        lock (Gate)
        {
            if (Libraries.TryGetValue(path, out var cached)) return cached;
            IPkcs11Library? lib = null;
            try { lib = Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Factories, path, AppType.MultiThreaded); }
            catch (Exception ex) { log?.Invoke($"PKCS#11 module {path} could not be loaded: {ex.Message}"); }
            Libraries[path] = lib;
            return lib;
        }
    }

    // ---- token objects ------------------------------------------------------------------------------------------

    private static byte[]? FindCertificateId(ISession session, byte[] raw)
    {
        var f = Factories.ObjectAttributeFactory;
        List<IObjectHandle> certs;
        try
        {
            certs = session.FindAllObjects(new List<IObjectAttribute>
                { f.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE), f.Create(CKA.CKA_VALUE, raw) });
        }
        catch { certs = new List<IObjectHandle>(); }
        // Some tokens cannot search on CKA_VALUE — compare every certificate instead.
        if (certs.Count == 0)
            certs = session.FindAllObjects(new List<IObjectAttribute> { f.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE) })
                .Where(h =>
                {
                    try { return session.GetAttributeValue(h, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray()?.SequenceEqual(raw) == true; }
                    catch { return false; }
                }).ToList();
        if (certs.Count == 0) return null;
        return session.GetAttributeValue(certs[0], new List<CKA> { CKA.CKA_ID })[0].GetValueAsByteArray() ?? Array.Empty<byte>();
    }

    private static IObjectHandle? FindPrivateKey(ISession session, byte[] id)
    {
        var f = Factories.ObjectAttributeFactory;
        var keys = session.FindAllObjects(new List<IObjectAttribute>
            { f.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY), f.Create(CKA.CKA_ID, id) });
        if (keys.Count > 0) return keys[0];
        // CKA_ID left empty by some issuers: accept the token's only private key, never guess between several.
        var all = session.FindAllObjects(new List<IObjectAttribute> { f.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY) });
        return all.Count == 1 ? all[0] : null;
    }

    private static bool ReadBool(ISession session, IObjectHandle h, CKA attr)
    {
        try { return session.GetAttributeValue(h, new List<CKA> { attr })[0].GetValueAsBool(); }
        catch { return false; }
    }

    private static readonly CKR[] PinErrors =
        { CKR.CKR_PIN_INCORRECT, CKR.CKR_PIN_LOCKED, CKR.CKR_PIN_INVALID, CKR.CKR_PIN_LEN_RANGE, CKR.CKR_PIN_EXPIRED };

    internal static Pkcs11PinException PinError(CKR rv) => new(rv switch
    {
        CKR.CKR_PIN_LOCKED => "The token PIN is locked (too many wrong attempts). Unlock it with the CA's token manager.",
        CKR.CKR_PIN_EXPIRED => "The token PIN has expired. Change it with the CA's token manager.",
        _ => $"The token rejected the PIN ({rv}). Check the PIN saved in the signing profile — signing stopped so the token does not lock."
    });

    private static void LoginUser(ISession session, string pin, (string, ulong) slotKey)
    {
        try { session.Login(CKU.CKU_USER, pin); }
        catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_USER_ALREADY_LOGGED_IN) { }
        catch (Pkcs11Exception ex) when (PinErrors.Contains(ex.RV)) { throw PinError(ex.RV); }
        lock (Gate) LoginRefs[slotKey] = LoginRefs.GetValueOrDefault(slotKey) + 1;
    }

    internal static void ReleaseLogin(ISession session, (string, ulong) slotKey)
    {
        bool last;
        lock (Gate)
        {
            var n = LoginRefs.GetValueOrDefault(slotKey) - 1;
            last = n <= 0;
            if (last) LoginRefs.Remove(slotKey); else LoginRefs[slotKey] = n;
        }
        // Login state is per token for the whole process: log out only when no other key of this token is open.
        if (last) { try { session.Logout(); } catch { } }
        try { session.CloseSession(); } catch { }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CRYPT_KEY_PROV_INFO
    {
        public string pwszContainerName;
        public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);
}

/// <summary>A logged-in session + private key handle; signing is serialised (PKCS#11 sessions are not thread-safe).</summary>
internal sealed class Pkcs11KeyHandle : IDisposable
{
    private readonly ISession _session;
    private readonly IObjectHandle _key;
    private readonly (string, ulong) _slotKey;
    private readonly string? _contextPin;
    private bool _disposed;

    public Pkcs11KeyHandle(ISession session, IObjectHandle key, (string, ulong) slotKey, string? contextPin)
    {
        _session = session; _key = key; _slotKey = slotKey; _contextPin = contextPin;
    }

    public byte[] Sign(IMechanism mechanism, byte[] data)
    {
        lock (this)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            try
            {
                return _contextPin != null ? _session.Sign(mechanism, _key, _contextPin, data) : _session.Sign(mechanism, _key, data);
            }
            catch (Pkcs11Exception ex) when (ex.RV is CKR.CKR_PIN_INCORRECT or CKR.CKR_PIN_LOCKED or CKR.CKR_PIN_EXPIRED)
            {
                throw Pkcs11KeyProvider.PinError(ex.RV);
            }
            catch (Pkcs11Exception ex)
            {
                throw new CryptographicException($"Token signing failed ({ex.RV})", ex);
            }
        }
    }

    public IMechanismFactory Mechanisms => Pkcs11KeyProvider.Factories.MechanismFactory;

    public Net.Pkcs11Interop.HighLevelAPI.Factories.IMechanismParamsFactory MechanismParams =>
        Pkcs11KeyProvider.Factories.MechanismParamsFactory;

    public void Dispose()
    {
        lock (this)
        {
            if (_disposed) return;
            _disposed = true;
            Pkcs11KeyProvider.ReleaseLogin(_session, _slotKey);
        }
    }
}

/// <summary>RSA whose private operations run on the token (CKM_RSA_PKCS over DigestInfo, or CKM_RSA_PKCS_PSS).</summary>
internal sealed class Pkcs11Rsa : RSA
{
    private readonly Pkcs11KeyHandle _h;
    private readonly RSA _pub;

    public Pkcs11Rsa(Pkcs11KeyHandle handle, RSA publicKey)
    {
        _h = handle; _pub = publicKey;
        LegalKeySizesValue = new[] { new KeySizes(512, 16384, 8) };
        KeySizeValue = publicKey.KeySize;
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters) throw new CryptographicException("The private key cannot leave the token");
        return _pub.ExportParameters(false);
    }

    public override void ImportParameters(RSAParameters parameters) => throw new NotSupportedException();

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding == RSASignaturePadding.Pkcs1)
            return _h.Sign(_h.Mechanisms.Create(CKM.CKM_RSA_PKCS), DigestInfo(hashAlgorithm).Concat(hash).ToArray());
        if (padding == RSASignaturePadding.Pss)
        {
            var (ckm, mgf) = hashAlgorithm.Name switch
            {
                "SHA384" => (CKM.CKM_SHA384, CKG.CKG_MGF1_SHA384),
                "SHA512" => (CKM.CKM_SHA512, CKG.CKG_MGF1_SHA512),
                _ => (CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256)
            };
            var p = _h.MechanismParams.CreateCkRsaPkcsPssParams(ConvertUtils.UInt64FromCKM(ckm), ConvertUtils.UInt64FromCKG(mgf), (ulong)hash.Length);
            return _h.Sign(_h.Mechanisms.Create(CKM.CKM_RSA_PKCS_PSS, p), hash);
        }
        throw new CryptographicException($"Unsupported RSA padding {padding}");
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        => _pub.VerifyHash(hash, signature, hashAlgorithm, padding);

    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => _pub.Encrypt(data, padding);

    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) => throw new NotSupportedException("Decryption on the token is not used");

    private static byte[] DigestInfo(HashAlgorithmName alg) => Convert.FromHexString(alg.Name switch
    {
        "SHA1" => "3021300906052b0e03021a05000414",
        "SHA384" => "3041300d060960864801650304020205000430",
        "SHA512" => "3051300d060960864801650304020305000440",
        _ => "3031300d060960864801650304020105000420"
    });

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _h.Dispose(); _pub.Dispose(); }
        base.Dispose(disposing);
    }
}

/// <summary>ECDSA on the token (CKM_ECDSA returns r||s, the IEEE P1363 layout .NET's ECDsa.SignHash returns).</summary>
internal sealed class Pkcs11ECDsa : ECDsa
{
    private readonly Pkcs11KeyHandle _h;
    private readonly ECDsa _pub;

    public Pkcs11ECDsa(Pkcs11KeyHandle handle, ECDsa publicKey)
    {
        _h = handle; _pub = publicKey;
        LegalKeySizesValue = new[] { new KeySizes(256, 521, 1) };
        KeySizeValue = publicKey.KeySize;
    }

    public override byte[] SignHash(byte[] hash) => _h.Sign(_h.Mechanisms.Create(CKM.CKM_ECDSA), hash);

    public override bool VerifyHash(byte[] hash, byte[] signature) => _pub.VerifyHash(hash, signature);

    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters) throw new CryptographicException("The private key cannot leave the token");
        return _pub.ExportParameters(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _h.Dispose(); _pub.Dispose(); }
        base.Dispose(disposing);
    }
}
