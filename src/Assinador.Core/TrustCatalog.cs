// SPDX-License-Identifier: AGPL-3.0-only
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Jhonju.Assinador.Core;

public enum CertificateRoot { Unknown, IcpBrasil, GovBr }

public sealed class TrustCatalog : IDisposable
{
    public const string GovBrRootHash = "163BD003BC0DF2BEAB88174B6D5B450B6E1DC973A64B2DC2A33218544F49EF4E";
    private static readonly HashSet<string> OfficialRootHashes =
    [
        "F0C15AFD258FB674E7A96E1A50FF873149364B9EC70D4D93C7A9F1EB6060D020",
        "CAA53FC6091C6951887C976E378F6EF89AA6377C55D97B6475422B71ED7E9B17",
        "3BDB9B509352F1D3D71C2BF64D9A38A4E6CEBDA27809D77F7AC476CBDE6E314A",
        "5657E70580EB678983F3ED7DFCE091D84CAE6549389A47FCCDA8D0E4DC2CF576",
        "D8478E37CE19C690CF657381E68FE600E4E1A042536830F06847E03E554C4B01",
        "2B07D0BC02C4A6E0478ED22D0D99E8F97E1827B269097696A7FEB6AAD30C3AC8"
    ];
    public IReadOnlyList<X509Certificate2> IcpRoots { get; }
    public IReadOnlyList<X509Certificate2> GovRoots { get; }
    public IReadOnlyList<X509Certificate2> Intermediates { get; }

    public TrustCatalog(IEnumerable<X509Certificate2> icpRoots,
        IEnumerable<X509Certificate2>? govRoots = null, IEnumerable<X509Certificate2>? intermediates = null)
    {
        IcpRoots = Copy(icpRoots);
        GovRoots = Copy(govRoots ?? []);
        Intermediates = Copy(intermediates ?? []);
    }

    public static TrustCatalog LoadBundled()
    {
        var icp = new List<X509Certificate2>();
        var gov = new List<X509Certificate2>();
        var extras = new List<X509Certificate2>();
        try
        {
            var assembly = typeof(TrustCatalog).Assembly;
            foreach (var resource in assembly.GetManifestResourceNames().Where(x => x.EndsWith(".crt", StringComparison.Ordinal)))
            {
                using var stream = assembly.GetManifestResourceStream(resource)!;
                using var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                var data = buffer.ToArray();
                var certificate = Encoding.ASCII.GetString(data).Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)
                    ? X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(data))
                    : X509CertificateLoader.LoadCertificate(data);
                var hash = certificate.GetCertHashString(HashAlgorithmName.SHA256);
                if (resource.Contains(".IcpBrasil.", StringComparison.Ordinal))
                {
                    if (!OfficialRootHashes.Contains(hash)) { certificate.Dispose(); throw new CryptographicException("Raiz ICP-Brasil diferente da distribuição verificada."); }
                    icp.Add(certificate);
                }
                else if (hash == GovBrRootHash) gov.Add(certificate);
                else extras.Add(certificate);
            }
            if (icp.Count != 6 || gov.Count != 1 || extras.Count != 2)
                throw new CryptographicException("A distribuição das autoridades públicas está incompleta.");
            return new(icp, gov, extras);
        }
        finally { foreach (var certificate in icp.Concat(gov).Concat(extras)) certificate.Dispose(); }
    }

    public CertificateRoot Classify(X509Certificate2 root) =>
        IcpRoots.Any(x => x.RawData.AsSpan().SequenceEqual(root.RawData)) ? CertificateRoot.IcpBrasil :
        GovRoots.Any(x => x.RawData.AsSpan().SequenceEqual(root.RawData)) ? CertificateRoot.GovBr : CertificateRoot.Unknown;

    private static X509Certificate2[] Copy(IEnumerable<X509Certificate2> certificates) =>
        certificates.Select(c => X509CertificateLoader.LoadCertificate(c.RawData)).ToArray();

    public void Dispose()
    {
        foreach (var certificate in IcpRoots.Concat(GovRoots).Concat(Intermediates)) certificate.Dispose();
    }
}
