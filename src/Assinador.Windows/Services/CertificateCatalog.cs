// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography.X509Certificates;
using Jhonju.Assinador.Core;

namespace Jhonju.Assinador.Windows.Services;

public static class CertificateCatalog
{
    public static IReadOnlyList<X509Certificate2> Read(CertificateTrustService trust, bool icpBrasilOnly = true)
    {
        var results = new List<X509Certificate2>();
        var seen = new HashSet<string>();
        var now = DateTimeOffset.Now;
        try
        {
            foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
            {
                using var store = new X509Store(StoreName.My, location);
                try { store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
                catch (System.Security.Cryptography.CryptographicException) { continue; }
                foreach (var certificate in store.Certificates)
                {
                    using (certificate)
                    {
                        if (seen.Contains(certificate.Thumbprint) || !IsSelectable(certificate, trust, now, icpBrasilOnly)) continue;
                        results.Add(new X509Certificate2(certificate));
                        seen.Add(certificate.Thumbprint);
                    }
                }
            }
            return results.OrderBy(x => x.GetNameInfo(X509NameType.SimpleName, false)).ToArray();
        }
        catch
        {
            foreach (var certificate in results) certificate.Dispose();
            throw;
        }
    }

    public static bool IsSelectable(X509Certificate2 certificate, CertificateTrustService trust,
        DateTimeOffset now, bool icpBrasilOnly = true)
    {
        // These requirements apply to every selection; HasPrivateKey does not open/export the key.
        return certificate.HasPrivateKey &&
            certificate.NotBefore.ToUniversalTime() <= now.UtcDateTime && certificate.NotAfter.ToUniversalTime() >= now.UtcDateTime &&
            certificate.PublicKey.Oid.Value is "1.2.840.113549.1.1.1" or "1.2.840.10045.2.1" &&
            !certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority) &&
            !certificate.Extensions.OfType<X509KeyUsageExtension>().Any(x => (x.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) == 0) &&
            (!icpBrasilOnly || trust.HasIcpBrasilRoot(certificate, now));
    }
}
