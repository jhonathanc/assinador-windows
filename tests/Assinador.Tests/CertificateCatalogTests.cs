using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jhonju.Assinador.Core;
using Jhonju.Assinador.Windows.Services;

namespace Assinador.Tests;

public class CertificateCatalogTests
{
    [Theory]
    [InlineData("icp", true, true)]
    [InlineData("gov", true, false)]
    [InlineData("other", true, false)]
    [InlineData("icp", false, true)]
    [InlineData("gov", false, true)]
    [InlineData("other", false, true)]
    public void SelectionUsesTheExpectedRootScope(string root, bool restrict, bool expected)
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = new TrustCatalog(root == "icp" ? [chain.Root] : [],
            root == "gov" ? [chain.Root] : [], [chain.Intermediate, chain.Root]);
        var trust = new CertificateTrustService(catalog);
        var selectable = restrict
            ? CertificateCatalog.IsSelectable(chain.Leaf, trust, chain.Now)
            : CertificateCatalog.IsSelectable(chain.Leaf, trust, chain.Now, icpBrasilOnly: false);
        Assert.Equal(expected, selectable);
    }

    [Fact] public void SelectionRejectsAnUntrustedRootEvenWhenItsNameClaimsIcpBrasil()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var bundled = TrustCatalog.LoadBundled();
        using var catalog = new TrustCatalog(bundled.IcpRoots, bundled.GovRoots,
            bundled.Intermediates.Concat([chain.Intermediate, chain.Root]));
        var trust = new CertificateTrustService(catalog);
        Assert.False(CertificateCatalog.IsSelectable(chain.Leaf, trust, chain.Now));
        Assert.True(CertificateCatalog.IsSelectable(chain.Leaf, trust, chain.Now, icpBrasilOnly: false));
    }

    [Theory]
    [InlineData("public-only")]
    [InlineData("expired")]
    [InlineData("authority")]
    [InlineData("wrong-usage")]
    public void UnrestrictedRootSelectionStillRequiresAUsableSigningCredential(string restriction)
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        using var publicOnly = X509CertificateLoader.LoadCertificate(chain.Leaf.RawData);
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=TESTE SEM USO DE ASSINATURA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
        using var wrongUsage = request.CreateSelfSigned(chain.Now.AddDays(-1), chain.Now.AddDays(1));
        var certificate = restriction switch
        {
            "public-only" => publicOnly,
            "authority" => chain.Root,
            "wrong-usage" => wrongUsage,
            _ => chain.Leaf
        };
        var now = restriction == "expired" ? chain.Now.AddYears(1) : chain.Now;
        Assert.False(CertificateCatalog.IsSelectable(certificate, new CertificateTrustService(catalog), now, icpBrasilOnly: false));
    }

    [Fact] public void SelectionChecksProvenanceWithoutDependingOnRevocationAvailability()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server, policy: false);
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        server.Dispose();
        Assert.True(CertificateCatalog.IsSelectable(chain.Leaf, new CertificateTrustService(catalog), chain.Now));
    }

    [Fact] public void RevokedCertificateRemainsBlockedAfterUnrestrictedSelection()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        server.Set("issuer.crl", chain.Crl(chain.Intermediate, chain.Leaf));
        var trust = new CertificateTrustService(catalog);
        Assert.True(CertificateCatalog.IsSelectable(chain.Leaf, trust, chain.Now, icpBrasilOnly: false));
        var error = Assert.Throws<CryptographicException>(() => trust.Evaluate(chain.Leaf, chain.Now));
        Assert.Contains("revogado", error.Message);
    }
}
