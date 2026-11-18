using System.Security.Cryptography;
using Jhonju.Assinador.Core;

namespace Assinador.Tests;

public class TrustTests
{
    [Fact] public void BundledAuthoritiesHaveTheExactApprovedRoots()
    {
        using var catalog = TrustCatalog.LoadBundled();
        Assert.Equal(6, catalog.IcpRoots.Count);
        Assert.Single(catalog.GovRoots);
        Assert.Equal(2, catalog.Intermediates.Count);
        Assert.Equal(TrustCatalog.GovBrRootHash, catalog.GovRoots[0].GetCertHashString(HashAlgorithmName.SHA256));
    }

    [Fact] public void QualifiedRequiresTheCompleteNativeChainAndValidRevocation()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        var result = new CertificateTrustService(catalog).Evaluate(chain.Leaf, chain.Now);
        Assert.True(result.Qualified, string.Join("\n", result.Details));
        Assert.Equal(CertificateRoot.IcpBrasil, result.Root);
        Assert.True(result.ShowValidatorLink);
        Assert.Equal(3, result.Chain.Count);
    }

    [Fact] public void RevokedCertificateBlocksSigning()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        server.Set("issuer.crl", chain.Crl(chain.Intermediate, chain.Leaf));
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        var error = Assert.Throws<CryptographicException>(() => new CertificateTrustService(catalog).Evaluate(chain.Leaf, chain.Now));
        Assert.Contains("revogado", error.Message);
    }

    [Fact] public void WindowsReusesPreviouslyVerifiedRevocationWhileTheCrlIsValid()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        var service = new CertificateTrustService(catalog);
        Assert.True(service.Evaluate(chain.Leaf, chain.Now).Qualified);
        server.Dispose();
        var offline = service.Evaluate(chain.Leaf, chain.Now.AddSeconds(5));
        Assert.True(offline.Qualified, string.Join("\n", offline.Details));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("stale")]
    [InlineData("wrong-key")]
    public void UnavailableOrUnusableRevocationNeverQualifies(string failure)
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        server.Set("issuer.crl", failure switch { "missing" => [], "stale" => chain.Crl(chain.Intermediate, stale: true), _ => chain.Crl(chain.Root) });
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        var result = new CertificateTrustService(catalog).Evaluate(chain.Leaf, chain.Now);
        Assert.False(result.Qualified);
        Assert.Equal(CertificateRoot.IcpBrasil, result.Root);
        Assert.True(result.ShowValidatorLink);
    }

    [Fact] public void MissingSigningPolicyNeverQualifies()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server, policy: false);
        using var catalog = new TrustCatalog([chain.Root], intermediates: [chain.Intermediate]);
        var result = new CertificateTrustService(catalog).Evaluate(chain.Leaf, chain.Now);
        Assert.False(result.Qualified);
        Assert.Contains("política", result.Explanation);
    }

    [Fact] public void GovBrReferenceEnablesTheLinkButDoesNotQualifyAsIcpBrasil()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = new TrustCatalog([], [chain.Root], [chain.Intermediate]);
        var result = new CertificateTrustService(catalog).Evaluate(chain.Leaf, chain.Now);
        Assert.False(result.Qualified);
        Assert.True(result.ShowValidatorLink);
        Assert.Equal(CertificateRoot.GovBr, result.Root);
    }

    [Fact] public void AnImitatedAuthorityNameDoesNotEnableTheValidatorLink()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = TrustCatalog.LoadBundled();
        var result = new CertificateTrustService(catalog).Evaluate(chain.Leaf, chain.Now, [chain.Intermediate, chain.Root]);
        Assert.False(result.Qualified);
        Assert.False(result.ShowValidatorLink);
        Assert.Equal(CertificateRoot.Unknown, result.Root);
    }

    [Theory]
    [InlineData(false, "CPF: 123.456.789-09")]
    [InlineData(true, "CNPJ: 12.345.678/0001-99")]
    public void IdentityUsesTheHolderDocument(bool company, string expected)
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server, cnpj: company);
        var identity = CertificateIdentity.From(chain.Leaf);
        Assert.Equal("SIGNATARIO DE TESTE", identity.Name);
        Assert.Equal(expected, identity.Document);
    }

    [Fact] public void ExpiredHolderIsRejectedBeforeAnyNetworkCheck()
    {
        using var server = new CrlServer();
        using var chain = new TestChain(server);
        using var catalog = new TrustCatalog([chain.Root]);
        Assert.Throws<CryptographicException>(() => new CertificateTrustService(catalog).Evaluate(chain.Leaf, chain.Now.AddYears(1)));
    }
}
