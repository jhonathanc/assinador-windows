// SPDX-License-Identifier: AGPL-3.0-only
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Jhonju.Assinador.Core;

public sealed record Qualification(bool Qualified, CertificateRoot Root, string Explanation,
    IReadOnlyList<byte[]> Chain, IReadOnlyList<string> Details)
{
    public bool ShowValidatorLink => Root is CertificateRoot.IcpBrasil or CertificateRoot.GovBr;
    public string SealText => Qualified ? "Assinatura qualificada (com raiz na ICP-Brasil)" : "Assinatura digital com certificado";
    public static Qualification Preview { get; } = new(false, CertificateRoot.Unknown, "Prévia", [], []);
}

/// <summary>Native Windows chain/revocation engine; only exact bundled roots qualify the seal.</summary>
public sealed class CertificateTrustService(TrustCatalog authorities)
{
    public bool HasIcpBrasilRoot(X509Certificate2 certificate, DateTimeOffset now)
    {
        // Selection checks provenance only. Evaluate still performs full revocation checks after selection.
        using var path = CreateChain(now, X509RevocationMode.NoCheck, authorities.Intermediates, authorities.IcpRoots);
        try
        {
            if (!path.Build(certificate)) return false;
            var root = path.ChainElements[^1].Certificate;
            return authorities.Classify(root) == CertificateRoot.IcpBrasil &&
                now.UtcDateTime >= root.NotBefore.ToUniversalTime() && now.UtcDateTime <= root.NotAfter.ToUniversalTime();
        }
        catch (CryptographicException) { return false; }
    }

    public Qualification Evaluate(X509Certificate2 certificate, DateTimeOffset now,
        IEnumerable<X509Certificate2>? additionalCertificates = null)
    {
        ValidateHolder(certificate, now);
        var extras = authorities.Intermediates.Concat(additionalCertificates ?? []).ToArray();
        using var path = CreateChain(now, X509RevocationMode.NoCheck, extras,
            authorities.IcpRoots.Concat(authorities.GovRoots));
        var recognized = path.Build(certificate);
        var root = recognized ? authorities.Classify(path.ChainElements[^1].Certificate) : CertificateRoot.Unknown;
        if (root != CertificateRoot.Unknown &&
            (now.UtcDateTime < path.ChainElements[^1].Certificate.NotBefore.ToUniversalTime() ||
             now.UtcDateTime > path.ChainElements[^1].Certificate.NotAfter.ToUniversalTime()))
        {
            root = CertificateRoot.Unknown;
            recognized = false;
        }

        // Windows supplies issuer downloads, CRL/OCSP checking and its own verified revocation cache.
        // A first build without revocation identifies the root; it never suffices for qualification.
        using var online = CreateChain(now, X509RevocationMode.Online, extras,
            recognized ? [path.ChainElements[^1].Certificate] : null);
        var valid = online.Build(certificate);
        if (online.ChainStatus.Any(x => (x.Status & X509ChainStatusFlags.Revoked) != 0))
            throw new CryptographicException("Certificado revogado. A assinatura foi bloqueada.");
        var details = online.ChainStatus.Select(x => $"{x.Status}: {x.StatusInformation.Trim()}").ToList();
        details.Insert(0, "Validação nativa do Windows: cadeia e revogação de todos os certificados subordinados.");
        var chain = (recognized ? path : online).ChainElements.Cast<X509ChainElement>()
            .Select(x => x.Certificate.RawData).ToArray();
        if (chain.Length == 0) chain = [certificate.RawData];
        if (root == CertificateRoot.Unknown)
            return new(false, root, "Raiz fora das cadeias ICP-Brasil e Gov.br autorizadas. Selo sem indicação de qualificada.", chain, details);
        if (!valid)
            return new(false, root, "A verificação completa da cadeia e revogação não foi concluída. Selo sem indicação de qualificada.", chain, details);
        if (root == CertificateRoot.GovBr)
            return new(false, root, "Cadeia e revogação verificadas até a raiz Gov.br de referência.", chain, details);
        if (!HasIcpSigningPolicy(certificate))
            return new(false, root, "Não foi identificada uma política ICP-Brasil de assinatura A1–A4. Selo sem indicação de qualificada.", chain, details);
        return new(true, root, "Cadeia e revogação verificadas até uma raiz oficial ICP-Brasil.", chain, details);
    }

    public static void ValidateHolder(X509Certificate2 certificate, DateTimeOffset now)
    {
        if (now.UtcDateTime < certificate.NotBefore.ToUniversalTime() || now.UtcDateTime > certificate.NotAfter.ToUniversalTime())
            throw new CryptographicException("O certificado está vencido ou ainda não é válido.");
        if (certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(x => x.CertificateAuthority))
            throw new CryptographicException("Selecione um certificado de titular, não uma autoridade certificadora.");
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (usage is not null && (usage.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) == 0)
            throw new CryptographicException("O certificado não permite assinatura digital.");
    }

    private static X509Chain CreateChain(DateTimeOffset now, X509RevocationMode revocation,
        IEnumerable<X509Certificate2> extras, IEnumerable<X509Certificate2>? roots)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.VerificationTime = now.LocalDateTime;
        chain.ChainPolicy.RevocationMode = revocation;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(12);
        chain.ChainPolicy.ExtraStore.AddRange(extras.ToArray());
        if (roots is not null)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots.ToArray());
        }
        return chain;
    }

    private static bool HasIcpSigningPolicy(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions["2.5.29.32"];
        if (extension is null) return false;
        var policies = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
        while (policies.HasData)
            if (Regex.IsMatch(policies.ReadSequence().ReadObjectIdentifier(), @"^2\.16\.76\.1\.2\.[1-4]\..+$")) return true;
        return false;
    }
}
