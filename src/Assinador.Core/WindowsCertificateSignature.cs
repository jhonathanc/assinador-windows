// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using iText.Signatures;
using iText.Kernel.Crypto;

namespace Jhonju.Assinador.Core;

/// <summary>Uses CAPI/CNG or the installed token provider directly. Never exports a private key.</summary>
public sealed class WindowsCertificateSignature : IExternalSignature, IDisposable
{
    private readonly RSA? rsa;
    private readonly ECDsa? ec;

    public WindowsCertificateSignature(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey) throw new CryptographicException("O certificado não possui chave privada acessível.");
        rsa = certificate.GetRSAPrivateKey();
        if (rsa is null) ec = certificate.GetECDsaPrivateKey();
        if (rsa is null && ec is null) throw new CryptographicException("O certificado deve usar RSA ou ECDSA.");
    }
    public string GetDigestAlgorithmName() => DigestAlgorithms.SHA256;
    public string GetSignatureAlgorithmName() => rsa is null ? "ECDSA" : "RSA";
    public ISignatureMechanismParams? GetSignatureMechanismParameters() => null;
    public byte[] Sign(byte[] message) => rsa is not null
        ? rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        : ec!.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    public void Dispose() { rsa?.Dispose(); ec?.Dispose(); }
}
