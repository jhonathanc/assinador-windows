// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography.X509Certificates;
using iText.Bouncycastleconnector;
using iText.Forms.Form.Element;
using iText.IO.Image;
using iText.Kernel.Pdf;
using iText.Layout.Properties;
using iText.Signatures;

namespace Jhonju.Assinador.Core;

public sealed record SigningResult(string FieldName, int SignatureCount);

public sealed class PadesSigner
{
    public SigningResult Sign(string source, string target, X509Certificate2 certificate,
        IReadOnlyList<byte[]> chain, byte[] sealPng, SignaturePlacement placement,
        DateTimeOffset date, string reason = "", string location = "")
    {
        if (PathsEqual(source, target)) throw new IOException("O destino deve ser diferente do PDF original.");
        if (File.Exists(target)) throw new IOException("O destino já existe. Escolha um novo arquivo.");
        CertificateTrustService.ValidateHolder(certificate, date);
        iText.Kernel.Geom.Rectangle rectangle;
        using (var pdf = new PdfDocument(new PdfReader(source)))
        {
            if (placement.Page > pdf.GetNumberOfPages()) throw new ArgumentException("Página inexistente.");
            if (pdf.GetCatalog().GetPdfObject().GetAsDictionary(PdfName.Perms)?.ContainsKey(PdfName.DocMDP) == true)
                throw new IOException("Este PDF é certificado e possui restrições para novas assinaturas.");
            var util = new SignatureUtil(pdf);
            foreach (var name in util.GetSignatureNames())
            {
                var references = util.GetSignatureDictionary(name).GetAsArray(PdfName.Reference);
                if (references is null) continue;
                for (var i = 0; i < references.Size(); i++)
                    if (PdfName.FieldMDP.Equals(references.GetAsDictionary(i)?.GetAsName(PdfName.TransformMethod)))
                        throw new IOException("O PDF possui bloqueios de campos assinados e não pode ser alterado por este aplicativo.");
            }
            var page = pdf.GetPage(placement.Page);
            rectangle = placement.ToPdfRectangle(page.GetCropBox(), page.GetRotation());
        }
        var field = "Ass-" + Guid.NewGuid().ToString("N");
        var appearance = new SignatureFieldAppearance("seal").SetContent(ImageDataFactory.Create(sealPng));
        foreach (var property in new[] { Property.PADDING_LEFT, Property.PADDING_RIGHT, Property.PADDING_TOP, Property.PADDING_BOTTOM,
                     Property.MARGIN_LEFT, Property.MARGIN_RIGHT, Property.MARGIN_TOP, Property.MARGIN_BOTTOM })
            appearance.SetProperty(property, UnitValue.CreatePointValue(0));
        var properties = new SignerProperties().SetFieldName(field).SetClaimedSignDate(date.LocalDateTime)
            .SetReason(string.IsNullOrWhiteSpace(reason) ? "Assinatura digital" : reason)
            .SetLocation(location).SetPageNumber(placement.Page).SetPageRect(rectangle).SetSignatureAppearance(appearance);
        var factory = BouncyCastleFactoryCreator.GetFactory();
        var parser = factory.CreateX509CertificateParser();
        var certificates = chain.Select(x => parser.ReadAllCerts(x).Single()).ToArray();
        if (certificates.Length == 0 || !certificates[0].GetEncoded().AsSpan().SequenceEqual(certificate.RawData))
            throw new ArgumentException("A cadeia deve começar pelo certificado selecionado.");
        var created = false;
        try
        {
            using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                created = true;
                using var reader = new PdfReader(source);
                using var signature = new WindowsCertificateSignature(certificate);
                new PdfPadesSigner(reader, output).SetStampingProperties(new StampingProperties().UseAppendMode())
                    .SetTemporaryDirectoryPath(Path.GetDirectoryName(Path.GetFullPath(target))!)
                    .SignWithBaselineBProfile(properties, certificates, signature);
            }
            using var signedPdf = new PdfDocument(new PdfReader(target));
            var signatures = new SignatureUtil(signedPdf);
            if (!signatures.SignatureCoversWholeDocument(field) || !signatures.ReadSignatureData(field).VerifySignatureIntegrityAndAuthenticity())
                throw new IOException("A verificação criptográfica do PDF assinado falhou.");
            return new(field, signatures.GetSignatureNames().Count);
        }
        catch
        {
            if (created) File.Delete(target);
            throw;
        }
    }

    public static bool PathsEqual(string first, string second) =>
        string.Equals(Path.GetFullPath(first), Path.GetFullPath(second), StringComparison.OrdinalIgnoreCase);
}

/// <summary>Publishes a completed copy without replacing the original or truncating an existing output on failure.</summary>
public static class CopyPublisher
{
    public static void Publish(string signedWorkingCopy, string destination, string original, bool overwrite = false)
    {
        original = Path.GetFullPath(original);
        destination = Path.GetFullPath(destination);
        if (PadesSigner.PathsEqual(original, destination)) throw new IOException("O PDF original não pode ser sobrescrito.");
        // Deny deletion/replacement of the original while publishing, including through an alias.
        using var originalHandle = File.OpenHandle(original, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        OriginalFileProtection.EnsureDifferent(originalHandle, original, destination);
        using var input = new FileStream(signedWorkingCopy, FileMode.Open, FileAccess.Read, FileShare.Read);
        var temporary = Path.Combine(Path.GetDirectoryName(destination)!, ".assinador-" + Guid.NewGuid().ToString("N") + ".tmp");
        var created = false;
        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                created = true;
                input.CopyTo(output);
                output.Flush(true);
            }
            OriginalFileProtection.EnsureDifferent(originalHandle, original, destination);
            if (overwrite && File.Exists(destination)) File.Replace(temporary, destination, null);
            else File.Move(temporary, destination);
            created = false;
        }
        finally
        {
            // Only this operation's temporary file is removed. Existing output is never deleted on failure.
            if (created) File.Delete(temporary);
        }
    }
}
