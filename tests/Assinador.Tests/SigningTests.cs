using System.Security.Cryptography;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Jhonju.Assinador.Core;
using Jhonju.Assinador.Windows.Controls;
using Jhonju.Assinador.Windows.Services;
using Rectangle = iText.Kernel.Geom.Rectangle;

namespace Assinador.Tests;

public class SigningTests
{
    private static byte[] Seal() => Sta.Run(SealRenderer.Placeholder);

    [Fact] public void RsaAndEcCoSignWithoutChangingTheOriginalOrPriorSignature()
    {
        using var files = new TestFiles();
        var original = files.PathFor("original.pdf");
        CreatePdf(original);
        var originalBytes = File.ReadAllBytes(original);
        var input = original;
        foreach (var algorithm in new[] { "RSA", "EC" })
        {
            using var key = algorithm == "RSA" ? (AsymmetricAlgorithm)RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var certificate = SelfSigned(key);
            var output = files.PathFor(algorithm + ".pdf");
            new PadesSigner().Sign(input, output, certificate, [certificate.RawData], Seal(), new(1, .1, .7, .7, .18), DateTimeOffset.Now);
            var inputBytes = File.ReadAllBytes(input);
            Assert.True(File.ReadAllBytes(output).AsSpan(0, inputBytes.Length).SequenceEqual(inputBytes));
            using var pdf = new PdfDocument(new PdfReader(output));
            var util = new SignatureUtil(pdf);
            foreach (var name in util.GetSignatureNames()) Assert.True(util.ReadSignatureData(name).VerifySignatureIntegrityAndAuthenticity());
            Assert.Equal(algorithm == "EC" ? 2 : 1, util.GetSignatureNames().Count);
            Assert.True(util.SignatureCoversWholeDocument(util.GetSignatureNames().Last()));
            input = output;
        }
        Assert.Equal(originalBytes, File.ReadAllBytes(original));
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("EC")]
    public void SignsUsingANonExportableCngKey(string algorithm)
    {
        using var files = new TestFiles();
        using var key = CngKey.Create(algorithm == "RSA" ? CngAlgorithm.Rsa : CngAlgorithm.ECDsaP256, "Jhonju-Assinador-Test-" + Guid.NewGuid().ToString("N"),
            new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None, Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider });
        try
        {
            Assert.Throws<CryptographicException>(() => key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob));
            using AsymmetricAlgorithm privateKey = algorithm == "RSA" ? new RSACng(key) : new ECDsaCng(key);
            using var certificate = SelfSigned(privateKey);
            var source = files.PathFor("source.pdf");
            CreatePdf(source);
            var result = new PadesSigner().Sign(source, files.PathFor("signed.pdf"), certificate, [certificate.RawData], Seal(), new(1, .1, .7, .7, .18), DateTimeOffset.Now);
            Assert.Equal(1, result.SignatureCount);
        }
        finally { key.Delete(); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(90)]
    [InlineData(180)]
    [InlineData(270)]
    public async Task VisibleSealMatchesThePreviewForRotatedAndCroppedPages(int rotation)
    {
        using var files = new TestFiles();
        using var key = RSA.Create(2048);
        using var certificate = SelfSigned(key);
        var source = files.PathFor("source.pdf");
        CreatePdf(source, rotation);
        var target = files.PathFor("signed.pdf");
        var renderer = new PdfPreviewService();
        await renderer.OpenAsync(source);
        var before = await renderer.RenderAsync(1);
        var placement = new SignaturePlacement(1, .13, .61, .65, .65 * before.PixelWidth / before.PixelHeight * SealRenderer.Height / SealRenderer.Width);
        new PadesSigner().Sign(source, target, certificate, [certificate.RawData], Seal(), placement, DateTimeOffset.Now);
        await renderer.OpenAsync(target);
        var after = await renderer.RenderAsync(1);
        Assert.Equal(before.PixelWidth, after.PixelWidth);
        var bounds = DifferenceBounds(before, after);
        Assert.InRange(bounds.Left, placement.Left * after.PixelWidth - 8, placement.Left * after.PixelWidth + 8);
        Assert.InRange(bounds.Top, placement.Top * after.PixelHeight - 8, placement.Top * after.PixelHeight + 8);
        Assert.InRange(bounds.Right, (placement.Left + placement.Width) * after.PixelWidth - 8, (placement.Left + placement.Width) * after.PixelWidth + 8);
        Assert.InRange(bounds.Bottom, (placement.Top + placement.Height) * after.PixelHeight - 8, (placement.Top + placement.Height) * after.PixelHeight + 8);
    }

    [Fact] public void PublishingPreservesTheOriginalAndAnUnapprovedExistingDestination()
    {
        using var files = new TestFiles();
        var source = files.PathFor("original.pdf");
        var signed = files.PathFor("signed.pdf");
        var existing = files.PathFor("existing.pdf");
        File.WriteAllText(source, "ORIGINAL"); File.WriteAllText(signed, "SIGNED"); File.WriteAllText(existing, "EXISTING");
        Assert.Throws<IOException>(() => CopyPublisher.Publish(signed, source, source));
        Assert.Throws<IOException>(() => CopyPublisher.Publish(signed, existing, source));
        Assert.Equal("ORIGINAL", File.ReadAllText(source));
        Assert.Equal("EXISTING", File.ReadAllText(existing));
        var output = files.PathFor("new.pdf");
        CopyPublisher.Publish(signed, output, source);
        Assert.Equal("SIGNED", File.ReadAllText(output));
    }

    [Fact] public void WidePagePlacementAndResizingStayInsideTheDocument()
    {
        Sta.Run(() =>
        {
            var bitmap = BitmapSource.Create(2000, 200, 96, 96, PixelFormats.Gray8, null, new byte[400000], 2000);
            var control = new PdfPlacementView();
            control.SetPage(bitmap, 1);
            control.ResizeSeal(.95);
            var box = control.Placement;
            Assert.InRange(box.Left + box.Width, 0, 1.00001);
            Assert.InRange(box.Top + box.Height, 0, 1.00001);
            Assert.True(box.Height <= .95);
            return true;
        });
    }

    [Fact] public void CertifiedPdfIsRejectedWithoutCreatingAnOutput()
    {
        using var files = new TestFiles();
        var source = files.PathFor("restricted.pdf");
        using (var pdf = new PdfDocument(new PdfWriter(source)))
        {
            pdf.AddNewPage();
            var permissions = new PdfDictionary();
            permissions.Put(PdfName.DocMDP, new PdfDictionary());
            pdf.GetCatalog().GetPdfObject().Put(PdfName.Perms, permissions);
        }
        using var key = RSA.Create(2048);
        using var certificate = SelfSigned(key);
        var target = files.PathFor("output.pdf");
        Assert.Throws<IOException>(() => new PadesSigner().Sign(source, target, certificate, [certificate.RawData], Seal(), new(1, .1, .1, .7, .2), DateTimeOffset.Now));
        Assert.False(File.Exists(target));
    }

    [Theory]
    [InlineData(-.1, .1)]
    [InlineData(.7, .5)]
    [InlineData(double.NaN, .1)]
    public void InvalidPlacementIsRejected(double left, double width) =>
        Assert.Throws<ArgumentException>(() => new SignaturePlacement(1, left, .1, width, .2).ToPdfRectangle(new Rectangle(600, 800), 0));

    internal static void CreatePdf(string path, int rotation = 0)
    {
        using var pdf = new PdfDocument(new PdfWriter(path));
        pdf.AddNewPage(new PageSize(600, 850)).SetCropBox(new Rectangle(30, 50, 500, 700)).SetRotation(rotation);
    }
    private static X509Certificate2 SelfSigned(AsymmetricAlgorithm key)
    {
        var request = key switch
        {
            RSA rsa => new CertificateRequest("CN=ASSINATURA DE TESTE", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ec => new CertificateRequest("CN=ASSINATURA DE TESTE", ec, HashAlgorithmName.SHA256),
            _ => throw new ArgumentException()
        };
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        return request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(5));
    }
    private static Rect DifferenceBounds(BitmapSource before, BitmapSource after)
    {
        var first = new FormatConvertedBitmap(before, PixelFormats.Bgra32, null, 0);
        var second = new FormatConvertedBitmap(after, PixelFormats.Bgra32, null, 0);
        var width = first.PixelWidth;
        var height = first.PixelHeight;
        var a = new byte[width * height * 4]; var b = new byte[a.Length];
        first.CopyPixels(a, width * 4, 0); second.CopyPixels(b, width * 4, 0);
        var minX = width; var minY = height; var maxX = 0; var maxY = 0;
        for (var y = 0; y < height; y++) for (var x = 0; x < width; x++)
        {
            var offset = (y * width + x) * 4;
            if (Math.Abs(a[offset] - b[offset]) + Math.Abs(a[offset + 1] - b[offset + 1]) + Math.Abs(a[offset + 2] - b[offset + 2]) < 100) continue;
            minX = Math.Min(minX, x); minY = Math.Min(minY, y); maxX = Math.Max(maxX, x); maxY = Math.Max(maxY, y);
        }
        Assert.True(minX < maxX && minY < maxY, "A assinatura visível não foi renderizada.");
        return new(minX, minY, maxX - minX + 1, maxY - minY + 1);
    }
}
