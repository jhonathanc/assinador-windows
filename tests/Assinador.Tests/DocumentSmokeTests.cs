using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Media.Imaging;
using iText.Kernel.Pdf;
using Jhonju.Assinador.Core;
using Jhonju.Assinador.Windows.Services;

namespace Assinador.Tests;

public class DocumentSmokeTests
{
    [Fact] public async Task OpensSignsAndRendersTheEntireDocumentWithoutChangingItsInput()
    {
        using var files = new TestFiles();
        var supplied = Environment.GetEnvironmentVariable("ASSINADOR_TEST_PDF");
        var source = files.PathFor("original.pdf");
        if (!string.IsNullOrWhiteSpace(supplied)) File.Copy(supplied, source);
        else
        {
            using var pdf = new PdfDocument(new PdfWriter(source));
            for (var i = 0; i < 59; i++) pdf.AddNewPage();
        }
        var original = File.ReadAllBytes(source);
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=DOCUMENTO DE TESTE - SEM VALIDADE JURIDICA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
        var renderer = new PdfPreviewService();
        await renderer.OpenAsync(source);
        var count = renderer.PageCount;
        var preview = await renderer.RenderAsync(1);
        var seal = Sta.Run(() => SealRenderer.Render(new("ASSINATURA DE TESTE", "Certificado temporário para testes"), DateTimeOffset.Now, Qualification.Preview));
        var placement = new SignaturePlacement(1, .05, .78, .7, .7 * preview.PixelWidth / preview.PixelHeight * SealRenderer.Height / SealRenderer.Width);
        var output = files.PathFor("documento-teste_assinado.pdf");
        new PadesSigner().Sign(source, output, certificate, [certificate.RawData], seal, placement, DateTimeOffset.Now, "Teste automatizado");
        await renderer.OpenAsync(output);
        Assert.Equal(count, renderer.PageCount);
        var first = await renderer.RenderAsync(1);
        var last = await renderer.RenderAsync(count);
        Assert.True(first.PixelWidth > 0 && last.PixelWidth > 0);
        Assert.Equal(original, File.ReadAllBytes(source));
        if (!string.IsNullOrWhiteSpace(supplied)) Assert.Equal(original, File.ReadAllBytes(supplied));
        var evidence = Environment.GetEnvironmentVariable("ASSINADOR_EVIDENCE_DIR");
        if (!string.IsNullOrWhiteSpace(evidence))
        {
            Directory.CreateDirectory(evidence);
            File.Copy(output, Path.Combine(evidence, "documento-teste_assinado.pdf"), true);
            File.WriteAllBytes(Path.Combine(evidence, "selo-teste.png"), seal);
            Sta.Run(() =>
            {
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(first));
                using var stream = File.Create(Path.Combine(evidence, "primeira-pagina-assinada.png"));
                encoder.Save(stream);
                return true;
            });
        }
    }
}
