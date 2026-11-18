using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using iText.Kernel.Pdf;
using iText.Signatures;
using Jhonju.Assinador.Core;
using Jhonju.Assinador.Windows.Services;

namespace Assinador.Tests;

public class OutputPublishingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SignsAndPublishesTheSameFileNameInAnotherDirectory(bool existingOutput)
    {
        using var files = new TestFiles();
        var inputDirectory = Directory.CreateDirectory(files.PathFor("entrada")).FullName;
        var outputDirectory = Directory.CreateDirectory(files.PathFor("saida")).FullName;
        var original = Path.Combine(inputDirectory, "documento.pdf");
        var destination = Path.Combine(outputDirectory, "documento.pdf");
        SigningTests.CreatePdf(original);
        var originalBytes = File.ReadAllBytes(original);
        if (existingOutput) File.WriteAllText(destination, "VERSAO ANTERIOR");
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=ASSINATURA DE TESTE", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
        var signed = files.PathFor("working-copy.pdf");
        var seal = Sta.Run(SealRenderer.Placeholder);
        var result = new PadesSigner().Sign(original, signed, certificate, [certificate.RawData], seal,
            new(1, .1, .7, .7, .18), DateTimeOffset.Now);

        Assert.Equal(Path.GetFileName(original), Path.GetFileName(destination));
        Assert.False(OriginalFileProtection.IsOriginal(original, destination));
        CopyPublisher.Publish(signed, destination, original, overwrite: existingOutput);

        Assert.Equal(originalBytes, File.ReadAllBytes(original));
        Assert.Equal(File.ReadAllBytes(signed), File.ReadAllBytes(destination));
        using var pdf = new PdfDocument(new PdfReader(destination));
        var signatures = new SignatureUtil(pdf);
        Assert.True(signatures.SignatureCoversWholeDocument(result.FieldName));
        Assert.True(signatures.ReadSignatureData(result.FieldName).VerifySignatureIntegrityAndAuthenticity());
        Assert.Empty(Directory.GetFiles(outputDirectory, ".assinador-*.tmp"));
    }

    [Fact] public void ExplicitOverwriteApprovalNeverAllowsReplacingTheOriginal()
    {
        using var files = new TestFiles();
        var original = files.PathFor("original.pdf");
        var signed = files.PathFor("signed.pdf");
        File.WriteAllText(original, "ORIGINAL");
        File.WriteAllText(signed, "SIGNED");
        Assert.True(OriginalFileProtection.IsOriginal(original, Path.Combine(files.DirectoryPath, ".", "original.pdf")));
        Assert.Throws<IOException>(() => CopyPublisher.Publish(signed, original, original, overwrite: true));
        Assert.Equal("ORIGINAL", File.ReadAllText(original));
    }

    [Fact] public void ASecondPathToTheOriginalCannotBeUsedToOverwriteIt()
    {
        using var files = new TestFiles();
        var original = files.PathFor("original.pdf");
        var alias = files.PathFor("outro-caminho.pdf");
        var signed = files.PathFor("signed.pdf");
        File.WriteAllText(original, "ORIGINAL");
        File.WriteAllText(signed, "SIGNED");
        Assert.True(CreateHardLink(alias, original, IntPtr.Zero), new Win32Exception(Marshal.GetLastWin32Error()).Message);
        Assert.True(OriginalFileProtection.IsOriginal(original, alias));
        Assert.Throws<IOException>(() => CopyPublisher.Publish(signed, alias, original, overwrite: true));
        Assert.Equal("ORIGINAL", File.ReadAllText(original));
        Assert.Equal("ORIGINAL", File.ReadAllText(alias));
    }

    [Fact] public void FailedReplacementPreservesTheExistingDestinationAndRemovesTheTemporaryCopy()
    {
        using var files = new TestFiles();
        var original = files.PathFor("original.pdf");
        var signed = files.PathFor("signed.pdf");
        var destination = files.PathFor("existing.pdf");
        File.WriteAllText(original, "ORIGINAL");
        File.WriteAllText(signed, "SIGNED");
        File.WriteAllText(destination, "EXISTING");
        using (var locked = new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert.Throws<IOException>(() => CopyPublisher.Publish(signed, destination, original, overwrite: true));
        Assert.Equal("ORIGINAL", File.ReadAllText(original));
        Assert.Equal("EXISTING", File.ReadAllText(destination));
        Assert.Empty(Directory.GetFiles(files.DirectoryPath, ".assinador-*.tmp"));
    }

    [Fact] public void MissingWorkingCopyNeverTruncatesAnExistingDestination()
    {
        using var files = new TestFiles();
        var original = files.PathFor("original.pdf");
        var destination = files.PathFor("existing.pdf");
        File.WriteAllText(original, "ORIGINAL");
        File.WriteAllText(destination, "EXISTING");
        Assert.Throws<FileNotFoundException>(() => CopyPublisher.Publish(files.PathFor("missing.pdf"), destination, original, overwrite: true));
        Assert.Equal("ORIGINAL", File.ReadAllText(original));
        Assert.Equal("EXISTING", File.ReadAllText(destination));
        Assert.Empty(Directory.GetFiles(files.DirectoryPath, ".assinador-*.tmp"));
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string newPath, string existingPath, IntPtr securityAttributes);
}
