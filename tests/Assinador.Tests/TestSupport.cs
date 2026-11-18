using System.Collections.Concurrent;
using System.IO;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Threading;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Assinador.Tests;

internal sealed class TestFiles : IDisposable
{
    public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "Jhonju-Assinador-Tests", Guid.NewGuid().ToString("N"));
    public TestFiles() => Directory.CreateDirectory(DirectoryPath);
    public string PathFor(string name) => Path.Combine(DirectoryPath, name);
    public void Dispose()
    {
        var expected = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "Jhonju-Assinador-Tests")) + Path.DirectorySeparatorChar;
        if (!Path.GetFullPath(DirectoryPath).StartsWith(expected, StringComparison.OrdinalIgnoreCase)) throw new IOException("Diretório de teste inesperado.");
        try { Directory.Delete(DirectoryPath, true); } catch (IOException) { }
    }
}

internal static class Sta
{
    public static T Run<T>(Func<T> action)
    {
        T? result = default;
        Exception? error = null;
        var thread = new Thread(() => { try { result = action(); } catch (Exception exception) { error = exception; } });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (error is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
        return result!;
    }
}

/// <summary>Loopback-only HTTP fixture for the actual Windows revocation engine.</summary>
internal sealed class CrlServer : IDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource cancellation = new();
    private readonly Task worker;
    private readonly ConcurrentDictionary<string, byte[]> files = new();
    private bool disposed;
    public string BaseUrl { get; }
    public CrlServer()
    {
        listener.Start();
        BaseUrl = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/{Guid.NewGuid():N}/";
        worker = RunAsync();
    }
    public void Set(string name, byte[] content) => files[new Uri(BaseUrl + name).AbsolutePath] = content;
    private async Task RunAsync()
    {
        try
        {
            while (!cancellation.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellation.Token);
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true);
                var first = await reader.ReadLineAsync(cancellation.Token);
                while (!string.IsNullOrEmpty(await reader.ReadLineAsync(cancellation.Token))) { }
                var path = first?.Split(' ').ElementAtOrDefault(1) ?? "";
                var found = files.TryGetValue(path, out var data);
                data ??= [];
                var headers = Encoding.ASCII.GetBytes($"HTTP/1.1 {(found ? "200 OK" : "404 Not Found")}\r\nContent-Type: application/pkix-crl\r\nContent-Length: {data.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(headers, cancellation.Token);
                await stream.WriteAsync(data, cancellation.Token);
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or IOException or SocketException) { }
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        cancellation.Cancel(); listener.Stop(); worker.GetAwaiter().GetResult(); cancellation.Dispose();
    }
}

internal sealed class TestChain : IDisposable
{
    public X509Certificate2 Root { get; }
    public X509Certificate2 Intermediate { get; }
    public X509Certificate2 Leaf { get; }
    public DateTimeOffset Now { get; } = DateTimeOffset.Now;

    public TestChain(CrlServer server, bool policy = true, bool cnpj = false)
    {
        Root = Issue("CN=Raiz ICP-Brasil DE TESTE " + Guid.NewGuid().ToString("N"), null, true, null, false, false);
        Intermediate = Issue("CN=AC intermediaria de teste " + Guid.NewGuid().ToString("N"), Root, true, server.BaseUrl + "root.crl", false, false);
        Leaf = Issue("CN=SIGNATARIO DE TESTE:12345678909", Intermediate, false, server.BaseUrl + "issuer.crl", policy, cnpj);
        server.Set("root.crl", Crl(Root));
        server.Set("issuer.crl", Crl(Intermediate));
    }

    public byte[] Crl(X509Certificate2 issuer, X509Certificate2? revoked = null, bool stale = false)
    {
        var builder = new CertificateRevocationListBuilder();
        if (revoked is not null) builder.AddEntry(revoked, Now.AddHours(-1), X509RevocationReason.KeyCompromise);
        return builder.Build(issuer, BigInteger.One, stale ? Now.AddMinutes(-1) : Now.AddDays(2),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, Now.AddHours(-2));
    }

    private X509Certificate2 Issue(string subject, X509Certificate2? issuer, bool ca, string? crlUrl, bool policy, bool cnpj)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(ca ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign : X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (crlUrl is not null) request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([crlUrl]));
        if (!ca)
        {
            var names = new AsnWriter(AsnEncodingRules.DER);
            names.PushSequence();
            names.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            names.WriteObjectIdentifier(cnpj ? "2.16.76.1.3.3" : "2.16.76.1.3.1");
            names.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            names.WriteCharacterString(UniversalTagNumber.UTF8String, cnpj ? "12345678000199" : "0101199012345678909");
            names.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            names.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            names.PopSequence();
            request.CertificateExtensions.Add(new X509Extension("2.5.29.17", names.Encode(), false));
            if (policy)
            {
                var policies = new AsnWriter(AsnEncodingRules.DER);
                policies.PushSequence(); policies.PushSequence();
                policies.WriteObjectIdentifier("2.16.76.1.2.1.9999");
                policies.PopSequence(); policies.PopSequence();
                request.CertificateExtensions.Add(new X509Extension("2.5.29.32", policies.Encode(), false));
            }
        }
        if (issuer is null) return request.CreateSelfSigned(Now.AddDays(-3), Now.AddDays(30));
        using var publicCertificate = request.Create(issuer, Now.AddDays(-2), Now.AddDays(ca ? 20 : 10), RandomNumberGenerator.GetBytes(16));
        return publicCertificate.CopyWithPrivateKey(key);
    }
    public void Dispose() { Leaf.Dispose(); Intermediate.Dispose(); Root.Dispose(); }
}
