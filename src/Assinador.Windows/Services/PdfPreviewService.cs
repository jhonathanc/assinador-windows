// SPDX-License-Identifier: AGPL-3.0-only
using System.IO;
using System.Windows.Media.Imaging;
using global::Windows.Storage;
using global::Windows.Storage.Streams;
using WinPdf = global::Windows.Data.Pdf;

namespace Jhonju.Assinador.Windows.Services;

/// <summary>Renders locally using the Windows PDF engine, without a browser or external service.</summary>
public sealed class PdfPreviewService
{
    private WinPdf.PdfDocument? document;
    public int PageCount => checked((int)(document?.PageCount ?? 0));

    public async Task OpenAsync(string path)
    {
        var file = await StorageFile.GetFileFromPathAsync(Path.GetFullPath(path));
        document = await WinPdf.PdfDocument.LoadFromFileAsync(file);
        if (PageCount == 0) throw new IOException("O PDF não contém páginas.");
    }

    public async Task<BitmapSource> RenderAsync(int pageNumber)
    {
        if (document is null || pageNumber < 1 || pageNumber > PageCount) throw new ArgumentOutOfRangeException(nameof(pageNumber));
        using var page = document.GetPage((uint)(pageNumber - 1));
        var size = page.Size;
        var scale = 1800 / Math.Max(size.Width, size.Height);
        using var output = new InMemoryRandomAccessStream();
        await page.RenderToStreamAsync(output, new WinPdf.PdfPageRenderOptions
        {
            DestinationWidth = (uint)Math.Max(1, Math.Round(size.Width * scale)),
            DestinationHeight = (uint)Math.Max(1, Math.Round(size.Height * scale))
        });
        using var reader = new DataReader(output.GetInputStreamAt(0));
        await reader.LoadAsync((uint)output.Size);
        var bytes = new byte[checked((int)output.Size)];
        reader.ReadBytes(bytes);
        return Decode(bytes);
    }

    public static BitmapImage Decode(byte[] png)
    {
        using var memory = new MemoryStream(png);
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.StreamSource = memory;
        bitmap.EndInit();
        bitmap.Freeze();
        return bitmap;
    }
}
