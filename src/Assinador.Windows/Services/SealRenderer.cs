// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Jhonju.Assinador.Core;

namespace Jhonju.Assinador.Windows.Services;

public static class SealRenderer
{
    public const int Width = 1800;
    public const int Height = 460;
    private static readonly CultureInfo Culture = CultureInfo.GetCultureInfo("pt-BR");

    public static byte[] Placeholder() => Render(new("SIGNATÁRIO DO CERTIFICADO", "CPF/CNPJ conforme certificado"),
        DateTimeOffset.Now, Qualification.Preview, true);

    public static byte[] Render(CertificateIdentity identity, DateTimeOffset date, Qualification qualification, bool preview = false)
    {
        var visual = new DrawingVisual();
        using (var draw = visual.RenderOpen())
        {
            var gray = new SolidColorBrush(Color.FromRgb(137, 148, 160));
            var blue = new SolidColorBrush(Color.FromRgb(0, 72, 145));
            draw.DrawRoundedRectangle(Brushes.White, new Pen(gray, 3), new Rect(3, 3, 1794, 454), 32, 32);
            draw.DrawLine(new Pen(gray, 3), new Point(565, 65), new Point(565, 398));
            draw.DrawRoundedRectangle(null, new Pen(blue, 13), new Rect(72, 150, 64, 86), 32, 32);
            draw.DrawRoundedRectangle(new LinearGradientBrush(Color.FromRgb(0, 72, 145), Color.FromRgb(0, 53, 115), 90),
                null, new Rect(48, 198, 112, 94), 17, 17);
            draw.DrawGeometry(null, new Pen(Brushes.White, 14) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round },
                Geometry.Parse("M74,242 L94,261 L139,219"));
            Text(draw, "assinatura", 177, 127, 76, blue, true, 370);
            Text(draw, "digital", 177, 202, 76, blue, true, 370);
            var colors = new[] { Color.FromRgb(29, 160, 58), Color.FromRgb(255, 210, 0), Color.FromRgb(0, 115, 255) };
            for (var i = 0; i < colors.Length; i++)
            {
                var x = 178 + i * 113;
                var geometry = new StreamGeometry();
                using (var path = geometry.Open())
                {
                    path.BeginFigure(new Point(x + 25, 319), true, true);
                    path.PolyLineTo([new(x + 138, 319), new(x + 113, 354), new(x, 354)], true, false);
                }
                draw.DrawGeometry(new SolidColorBrush(colors[i]), null, geometry);
            }
            var showLink = !preview && qualification.ShowValidatorLink;
            var top = showLink ? 52 : 86;
            Text(draw, identity.Name.ToUpper(Culture), 615, top, 58, Brushes.Black, true, 1125);
            Text(draw, identity.Document, 615, top + 68, 46, Brushes.Black, false, 1125);
            var timestamp = date.ToString("dd/MM/yyyy HH:mm:ss", Culture) + " " + date.ToString("zzz", Culture).Replace(":", "");
            Text(draw, preview ? "Data: definida ao assinar" : "Data: " + timestamp, 615, top + 136, 46, Brushes.Black, false, 1125);
            if (showLink) Text(draw, "Verifique em https://validar.iti.gov.br", 615, top + 204, 46, Brushes.Black, false, 1125);
            Text(draw, preview ? "Certificado escolhido ao assinar" : qualification.SealText,
                615, top + (showLink ? 272 : 204), 46, Brushes.Black, false, 1125);
        }
        var bitmap = new RenderTargetBitmap(Width, Height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var output = new MemoryStream();
        encoder.Save(output);
        return output.ToArray();
    }

    private static void Text(DrawingContext draw, string value, double x, double y, double size, Brush color, bool bold, double available)
    {
        var face = new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, bold ? FontWeights.Bold : FontWeights.Normal, FontStretches.Normal);
        FormattedText Create(double fontSize) => new(value, Culture, FlowDirection.LeftToRight, face, fontSize, color, 1);
        var text = Create(size);
        if (text.Width > available) text = Create(size * available / text.Width);
        draw.DrawText(text, new Point(x, y));
    }
}
