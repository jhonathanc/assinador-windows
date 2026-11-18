// SPDX-License-Identifier: AGPL-3.0-only
using iText.Kernel.Geom;

namespace Jhonju.Assinador.Core;

/// <summary>Fractions of the displayed, rotated CropBox, measured from the upper left.</summary>
public readonly record struct SignaturePlacement(int Page, double Left, double Top, double Width, double Height)
{
    public Rectangle ToPdfRectangle(Rectangle crop, int rotation)
    {
        var values = new[] { Left, Top, Width, Height };
        if (Page < 1 || values.Any(x => !double.IsFinite(x)) || Left < 0 || Top < 0 || Width <= 0 || Height <= 0 ||
            Left + Width > 1.00001 || Top + Height > 1.00001)
            throw new ArgumentException("Posição do selo fora dos limites da página.");
        var (x, y, width, height) = ((rotation % 360 + 360) % 360) switch
        {
            0 => (Left, 1 - Top - Height, Width, Height),
            90 => (Top, Left, Height, Width),
            180 => (1 - Left - Width, Top, Width, Height),
            270 => (1 - Top - Height, 1 - Left - Width, Height, Width),
            _ => throw new ArgumentException("Rotação de página não suportada.")
        };
        return new Rectangle((float)(crop.GetLeft() + x * crop.GetWidth()), (float)(crop.GetBottom() + y * crop.GetHeight()),
            (float)(width * crop.GetWidth()), (float)(height * crop.GetHeight()));
    }
}
