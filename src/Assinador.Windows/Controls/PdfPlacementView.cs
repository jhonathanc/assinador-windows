// SPDX-License-Identifier: AGPL-3.0-only
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Jhonju.Assinador.Core;

namespace Jhonju.Assinador.Windows.Controls;

public sealed class PdfPlacementView : FrameworkElement
{
    private BitmapSource? pageImage;
    private BitmapSource? sealImage;
    private SignaturePlacement placement;
    private Point dragOffset;
    public event Action<SignaturePlacement>? PlacementChanged;
    public SignaturePlacement Placement => placement;
    public BitmapSource? PageImage => pageImage;

    public PdfPlacementView() { Focusable = true; Cursor = Cursors.SizeAll; }

    public void SetPage(BitmapSource image, int page)
    {
        pageImage = image;
        placement = new(page, .05, .05, .7, .1);
        ResizeSeal(.7);
        UpdatePlacement(placement with { Top = Math.Clamp(1 - placement.Height - .05, 0, 1 - placement.Height) });
    }

    public void SetSeal(BitmapSource image) { sealImage = image; InvalidateVisual(); }

    public void ResizeSeal(double width)
    {
        if (pageImage is null) return;
        width = Math.Clamp(width, .2, .95);
        var height = width * pageImage.PixelWidth / pageImage.PixelHeight * SealRendererRatio;
        if (height > .95) { width *= .95 / height; height = .95; }
        UpdatePlacement(placement with { Width = width, Height = height,
            Left = Math.Clamp(placement.Left, 0, 1 - width), Top = Math.Clamp(placement.Top, 0, 1 - height) });
    }

    private const double SealRendererRatio = 460.0 / 1800;

    protected override void OnRender(DrawingContext draw)
    {
        base.OnRender(draw);
        if (pageImage is null || ActualWidth <= 0 || ActualHeight <= 0) return;
        draw.DrawImage(pageImage, new Rect(0, 0, ActualWidth, ActualHeight));
        var box = SealBox();
        if (sealImage is not null) draw.DrawImage(sealImage, box);
        draw.DrawRectangle(null, new Pen(new SolidColorBrush(Color.FromRgb(0, 100, 210)), 1.5) { DashStyle = DashStyles.Dash }, box);
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        if (!IsEnabled || pageImage is null) return;
        Focus();
        var point = e.GetPosition(this);
        var box = SealBox();
        dragOffset = box.Contains(point) ? new Point(point.X - box.X, point.Y - box.Y) : new Point(box.Width / 2, box.Height / 2);
        CaptureMouse();
        MoveTo(point);
        e.Handled = true;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (IsMouseCaptured && e.LeftButton == MouseButtonState.Pressed) MoveTo(e.GetPosition(this));
    }
    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e) { ReleaseMouseCapture(); base.OnMouseLeftButtonUp(e); }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        var step = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) ? .02 : .005;
        var (dx, dy) = e.Key switch { Key.Left => (-step, 0d), Key.Right => (step, 0d), Key.Up => (0d, -step), Key.Down => (0d, step), _ => (0d, 0d) };
        if (dx == 0 && dy == 0) return;
        UpdatePlacement(placement with { Left = Math.Clamp(placement.Left + dx, 0, 1 - placement.Width), Top = Math.Clamp(placement.Top + dy, 0, 1 - placement.Height) });
        e.Handled = true;
    }

    private Rect SealBox() => new(placement.Left * ActualWidth, placement.Top * ActualHeight, placement.Width * ActualWidth, placement.Height * ActualHeight);
    private void MoveTo(Point point)
    {
        if (ActualWidth <= 0 || ActualHeight <= 0) return;
        UpdatePlacement(placement with { Left = Math.Clamp((point.X - dragOffset.X) / ActualWidth, 0, 1 - placement.Width),
            Top = Math.Clamp((point.Y - dragOffset.Y) / ActualHeight, 0, 1 - placement.Height) });
    }
    private void UpdatePlacement(SignaturePlacement value) { placement = value; InvalidateVisual(); PlacementChanged?.Invoke(value); }
}
