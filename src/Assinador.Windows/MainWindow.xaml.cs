// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Jhonju.Assinador.Core;
using Jhonju.Assinador.Windows.Services;
using Microsoft.Win32;

namespace Jhonju.Assinador.Windows;

public partial class MainWindow : Window
{
    private PdfPreviewService previewService = new();
    private readonly TrustCatalog authorities = TrustCatalog.LoadBundled();
    private readonly string session = Path.Combine(Path.GetTempPath(), "Jhonju-Assinador", Guid.NewGuid().ToString("N"));
    private string? workingSource;
    private string? originalPath;
    private int currentPage = 1;
    private bool busy;
    private IReadOnlyList<string> details = [];

    public MainWindow()
    {
        InitializeComponent();
        Directory.CreateDirectory(session);
        Preview.SetSeal(PdfPreviewService.Decode(SealRenderer.Placeholder()));
        Loaded += async (_, _) =>
        {
            var argument = Environment.GetCommandLineArgs().Skip(1).FirstOrDefault();
            if (argument is not null && File.Exists(argument) && Path.GetExtension(argument).Equals(".pdf", StringComparison.OrdinalIgnoreCase))
                await OpenPdfAsync(argument);
        };
    }

    private async void OpenClick(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Title = "Abrir PDF", Filter = "Documento PDF (*.pdf)|*.pdf", CheckFileExists = true, Multiselect = false, RestoreDirectory = true };
        if (picker.ShowDialog(this) == true) await OpenPdfAsync(picker.FileName);
    }

    public async Task OpenPdfAsync(string path)
    {
        if (busy) return;
        SetBusy(true, "Abrindo PDF…");
        try
        {
            var copy = Path.Combine(session, "input-" + Guid.NewGuid().ToString("N") + ".pdf");
            await Task.Run(() => File.Copy(path, copy, false));
            // Load into a fresh renderer first: a failed open preserves the previous document and placement.
            var check = new PdfPreviewService();
            await check.OpenAsync(copy);
            var image = await check.RenderAsync(1);
            previewService = check;
            originalPath = Path.GetFullPath(path);
            workingSource = copy;
            currentPage = 1;
            FileName.Text = Path.GetFileName(path);
            FileName.ToolTip = originalPath;
            EmptyHint.Visibility = Visibility.Collapsed;
            Preview.Visibility = Visibility.Visible;
            Preview.SetPage(image, 1);
            Preview.SetSeal(PdfPreviewService.Decode(SealRenderer.Placeholder()));
            SealSize.Value = 70;
            details = [];
            DetailsButton.Visibility = Visibility.Collapsed;
            UpdatePreviewSize();
            Status.Text = "Clique no PDF ou arraste o selo. Ajuste o tamanho antes de assinar.";
        }
        catch (Exception exception) { ShowError(exception); }
        finally { SetBusy(false); }
    }

    private async void SignClick(object sender, RoutedEventArgs e)
    {
        if (busy || workingSource is null || originalPath is null) return;
        var icpBrasilOnly = (Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.None;
        var destination = new SaveFileDialog
        {
            Title = "Salvar cópia assinada", Filter = "Documento PDF (*.pdf)|*.pdf", AddExtension = true, DefaultExt = ".pdf",
            FileName = Path.GetFileNameWithoutExtension(originalPath) + "_assinado.pdf",
            InitialDirectory = Path.GetDirectoryName(originalPath), OverwritePrompt = true, RestoreDirectory = true
        };
        destination.FileOk += (_, args) =>
        {
            try
            {
                if (!OriginalFileProtection.IsOriginal(originalPath, destination.FileName)) return;
                MessageBox.Show(this, "O PDF original não pode ser sobrescrito. Escolha outra pasta ou outro nome.", "Salvar cópia", MessageBoxButton.OK, MessageBoxImage.Information);
                args.Cancel = true;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                MessageBox.Show(this, exception.Message, "Verificar destino", MessageBoxButton.OK, MessageBoxImage.Warning);
                args.Cancel = true;
            }
        };
        if (destination.ShowDialog(this) != true) { Status.Text = "Assinatura cancelada. O original foi preservado."; return; }
        var destinationPath = Path.GetFullPath(destination.FileName);
        var overwriteExisting = File.Exists(destinationPath);
        SetBusy(true, "Lendo certificados disponíveis no Windows…");
        IReadOnlyList<X509Certificate2> candidates = [];
        try
        {
            Preview.SetSeal(PdfPreviewService.Decode(SealRenderer.Placeholder()));
            details = [];
            DetailsButton.Visibility = Visibility.Collapsed;
            var trust = new CertificateTrustService(authorities);
            candidates = await Task.Run(() => CertificateCatalog.Read(trust, icpBrasilOnly));
            if (candidates.Count == 0) throw new InvalidOperationException(icpBrasilOnly
                ? "Nenhum certificado válido com chave privada RSA/EC e cadeia reconhecida até uma raiz ICP-Brasil foi encontrado. Verifique a instalação do certificado e de sua cadeia, ou conecte o token com o respectivo driver."
                : "Nenhum certificado válido com chave privada RSA/EC foi encontrado. Instale-o em Pessoal ou conecte seu token com o respectivo driver.");
            Status.Text = "Selecione o certificado para esta assinatura.";
            using var certificate = NativeCertificatePicker.Select(this, candidates);
            if (certificate is null)
            {
                Status.Text = "Assinatura cancelada. Nenhum arquivo foi criado.";
                return;
            }
            Status.Text = "Verificando cadeia, validade e revogação…";
            var date = DateTimeOffset.Now;
            var qualification = await Task.Run(() => trust.Evaluate(certificate, date));
            var identity = CertificateIdentity.From(certificate);
            var seal = SealRenderer.Render(identity, date, qualification);
            Preview.SetSeal(PdfPreviewService.Decode(seal));
            var placement = Preview.Placement;
            var reason = Reason.Text;
            var location = Location.Text;
            var signedWorkingCopy = Path.Combine(session, "signed-" + Guid.NewGuid().ToString("N") + ".pdf");
            Status.Text = "Assinando e salvando a cópia… O provedor do certificado pode solicitar o PIN.";
            await Task.Run(() =>
            {
                new PadesSigner().Sign(workingSource, signedWorkingCopy, certificate, qualification.Chain, seal, placement, date, reason, location);
                CopyPublisher.Publish(signedWorkingCopy, destinationPath, originalPath, overwriteExisting);
            });
            details = qualification.Details;
            DetailsButton.Visibility = Visibility.Visible;
            Status.Text = $"Cópia salva: {destinationPath}\n{qualification.Explanation}";
        }
        catch (Exception exception) { ShowError(exception); }
        finally
        {
            foreach (var candidate in candidates) candidate.Dispose();
            SetBusy(false);
        }
    }

    private async Task ChangePageAsync(int number)
    {
        if (busy || workingSource is null || number < 1 || number > previewService.PageCount) return;
        SetBusy(true, "Carregando página…");
        try
        {
            var image = await previewService.RenderAsync(number);
            currentPage = number;
            Preview.SetPage(image, number);
            Preview.ResizeSeal(SealSize.Value / 100);
            UpdatePreviewSize();
            Status.Text = "Posicione o selo nesta página.";
        }
        catch (Exception exception) { ShowError(exception); }
        finally { SetBusy(false); }
    }

    private async void PreviousClick(object sender, RoutedEventArgs e) => await ChangePageAsync(currentPage - 1);
    private async void NextClick(object sender, RoutedEventArgs e) => await ChangePageAsync(currentPage + 1);
    private void SealSizeChanged(object sender, RoutedPropertyChangedEventArgs<double> e) { if (Preview is not null) Preview.ResizeSeal(e.NewValue / 100); }
    private void ZoomChanged(object sender, SelectionChangedEventArgs e) => UpdatePreviewSize();
    private void PreviewSizeChanged(object sender, SizeChangedEventArgs e) => UpdatePreviewSize();

    private void UpdatePreviewSize()
    {
        if (Preview?.PageImage is not { } bitmap || PreviewScroll is null || Zoom is null) return;
        var width = Math.Max(100, PreviewScroll.ActualWidth - 48);
        var height = Math.Max(100, PreviewScroll.ActualHeight - 48);
        var zoom = Zoom.SelectedIndex switch { 1 => 1.5, 2 => 2, 3 => 3, _ => 1 };
        var scale = Math.Min(width / bitmap.PixelWidth, height / bitmap.PixelHeight) * zoom;
        Preview.Width = bitmap.PixelWidth * scale;
        Preview.Height = bitmap.PixelHeight * scale;
    }

    private void SetBusy(bool value, string? message = null)
    {
        busy = value;
        OpenButton.IsEnabled = !value;
        SignButton.IsEnabled = !value && workingSource is not null;
        PageTools.IsEnabled = !value && workingSource is not null;
        Options.IsEnabled = !value;
        Preview.IsEnabled = !value;
        PreviousButton.IsEnabled = currentPage > 1;
        NextButton.IsEnabled = currentPage < previewService.PageCount;
        PageLabel.Text = $"Página {(workingSource is null ? 0 : currentPage)} / {previewService.PageCount}";
        Progress.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
        if (message is not null) Status.Text = message;
    }

    private void ShowError(Exception exception)
    {
        Status.Text = "Não foi possível concluir: " + exception.Message;
        MessageBox.Show(this, exception.Message, "Assinador PDF", MessageBoxButton.OK, MessageBoxImage.Warning);
    }
    private void DetailsClick(object sender, RoutedEventArgs e) => MessageBox.Show(this, string.Join("\n\n", details), "Verificação do certificado", MessageBoxButton.OK, MessageBoxImage.Information);
    private void AboutClick(object sender, RoutedEventArgs e) => MessageBox.Show(this,
        "Assinador PDF · Jhonju · 0.1.3\n\nCódigo aberto em C# / WPF / .NET 10.\n" +
        "Utiliza iText Community 9.6.0, © Apryse Group NV, sob GNU AGPL v3. Consulte LICENSE, NOTICE e README.\n\n" +
        "O PDF e a chave privada permanecem no computador. A rede é usada para verificar a cadeia e a revogação do certificado. ",
        "Sobre", MessageBoxButton.OK, MessageBoxImage.Information);

    private void WindowClosing(object? sender, CancelEventArgs e)
    {
        if (!busy) return;
        e.Cancel = true;
        Status.Text += "\nAguarde a operação terminar antes de fechar o aplicativo.";
    }
    private void WindowClosed(object? sender, EventArgs e)
    {
        authorities.Dispose();
        try { Directory.Delete(session, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
