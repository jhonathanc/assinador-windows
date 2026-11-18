// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Interop;

namespace Jhonju.Assinador.Windows.Services;

/// <summary>Opens the Windows certificate chooser anew for every signing attempt.</summary>
public static class NativeCertificatePicker
{
    public static X509Certificate2? Select(Window owner, IReadOnlyList<X509Certificate2> certificates)
    {
        owner.Dispatcher.VerifyAccess();
        if (certificates.Count == 0) return null;
        var available = new X509Certificate2Collection(certificates.ToArray());
        var selected = X509Certificate2UI.SelectFromCollection(available,
            "Selecionar certificado pessoal",
            "Escolha o certificado para assinar esta cópia do PDF.",
            X509SelectionFlag.SingleSelection,
            new WindowInteropHelper(owner).EnsureHandle());
        try
        {
            // Clone the returned context, retaining its Windows private-key association.
            // No choice or private-key material is persisted by the application.
            return selected.Count == 0 ? null : new X509Certificate2(selected[0]);
        }
        finally
        {
            foreach (var certificate in selected) certificate.Dispose();
        }
    }
}
