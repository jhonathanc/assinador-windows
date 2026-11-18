// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Jhonju.Assinador.Core;

public static class OriginalFileProtection
{
    public static bool IsOriginal(string original, string destination)
    {
        if (PadesSigner.PathsEqual(original, destination)) return true;
        if (!File.Exists(original) || !File.Exists(destination)) return false;
        try
        {
            using var source = File.OpenHandle(original, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var target = File.OpenHandle(destination, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return SameFile(source, target);
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    internal static void EnsureDifferent(SafeFileHandle originalHandle, string original, string destination)
    {
        if (PadesSigner.PathsEqual(original, destination)) throw new IOException("O PDF original não pode ser sobrescrito.");
        if (!File.Exists(destination)) return;
        using var target = File.OpenHandle(destination, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (SameFile(originalHandle, target)) throw new IOException("O destino aponta para o PDF original e não pode ser sobrescrito.");
    }

    private static bool SameFile(SafeFileHandle first, SafeFileHandle second)
    {
        if (GetFileInformationByHandleEx(first, 18, out var a, 24) && GetFileInformationByHandleEx(second, 18, out var b, 24))
            return a.VolumeSerial == b.VolumeSerial && a.FileIdLow == b.FileIdLow && a.FileIdHigh == b.FileIdHigh;
        // Some network file systems expose only the older 64-bit identifier.
        if (GetFileInformationByHandle(first, out var x) && GetFileInformationByHandle(second, out var y))
            return x.VolumeSerial == y.VolumeSerial && x.FileIndexHigh == y.FileIndexHigh && x.FileIndexLow == y.FileIndexLow;
        throw new IOException("Não foi possível verificar a identidade do arquivo.", new Win32Exception(Marshal.GetLastWin32Error()));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo { public ulong VolumeSerial, FileIdLow, FileIdHigh; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, FileIndexHigh, FileIndexLow;
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass, out FileIdInfo information, uint size);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo information);
}
