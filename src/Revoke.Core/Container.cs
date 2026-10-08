using System.Diagnostics;
using System.Management;
using Microsoft.Win32;

namespace Revoke.Core;

/// <summary>
/// Programs started from inside a packaged (MSIX) app, like a terminal in Claude Code or
/// Codex, can inherit its container. Windows then quietly keeps their registry and
/// AppData writes in that app's private storage: Revoke's settings, its sign-in entry,
/// and every privacy and startup switch it flips would change nothing for real. Revoke
/// checks for that when it starts, and relaunches itself outside.
/// </summary>
public static class Container
{
    const string ProbeKey = @"Software\Revoke";
    const uint HKEY_CURRENT_USER = 0x80000001;

    /// <summary>
    /// Whether this process's registry writes are being captured: it writes a value, then
    /// asks WMI, which reads the registry from a Windows service outside any container,
    /// whether the value is really there. False when WMI can't say.
    /// </summary>
    public static bool IsCaptured()
    {
        var name = $"ContainerProbe{Environment.ProcessId}";
        RegistryKey? key = null;
        try
        {
            key = Registry.CurrentUser.CreateSubKey(ProbeKey);
            key.SetValue(name, "1", RegistryValueKind.String);
            using var registry = new ManagementClass(@"\\.\root\default:StdRegProv");
            using var input = registry.GetMethodParameters("GetStringValue");
            input["hDefKey"] = HKEY_CURRENT_USER;
            input["sSubKeyName"] = ProbeKey;
            input["sValueName"] = name;
            using var output = registry.InvokeMethod("GetStringValue", input, null);
            return output?["sValue"] as string != "1";
        }
        catch (Exception e) when (e is ManagementException or UnauthorizedAccessException or IOException
            or System.Runtime.InteropServices.COMException)
        {
            return false;
        }
        finally
        {
            try
            {
                key?.DeleteValue(name, throwOnMissingValue: false);
                if (key?.ValueCount == 0 && key.SubKeyCount == 0)
                {
                    key.Dispose();
                    key = null;
                    Registry.CurrentUser.DeleteSubKey(ProbeKey, throwOnMissingSubKey: false);
                }
            }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException) { }
            key?.Dispose();
        }
    }

    /// <summary>Starts the program again through Explorer, which hands it to the desktop
    /// shell: that starts it as you'd start it yourself, outside any container.</summary>
    public static void RelaunchOutside(string program) =>
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{program}\"") { UseShellExecute = false });
}
