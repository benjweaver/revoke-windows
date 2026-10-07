using System.ServiceProcess;
using Microsoft.Win32;

namespace Revoke.Core;

/// <param name="Start">2 automatic, 3 manual, 4 disabled.</param>
public sealed record Service(string Name, string DisplayName, Client Client, string Program, int Start, bool Running)
{
    public bool StartsWithWindows => Start == 2;

    /// <summary>Set-Service's name for a start value.</summary>
    public static string StartName(int start) => start switch
    {
        2 => "Automatic",
        4 => "Disabled",
        _ => "Manual",
    };
}

/// <summary>
/// Windows services an app installed. Claude's CoworkVMService and ChatGPT's
/// CodexSandboxService run as LocalSystem and start with Windows, so stopping the
/// app's own processes leaves them running. Stopping them, or changing how they
/// start, needs admin rights.
/// </summary>
public static class Services
{
    const string Root = @"SYSTEM\CurrentControlSet\Services";

    /// <summary>Every service whose program lives outside Windows' own folders. Drivers
    /// and services hosted in svchost are Windows' business, not an app's.</summary>
    public static List<Service> Read()
    {
        var services = new List<Service>();
        using var root = Registry.LocalMachine.OpenSubKey(Root);
        if (root is null) return services;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        foreach (var name in root.GetSubKeyNames())
        {
            using var key = root.OpenSubKey(name);
            // Bit 0x10 or 0x20 is a service in its own or a shared process; lower bits are drivers.
            if (key?.GetValue("Type") is not int type || (type & 0x30) == 0) continue;
            if (key.GetValue("ImagePath") is not string image) continue;
            var program = Client.ProgramInCommand(image);
            if (program.StartsWith(windows, StringComparison.OrdinalIgnoreCase)) continue;
            var display = key.GetValue("DisplayName") as string;
            services.Add(new Service(
                name,
                display is null || display.StartsWith('@') ? name : display,
                Client.FromPath(program),
                program,
                key.GetValue("Start") is int start ? start : 3,
                false));
        }
        return services;
    }

    /// <summary>Whether each service is running. Asking the service manager needs no admin rights.</summary>
    public static List<Service> WithStatus(IEnumerable<Service> services) =>
        services.Select(service =>
        {
            try
            {
                using var controller = new ServiceController(service.Name);
                return service with { Running = controller.Status != ServiceControllerStatus.Stopped };
            }
            catch (Exception e) when (e is InvalidOperationException or ArgumentException)
            {
                return service with { Running = false };
            }
        }).ToList();
}
