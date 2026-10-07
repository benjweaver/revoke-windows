using Microsoft.Win32;

namespace Revoke.Core;

/// <summary>A packaged app's startup task, or a Run key value. Machine-wide Run values are
/// for every user, and switching them needs admin rights.</summary>
public abstract record StartupItem
{
    public sealed record Task(string Family, string TaskId) : StartupItem;
    public sealed record Run(string Name, bool Machine, bool Wow64) : StartupItem;
}

public sealed record StartupEntry(Client Client, StartupItem Item, bool Enabled);

/// <summary>What starts when you sign in, switched the way Settings › Apps › Startup does.</summary>
public static class Startup
{
    const string Tasks = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData";
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string Run32Key = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    const string Approved = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    public static List<StartupEntry> Read(IEnumerable<Package> packages)
    {
        var entries = new List<StartupEntry>();
        foreach (var package in packages)
        {
            foreach (var (taskId, byDefault) in package.StartupTasks)
            {
                using var key = Registry.CurrentUser.OpenSubKey($@"{Tasks}\{package.Family}\{taskId}");
                // 0 disabled, 1 disabled by the user, 2 enabled, 3 disabled by policy,
                // 4 enabled by policy. A task never switched has no state yet.
                var enabled = key?.GetValue("State") is int state ? state is 2 or 4 : byDefault;
                entries.Add(new StartupEntry(Client.Package(package.Family), new StartupItem.Task(package.Family, taskId), enabled));
            }
        }
        foreach (var (root, machine, path, wow64) in new[]
        {
            (Registry.CurrentUser, false, RunKey, false),
            (Registry.LocalMachine, true, RunKey, false),
            (Registry.LocalMachine, true, Run32Key, true),
        })
        {
            using var key = root.OpenSubKey(path);
            if (key is null) continue;
            using var approved = root.OpenSubKey($@"{Approved}\{(wow64 ? "Run32" : "Run")}");
            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is not string command) continue;
                // The first byte is even while enabled and odd once switched off.
                var enabled = approved?.GetValue(name) is not byte[] { Length: > 0 } bytes || bytes[0] % 2 == 0;
                entries.Add(new StartupEntry(Client.FromPath(Client.ProgramInCommand(command)), new StartupItem.Run(name, machine, wow64), enabled));
            }
        }
        return entries;
    }

    /// <summary>Switches an item on or off without admin rights. Machine-wide ones go
    /// through <see cref="Elevated"/> instead.</summary>
    public static void Set(StartupItem item, bool enabled)
    {
        switch (item)
        {
            case StartupItem.Task task:
                using (var key = Registry.CurrentUser.CreateSubKey($@"{Tasks}\{task.Family}\{task.TaskId}"))
                    key.SetValue("State", enabled ? 2 : 1, RegistryValueKind.DWord);
                break;
            case StartupItem.Run { Machine: false } run:
                using (var key = Registry.CurrentUser.CreateSubKey($@"{Approved}\Run"))
                    key.SetValue(run.Name, Approval(enabled), RegistryValueKind.Binary);
                break;
            default:
                throw new InvalidOperationException("Needs admin rights.");
        }
    }

    /// <summary>StartupApproved's 12-byte format: a state byte, three zero bytes, and the
    /// FILETIME it was switched off (zero while on).</summary>
    public static byte[] Approval(bool enabled)
    {
        var bytes = new byte[12];
        bytes[0] = (byte)(enabled ? 2 : 3);
        if (!enabled) BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(bytes, 4);
        return bytes;
    }

    /// <summary>Where Windows keeps whether each machine-wide Run value is switched on.</summary>
    public static string ApprovedKey(bool wow64) => $@"{Approved}\{(wow64 ? "Run32" : "Run")}";
}
