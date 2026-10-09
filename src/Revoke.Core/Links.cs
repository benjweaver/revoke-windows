using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace Revoke.Core;

/// <summary>
/// A way other programs open an app: a link scheme (claude://, codex://, claude-cli://) or
/// a file type, as registered in your part of the registry.
/// </summary>
/// <param name="Key">The class's key under HKCU\Software\Classes: "claude-cli", or a packaged
/// app's "AppX…" ProgID.</param>
/// <param name="Verb">The shell verb, usually "open".</param>
/// <param name="Scheme">The link scheme, for desktop programs' classes; packaged apps' ProgIDs
/// don't say which of the app's schemes they're for.</param>
/// <param name="Aumid">The packaged app it opens, to open it through Windows when the person says yes.</param>
/// <param name="IsFile">Opens files rather than links.</param>
/// <param name="Program">The desktop program it opens.</param>
/// <param name="Blocked">Revoke stands in for the app, and asks before opening it.</param>
/// <param name="Moved">Blocked, but by a Revoke.exe somewhere other than this one.</param>
public sealed record LinkHandler(Client Client, string Key, string Verb, string? Scheme, string? Aumid, bool IsFile,
    string? Program, bool Blocked, bool Moved = false);

/// <summary>
/// Links and files that open an app. A web page, an email or a document can open an agent
/// with a link that carries a prompt, while nobody's looking. Revoke can put itself in the
/// app's place for those, so Windows opens Revoke instead, which shows the link and opens
/// the app only if the person says so. The app's own entry is kept beside Revoke's, to put
/// back. All of it is in your part of the registry, so it needs no admin rights, and keeps
/// working while Revoke isn't running.
/// </summary>
public static class Links
{
    const string Classes = @"Software\Classes";
    /// <summary>Where Revoke keeps what it replaced, beside its own command.</summary>
    const string SavedDelegate = "RevokeDelegateExecute";
    const string SavedCommand = "RevokeCommand";
    public const string Flag = "--link";

    /// <summary>The Revoke.exe Windows opens in an app's place.</summary>
    public static string? Program { get; set; } = Environment.ProcessPath;

    /// <summary>Every packaged app's link and file ProgIDs, and every desktop program's link
    /// schemes, registered for this user.</summary>
    public static List<LinkHandler> Read()
    {
        var handlers = new List<LinkHandler>();
        using var classes = Registry.CurrentUser.OpenSubKey(Classes);
        if (classes is null) return handlers;
        foreach (var name in classes.GetSubKeyNames())
        {
            try
            {
                using var key = classes.OpenSubKey(name);
                if (key is null) continue;
                if (name.StartsWith("AppX", StringComparison.OrdinalIgnoreCase)) ReadPackaged(name, key, handlers);
                else if (key.GetValue("URL Protocol") is not null) ReadDesktop(name, key, handlers);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        }
        return handlers;
    }

    static void ReadPackaged(string name, RegistryKey key, List<LinkHandler> handlers)
    {
        using var shell = key.OpenSubKey("Shell");
        if (shell is null) return;
        foreach (var verb in shell.GetSubKeyNames())
        {
            using var verbKey = shell.OpenSubKey(verb);
            if (verbKey?.GetValue("AppUserModelID") is not string aumid) continue;
            var contract = verbKey.GetValue("ContractId") as string;
            if (contract is not ("Windows.Protocol" or "Windows.File")) continue;
            using var command = verbKey.OpenSubKey("command");
            if (command is null) continue;
            var family = aumid.Split('!')[0];
            handlers.Add(new LinkHandler(Client.Package(family), name, verb, null, aumid, contract == "Windows.File", null,
                IsOurs(command), Moved(command)));
        }
    }

    static void ReadDesktop(string name, RegistryKey key, List<LinkHandler> handlers)
    {
        using var command = key.OpenSubKey(@"shell\open\command");
        if (command is null) return;
        var blocked = IsOurs(command);
        var original = blocked ? command.GetValue(SavedCommand) as string : command.GetValue(null) as string;
        if (string.IsNullOrWhiteSpace(original)) return;
        var program = Client.ProgramInCommand(original);
        // A desktop entry for a packaged app (Electron writes one for Claude) opens the package.
        var client = Client.FromPath(program);
        handlers.Add(new LinkHandler(client, name, "open", name, null, false, program, blocked, Moved(command)));
    }

    /// <summary>Whether this command is Revoke standing in for the app.</summary>
    static bool IsOurs(RegistryKey command) =>
        command.GetValue("DelegateExecute") is null
        && command.GetValue(null) is string line
        && line.Contains($" {Flag} ", StringComparison.Ordinal)
        && Path.GetFileName(Client.ProgramInCommand(line)).Equals("Revoke.exe", StringComparison.OrdinalIgnoreCase);

    static bool Moved(RegistryKey command) =>
        IsOurs(command) && Program is { } program
        && !Client.ProgramInCommand((string)command.GetValue(null)!).Equals(program, StringComparison.OrdinalIgnoreCase);

    static string CommandFor(string revoke, LinkHandler handler) =>
        $"\"{revoke}\" {Flag} \"{handler.Key}\" \"{handler.Verb}\" \"%1\"";

    static string CommandKey(LinkHandler handler) =>
        $@"{Classes}\{handler.Key}\{(handler.Aumid is null ? "shell" : "Shell")}\{handler.Verb}\command";

    /// <summary>Puts Revoke in the app's place for this handler. Run again after the app
    /// registers itself again, it saves the app's new entry; run again after Revoke moves,
    /// it points at the new Revoke.</summary>
    public static void Block(LinkHandler handler)
    {
        // Only a real Revoke.exe can stand in for an app; a test host can't answer links.
        var revoke = Program is { } program && Path.GetFileName(program).Equals("Revoke.exe", StringComparison.OrdinalIgnoreCase)
            ? program : throw new InvalidOperationException("Only Revoke.exe can stand in for an app's links.");
        using var command = Registry.CurrentUser.OpenSubKey(CommandKey(handler), writable: true)
            ?? throw new IOException($"{handler.Key} is gone.");
        if (!IsOurs(command))
        {
            if (command.GetValue("DelegateExecute") is string delegateExecute)
            {
                command.SetValue(SavedDelegate, delegateExecute, RegistryValueKind.String);
                command.DeleteValue("DelegateExecute");
            }
            else if (command.GetValue(null, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string original)
            {
                command.SetValue(SavedCommand, original, command.GetValueKind("") == RegistryValueKind.ExpandString
                    ? RegistryValueKind.ExpandString : RegistryValueKind.String);
            }
        }
        command.SetValue(null, CommandFor(revoke, handler), RegistryValueKind.String);
    }

    /// <summary>Puts the app's own entry back.</summary>
    public static void Unblock(LinkHandler handler)
    {
        using var command = Registry.CurrentUser.OpenSubKey(CommandKey(handler), writable: true);
        if (command is null || !IsOurs(command)) return;
        if (command.GetValue(SavedDelegate) is string delegateExecute)
        {
            command.SetValue("DelegateExecute", delegateExecute, RegistryValueKind.String);
            command.DeleteValue(SavedDelegate);
            command.DeleteValue("", throwOnMissingValue: false);
        }
        else if (command.GetValue(SavedCommand, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string original)
        {
            command.SetValue(null, original, command.GetValueKind(SavedCommand));
            command.DeleteValue(SavedCommand);
        }
    }

    /// <summary>Puts every app's own entry back, as when Revoke is uninstalled.</summary>
    public static int UnblockAll()
    {
        var count = 0;
        foreach (var handler in Read().Where(h => h.Blocked))
        {
            try
            {
                Unblock(handler);
                count++;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return count;
    }

    // Opening a link Revoke stood in for

    /// <summary>
    /// Windows opened Revoke in an app's place. Shows the person what's being opened and by
    /// whom, and opens the app only if they say so. The link is shown whole, since it's the
    /// part that can carry instructions for the agent.
    /// </summary>
    public static void Handle(string key, string verb, string target)
    {
        var handler = Read().FirstOrDefault(h => h.Key.Equals(key, StringComparison.OrdinalIgnoreCase)
            && h.Verb.Equals(verb, StringComparison.OrdinalIgnoreCase));
        if (handler is null)
        {
            Native.MessageBoxW(0, "Revoke stopped something opening an app, but the app's entry is gone, so it can't be opened from here.",
                "Revoke", Native.MB_OK | Native.MB_ICONWARNING | Native.MB_SETFOREGROUND | Native.MB_TOPMOST);
            return;
        }
        var appName = NameOf(handler);
        var opener = Opener();
        var who = opener is null ? "Something" : opener;
        string message;
        if (handler.IsFile)
        {
            message = $"{who} wants to open this file in {appName}:\n\n{Shown(target)}\n\n"
                + $"Open it only if you just opened it yourself. A file can carry instructions for {appName}.";
        }
        else
        {
            message = $"{who} wants to open {appName} with this link:\n\n{Shown(Readable(target))}\n\n"
                + $"Open it only if you just clicked it yourself. A link can carry instructions for {appName}, "
                + "like a prompt for it to run.";
        }
        var answer = Native.MessageBoxW(0, message + $"\n\nOpen {appName}?", "Revoke",
            Native.MB_YESNO | Native.MB_ICONWARNING | Native.MB_DEFBUTTON2 | Native.MB_SETFOREGROUND | Native.MB_TOPMOST);
        if (answer != Native.IDYES) return;
        try
        {
            Open(handler, target);
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or COMException or System.ComponentModel.Win32Exception)
        {
            Native.MessageBoxW(0, $"Couldn't open {appName}: {e.Message}", "Revoke",
                Native.MB_OK | Native.MB_ICONERROR | Native.MB_SETFOREGROUND);
        }
    }

    /// <summary>Opens the app the way Windows would have, with the link or file as its
    /// argument: packaged apps through Windows' activation manager, which doesn't go through
    /// the entry Revoke replaced, and desktop programs with their own command. (Windows
    /// won't hand a link to a packaged desktop app any other way: it takes it on its command
    /// line, as the entry's Parameters say.)</summary>
    static void Open(LinkHandler handler, string target)
    {
        if (!IsSafeArgument(target) || (handler.Aumid is null && !handler.IsFile && !IsSafeLink(target, handler.Scheme)))
            throw new InvalidOperationException("it isn't something Revoke can pass on safely.");
        if ((handler.Aumid ?? PackagedApp(handler.Client)) is { } aumid)
        {
            using var verb = Registry.CurrentUser.OpenSubKey($@"{Classes}\{handler.Key}\Shell\{handler.Verb}");
            var parameters = verb?.GetValue("Parameters") as string is { Length: > 0 } p ? p : "\"%1\"";
            Activate(aumid, Substitute(parameters, target));
            return;
        }
        using var command = Registry.CurrentUser.OpenSubKey(CommandKey(handler));
        var original = command?.GetValue(SavedCommand) as string ?? throw new IOException("the app's own entry is gone.");
        var program = Client.ProgramInCommand(original);
        var rest = original.TrimStart();
        rest = rest.StartsWith('"') ? rest[(rest.IndexOf('"', 1) + 1)..] : rest[(rest.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) + 4)..];
        Process.Start(new ProcessStartInfo(program, Substitute(rest, target).Trim()) { UseShellExecute = false });
    }

    static string Substitute(string parameters, string target) =>
        parameters.Replace("%1", target).Replace("%L", target).Replace("%l", target).Replace("%*", target);

    /// <summary>The package's first app, for a desktop entry that opens a packaged app.</summary>
    static string? PackagedApp(Client client) =>
        client.Family is not null && Packages.Installed().FirstOrDefault(p => p.Family == client.Family) is { Apps: [var app, ..] } package
            ? $"{package.Family}!{app}" : null;

    /// <summary>The app's name as the panel shows it.</summary>
    static string NameOf(LinkHandler handler)
    {
        if (handler.Client.Family is { } family)
            return Packages.Installed().FirstOrDefault(p => p.Family == family)?.Name ?? family.Split('_')[0];
        using var command = Registry.CurrentUser.OpenSubKey(CommandKey(handler));
        var program = Client.ProgramInCommand(command?.GetValue(SavedCommand) as string ?? "");
        if (Model.KnownName(program) is { } known) return known;
        try
        {
            var description = FileVersionInfo.GetVersionInfo(program).FileDescription?.Trim();
            if (!string.IsNullOrEmpty(description)) return description;
        }
        catch (FileNotFoundException) { }
        return Path.GetFileNameWithoutExtension(program);
    }

    /// <summary>Something that can go into a command line as one quoted argument: no quotes
    /// or control characters to break out of the quotes with. Browsers escape both in links,
    /// and Windows paths can't hold them.</summary>
    internal static bool IsSafeArgument(string target) =>
        target.Length > 0 && !target.Any(c => c == '"' || char.IsControl(c));

    /// <summary>A link for this scheme that can go into a command line as one argument.</summary>
    internal static bool IsSafeLink(string target, string? scheme) =>
        scheme is not null
        && target.StartsWith(scheme + ":", StringComparison.OrdinalIgnoreCase)
        && IsSafeArgument(target);

    /// <summary>The link with %-escapes decoded, so a prompt in it reads as text.</summary>
    internal static string Readable(string link)
    {
        try { return Uri.UnescapeDataString(link.Replace('+', ' ')); }
        catch (UriFormatException) { return link; }
    }

    /// <summary>
    /// Text safe to show: characters that reorder or hide text (right-to-left overrides,
    /// zero-width spaces) are shown as escapes, so a link can't make itself look like
    /// something else, and very long text is cut.
    /// </summary>
    internal static string Shown(string text)
    {
        const int max = 1500;
        var shown = new StringBuilder();
        foreach (var c in text)
        {
            if (shown.Length >= max)
            {
                shown.Append($"… ({text.Length - max} more characters)");
                break;
            }
            var hidden = char.IsControl(c) && c is not ('\n' or '\t')
                || c is >= '​' and <= '‏' or >= '‪' and <= '‮' or >= '⁦' and <= '⁩' or '﻿';
            if (hidden) shown.Append($"\\u{(int)c:X4}");
            else shown.Append(c);
        }
        return shown.ToString();
    }

    /// <summary>The program that asked Windows to open the link, by name, when that's
    /// something the person would recognise: Chrome, Outlook. Windows' own brokers, which
    /// pass links on for packaged apps, say nothing useful.</summary>
    static string? Opener()
    {
        var procs = Processes.List();
        var self = procs.FirstOrDefault(p => p.Pid == Environment.ProcessId);
        var parent = self is null ? null : procs.FirstOrDefault(p => p.Pid == self.Parent && p.Started <= self.Started);
        if (parent?.Path is not { } path) return null;
        var file = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
        if (file is "svchost" or "sihost" or "runtimebroker" or "dllhost" or "openwith" or "launchwinapp") return null;
        if (file == "explorer") return "File Explorer";
        try
        {
            var description = FileVersionInfo.GetVersionInfo(path).FileDescription?.Trim();
            return string.IsNullOrEmpty(description) ? Path.GetFileName(path) : description;
        }
        catch (FileNotFoundException)
        {
            return Path.GetFileName(path);
        }
    }

    // Windows' activation manager

    static void Activate(string aumid, string arguments)
    {
        var manager = (IApplicationActivationManager)new ApplicationActivationManager();
        Marshal.ThrowExceptionForHR(manager.ActivateApplication(aumid, arguments, 0, out _));
    }

    [ComImport, Guid("2e941141-7f97-4756-ba1d-9decde894a3d"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IApplicationActivationManager
    {
        [PreserveSig] int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string aumid, [MarshalAs(UnmanagedType.LPWStr)] string? arguments, int options, out uint pid);
        [PreserveSig] int ActivateForFile([MarshalAs(UnmanagedType.LPWStr)] string aumid, nint items, [MarshalAs(UnmanagedType.LPWStr)] string verb, out uint pid);
        [PreserveSig] int ActivateForProtocol([MarshalAs(UnmanagedType.LPWStr)] string aumid, nint items, out uint pid);
    }

    [ComImport, Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C")]
    class ApplicationActivationManager { }
}
