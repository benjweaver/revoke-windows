using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace Revoke.Core;

public sealed record HelperRequest(List<ElevatedOp> Ops);

/// <param name="Error">The first change that failed, or null.</param>
/// <param name="Rejected">Indexes of the changes the helper won't make, for a UAC prompt to make instead.</param>
public sealed record HelperReply(string? Error, List<int> Rejected);

/// <summary>
/// Revoke Helper: a Windows service, installed once, that makes Revoke's admin changes
/// without a UAC prompt each time. It runs as SYSTEM from Program Files, where only
/// admins can replace it, and listens on a pipe only the user who installed it can
/// open. It checks every change itself (see <see cref="HelperPolicy"/>), makes the ones it
/// allows through <see cref="AdminChanges"/>, and only
/// tightens the firewall, undoes its own changes, and stops or sets to Manual the
/// services of watched developers. Anything else gets the UAC prompt as before.
/// </summary>
public static unsafe partial class Helper
{
    public const string ServiceName = "RevokeHelper";
    public const string PipeName = "dev.benjweaver.Revoke.Helper";

    public static string InstallPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Revoke", "Helper", "RevokeHelper.exe");

    /// <summary>Where the helper keeps what it changed, readable only by admins and SYSTEM.</summary>
    public static string StateFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Revoke");

    /// <summary>The helper beside Revoke.exe, which installing copies into Program Files.</summary>
    public static string BundledPath => Path.Combine(AppContext.BaseDirectory, "Helper", "RevokeHelper.exe");

    public static JsonSerializerOptions Json => Elevated.Json;

    public static bool IsInstalled
    {
        get
        {
            try
            {
                using var service = new ServiceController(ServiceName);
                _ = service.Status;
                return true;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
    }

    /// <summary>Whether the helper's service is running, which any user may ask.</summary>
    public static bool IsRunning
    {
        get
        {
            try
            {
                using var service = new ServiceController(ServiceName);
                return service.Status == ServiceControllerStatus.Running;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
    }

    /// <summary>Whether the installed helper is the one beside Revoke.exe. Installing copies
    /// it, keeping its size and modified time.</summary>
    public static bool IsCurrent
    {
        get
        {
            var (installed, bundled) = (new FileInfo(InstallPath), new FileInfo(BundledPath));
            return !bundled.Exists || (installed.Exists && installed.Length == bundled.Length
                && installed.LastWriteTimeUtc == bundled.LastWriteTimeUtc);
        }
    }

    /// <summary>Installs or updates the helper service for this user, behind one UAC prompt.</summary>
    public static string? Install() => Elevated.RunAsAdmin(["--install", WindowsIdentity.GetCurrent().User!.Value]);

    /// <summary>Removes the helper service, behind one UAC prompt.</summary>
    public static string? Uninstall() => Elevated.RunAsAdmin(["--uninstall"]);

    /// <summary>Hands the changes to the helper. Null if it isn't there to ask.</summary>
    public static HelperReply? Send(IReadOnlyCollection<ElevatedOp> ops)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
            pipe.Connect(1500);
            // Anyone can create a pipe by this name while the helper isn't running; only
            // the helper in Program Files gets told anything.
            if (!ServerIsHelper(pipe)) return null;
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            writer.WriteLine(JsonSerializer.Serialize(new HelperRequest([.. ops]), Json));
            var line = reader.ReadLine();
            return line is null ? null : JsonSerializer.Deserialize<HelperReply>(line, Json);
        }
        catch (Exception e) when (e is System.TimeoutException or IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether the pipe's server is the RevokeHelper service. Users can't read a SYSTEM
    /// process's path, but anyone can ask the service manager which process a service
    /// runs as, and only an admin can register that service or point it elsewhere.
    /// </summary>
    static bool ServerIsHelper(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid) || pid == 0) return false;
        return ServiceProcessId(ServiceName) == pid;
    }

    /// <summary>The process a service is running as, which any user may ask the service manager.</summary>
    internal static uint? ServiceProcessId(string name)
    {
        var manager = OpenSCManagerW(null, null, 0x1); // SC_MANAGER_CONNECT
        if (manager == 0) return null;
        try
        {
            var service = OpenServiceW(manager, name, 0x4); // SERVICE_QUERY_STATUS
            if (service == 0) return null;
            try
            {
                SERVICE_STATUS_PROCESS status;
                return QueryServiceStatusEx(service, 0, &status, (uint)sizeof(SERVICE_STATUS_PROCESS), out _) // SC_STATUS_PROCESS_INFO
                    ? status.dwProcessId : null;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode,
            dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(nint pipe, out uint processId);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint OpenServiceW(nint manager, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceStatusEx(nint service, int level, SERVICE_STATUS_PROCESS* buffer, uint size, out uint needed);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint handle);

    /// <summary>Creates the state folder so only SYSTEM and administrators can open it.</summary>
    public static void SecureStateFolder()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        var folder = new DirectoryInfo(StateFolder);
        if (folder.Exists) folder.SetAccessControl(security);
        else folder.Create(security);
    }
}

/// <summary>What the helper changed, so it only ever undoes its own changes.</summary>
public sealed class HelperState
{
    /// <summary>Inbound rules it switched off.</summary>
    public HashSet<string> DisabledRules { get; set; } = [];
    /// <summary>How services started before it set them to Manual.</summary>
    public Dictionary<string, int> ServiceStarts { get; set; } = [];

    static string FilePath => Path.Combine(Helper.StateFolder, "helper-state.json");

    public static HelperState Load()
    {
        try { return JsonSerializer.Deserialize<HelperState>(File.ReadAllText(FilePath)) ?? new(); }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return new(); }
    }

    public void Save() => File.WriteAllText(FilePath, JsonSerializer.Serialize(this));
}

/// <summary>
/// What the helper agrees to do without a UAC prompt. The pipe only lets the installing
/// user in, but any program running as that user could talk to it, so the helper only
/// makes changes that tighten things or undo its own:
/// <list type="bullet">
/// <item>switch off inbound allow rules, and back on only the ones it switched off;</item>
/// <item>add and remove rules in Revoke's own firewall group;</item>
/// <item>stop, or set to Manual, services from watched developers (Anthropic and OpenAI),
/// and put back only start types it changed;</item>
/// <item>switch off those developers' machine-wide startup entries, and back on.</item>
/// </list>
/// Services and machine-wide startup entries can only be made by admins, so naming
/// one can't trick the helper into touching something an admin didn't install.
/// </summary>
public sealed class HelperPolicy
{
    public const int MaxOps = 500;

    readonly Dictionary<string, FirewallRule> rules;
    readonly Dictionary<string, Service> services;
    readonly Dictionary<(bool Wow64, string Name), string> machineStartup;
    readonly HelperState state;
    readonly Func<string, string?> publisherOf;

    public HelperPolicy(IEnumerable<FirewallRule> rules, IEnumerable<Service> services,
        IEnumerable<(bool Wow64, string Name, string Program)> machineStartup, HelperState state, Func<string, string?> publisherOf)
    {
        this.rules = rules.GroupBy(r => r.Id).ToDictionary(g => g.Key, g => g.First());
        this.services = services.GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        this.machineStartup = machineStartup.GroupBy(e => (e.Wow64, e.Name)).ToDictionary(g => g.Key, g => g.First().Program);
        this.state = state;
        this.publisherOf = publisherOf;
    }

    /// <summary>The policy for this PC as it is now.</summary>
    public static HelperPolicy ForThisPc(HelperState state) => new(
        Firewall.Read() ?? [],
        Services.Read(),
        Startup.Read([])
            .Select(e => e.Item)
            .OfType<StartupItem.Run>()
            .Where(r => r.Machine)
            .Select(r => (r.Wow64, r.Name, Program: MachineRunProgram(r))),
        state,
        PublisherOf);

    /// <summary>Null if the helper may make the change, or why not.</summary>
    public string? Check(ElevatedOp op) => op switch
    {
        ElevatedOp.SetRuleEnabled { Enabled: false } r =>
            rules.TryGetValue(r.Id, out var rule) && rule.Inbound && rule.Allow ? null : "only inbound allow rules can be switched off",
        ElevatedOp.SetRuleEnabled { Enabled: true } r =>
            state.DisabledRules.Contains(r.Id) ? null : "only rules the helper switched off can be switched on",
        ElevatedOp.BlockLocalNetwork b =>
            Path.IsPathFullyQualified(b.Program) && File.Exists(b.Program) && b.Label.Length <= 200 && b.ClientKey.Length <= 1000
                ? null : "not a program on this PC",
        ElevatedOp.RemoveBlocks r => r.ClientKey.Length <= 1000 ? null : "not a client",
        ElevatedOp.StopService s => WatchedService(s.Name),
        ElevatedOp.SetServiceStart s => WatchedService(s.Name)
            ?? (s.Start == 3 || (state.ServiceStarts.TryGetValue(s.Name, out var original) && original == s.Start)
                ? null : "only Manual, or the start type the helper changed it from"),
        ElevatedOp.SetMachineStartup m => MachineStartup(m),
        _ => "the helper doesn't do that",
    };

    string? WatchedService(string name) =>
        services.TryGetValue(name, out var service) && Watched(service.Program) ? null : "not a watched developer's service";

    string? MachineStartup(ElevatedOp.SetMachineStartup m) =>
        machineStartup.TryGetValue((m.Wow64, m.Name), out var program) && Watched(program)
            ? null : "not a watched developer's startup entry";

    bool Watched(string program) => Settings.WatchedByDefault(Client.FromPath(program), publisherOf(program) ?? "");

    static string MachineRunProgram(StartupItem.Run run)
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(run.Wow64
            ? @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            : @"Software\Microsoft\Windows\CurrentVersion\Run");
        return key?.GetValue(run.Name) is string command ? Client.ProgramInCommand(command) : "";
    }

    /// <summary>Who published a program: its package's publisher if it's inside
    /// Program Files\WindowsApps (which only Windows can write to), or its signer.</summary>
    public static string? PublisherOf(string program)
    {
        string full;
        try { full = Path.GetFullPath(program); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        var apps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps") + "\\";
        if (full.StartsWith(apps, StringComparison.OrdinalIgnoreCase))
        {
            var folder = full[apps.Length..].Split('\\')[0];
            try
            {
                var manifest = XDocument.Load(Path.Combine(apps, folder, "AppxManifest.xml"));
                return manifest.Descendants().FirstOrDefault(e => e.Name.LocalName == "PublisherDisplayName")?.Value;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Xml.XmlException)
            {
                return null;
            }
        }
        return Signer.Organization(full);
    }
}
