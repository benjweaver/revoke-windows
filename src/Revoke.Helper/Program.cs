using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using Revoke.Core;

namespace RevokeHelper;

/// <summary>
/// Revoke Helper. One program with four jobs:
/// <list type="bullet">
/// <item><c>--user &lt;SID&gt;</c>: the Windows service, serving that user (how it's installed).</item>
/// <item><c>--report &lt;file&gt; --apply &lt;changes&gt;</c>: makes one set of changes, run as admin
/// by Revoke after a UAC prompt, when the service isn't installed or declines them.</item>
/// <item><c>--report &lt;file&gt; --install &lt;SID&gt;</c> and <c>--uninstall</c>: installs or removes the service.</item>
/// </list>
/// Failures go to the report file, and the exit code counts them.
/// </summary>
static class Program
{
    static int Main(string[] args)
    {
        var report = Value(args, "--report");
        try
        {
            List<string> failures;
            if (Value(args, "--user") is { } user)
            {
                ServiceBase.Run(new HelperService(new SecurityIdentifier(user)));
                return 0;
            }
            else if (Value(args, "--apply") is { } encoded)
            {
                var ops = JsonSerializer.Deserialize<List<ElevatedOp>>(Encoding.UTF8.GetString(Convert.FromBase64String(encoded)), Elevated.Json) ?? [];
                failures = AdminChanges.Apply(ops);
            }
            else if (Value(args, "--install") is { } sid)
            {
                failures = Installer.Install(new SecurityIdentifier(sid));
            }
            else if (args.Contains("--uninstall"))
            {
                failures = Installer.Uninstall();
            }
            else
            {
                Console.Error.WriteLine("Revoke runs this; it isn't run by hand.");
                return 2;
            }
            if (report is not null) File.WriteAllLines(report, failures);
            return failures.Count;
        }
        catch (Exception e) when (e is JsonException or FormatException or ArgumentException or IOException or UnauthorizedAccessException)
        {
            if (report is not null) File.WriteAllText(report, e.Message);
            return 1;
        }
    }

    static string? Value(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}

sealed class HelperService : ServiceBase
{
    const int MaxRequest = 1 << 20;
    readonly SecurityIdentifier user;
    readonly CancellationTokenSource stopping = new();
    Task? listening;

    public HelperService(SecurityIdentifier user)
    {
        this.user = user;
        ServiceName = Helper.ServiceName;
        CanStop = true;
        CanShutdown = true;
    }

    protected override void OnStart(string[] args)
    {
        Helper.SecureStateFolder();
        listening = Task.Run(() => ListenAsync(stopping.Token));
    }

    protected override void OnStop()
    {
        stopping.Cancel();
        listening?.Wait(TimeSpan.FromSeconds(5));
    }

    protected override void OnShutdown() => OnStop();

    /// <summary>The pipe only lets in the user it serves, and SYSTEM. One request at a time.</summary>
    PipeSecurity Security()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    async Task ListenAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await using var pipe = NamedPipeServerStreamAcl.Create(Helper.PipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, Security());
                await pipe.WaitForConnectionAsync(token);
                await ServeAsync(pipe, token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
            {
                Log($"A request failed: {e.Message}", EventLogEntryType.Warning);
            }
        }
    }

    async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        var line = await reader.ReadLineAsync(token);
        if (line is null || line.Length > MaxRequest) return;
        var request = JsonSerializer.Deserialize<HelperRequest>(line, Helper.Json);
        var reply = request is null ? new HelperReply("Empty request.", []) : Handle(request.Ops);
        await writer.WriteLineAsync(JsonSerializer.Serialize(reply, Helper.Json).AsMemory(), token);
    }

    /// <summary>Checks every change, makes the allowed ones, and records what it changed.</summary>
    HelperReply Handle(List<ElevatedOp> ops)
    {
        if (ops.Count > HelperPolicy.MaxOps) return new HelperReply("Too many changes at once.", []);
        var state = HelperState.Load();
        var policy = HelperPolicy.ForThisPc(state);
        var accepted = new List<ElevatedOp>();
        var rejected = new List<int>();
        var log = new StringBuilder();
        for (var i = 0; i < ops.Count; i++)
        {
            if (policy.Check(ops[i]) is { } reason)
            {
                rejected.Add(i);
                log.AppendLine($"Declined: {Elevated.Describe(ops[i])} ({reason})");
            }
            else
            {
                accepted.Add(ops[i]);
                log.AppendLine($"Made: {Elevated.Describe(ops[i])}");
            }
        }

        // Remember how services started before setting them to Manual, so only those
        // start types can be put back.
        var servicesBefore = Services.Read().ToDictionary(s => s.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var op in accepted.OfType<ElevatedOp.SetServiceStart>().Where(s => s.Start == 3))
        {
            if (servicesBefore.TryGetValue(op.Name, out var service) && service.Start != 3)
                state.ServiceStarts.TryAdd(service.Name, service.Start);
        }

        var failures = AdminChanges.Apply(accepted);

        // Record what actually changed, whatever failed.
        var rulesAfter = (Firewall.Read() ?? []).ToDictionary(r => r.Id);
        foreach (var op in accepted.OfType<ElevatedOp.SetRuleEnabled>())
        {
            if (!rulesAfter.TryGetValue(op.Id, out var rule)) state.DisabledRules.Remove(op.Id);
            else if (!op.Enabled && !rule.Active) state.DisabledRules.Add(op.Id);
            else if (op.Enabled && rule.Active) state.DisabledRules.Remove(op.Id);
        }
        var servicesAfter = Services.Read().ToDictionary(s => s.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var op in accepted.OfType<ElevatedOp.SetServiceStart>().Where(s => s.Start != 3))
        {
            if (servicesAfter.TryGetValue(op.Name, out var service) && service.Start == op.Start) state.ServiceStarts.Remove(service.Name);
        }
        state.Save();

        foreach (var failure in failures) log.AppendLine($"Failed: {failure}");
        Log(log.ToString().TrimEnd(), failures.Count == 0 ? EventLogEntryType.Information : EventLogEntryType.Warning);
        return new HelperReply(failures.FirstOrDefault(), rejected);
    }

    void Log(string message, EventLogEntryType type)
    {
        try { EventLog.WriteEntry(Helper.ServiceName, message, type); }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or Win32Exception) { }
    }
}

/// <summary>Installs and removes the service, through the Service Control Manager.</summary>
static partial class Installer
{
    const string Description = "Makes the firewall and service changes Revoke asks for, without a UAC prompt each time.";

    public static List<string> Install(SecurityIdentifier user)
    {
        var failures = new List<string>();
        try
        {
            StopIfRunning();
            // The copy keeps the file's modified time, which is how Revoke tells it's current.
            Directory.CreateDirectory(Path.GetDirectoryName(Helper.InstallPath)!);
            File.Copy(Environment.ProcessPath!, Helper.InstallPath, overwrite: true);

            var binary = $"\"{Helper.InstallPath}\" --user {user.Value}";
            var manager = Check(OpenSCManagerW(null, null, 0x2)); // SC_MANAGER_CREATE_SERVICE
            try
            {
                var service = OpenServiceW(manager, Helper.ServiceName, 0xF01FF); // SERVICE_ALL_ACCESS
                if (service == 0)
                {
                    service = Check(CreateServiceW(manager, Helper.ServiceName, "Revoke Helper", 0xF01FF,
                        0x10, 2, 1, binary, null, 0, null, null, null)); // own process, automatic, normal errors
                }
                else
                {
                    const uint NoChange = 0xFFFFFFFF;
                    if (!AdminChanges.ChangeServiceConfigW(service, NoChange, 2, NoChange, binary, null, 0, null, null, null, null))
                        throw new Win32Exception();
                }
                try
                {
                    var description = new SERVICE_DESCRIPTIONW { lpDescription = Marshal.StringToHGlobalUni(Description) };
                    try { ChangeServiceConfig2W(service, 1, ref description); } // SERVICE_CONFIG_DESCRIPTION
                    finally { Marshal.FreeHGlobal(description.lpDescription); }
                }
                finally
                {
                    AdminChanges.CloseServiceHandle(service);
                }
            }
            finally
            {
                AdminChanges.CloseServiceHandle(manager);
            }

            if (!EventLog.SourceExists(Helper.ServiceName)) EventLog.CreateEventSource(Helper.ServiceName, "Application");
            using var controller = new ServiceController(Helper.ServiceName);
            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }
        catch (Exception e) when (e is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException
            or System.ServiceProcess.TimeoutException or System.Security.SecurityException)
        {
            failures.Add($"Install the helper: {e.Message}");
        }
        return failures;
    }

    public static List<string> Uninstall()
    {
        var failures = new List<string>();
        try
        {
            StopIfRunning();
            var manager = Check(OpenSCManagerW(null, null, 0x1)); // SC_MANAGER_CONNECT
            try
            {
                var service = OpenServiceW(manager, Helper.ServiceName, 0x10000); // DELETE
                if (service != 0)
                {
                    try { if (!DeleteService(service)) throw new Win32Exception(); }
                    finally { AdminChanges.CloseServiceHandle(service); }
                }
            }
            finally
            {
                AdminChanges.CloseServiceHandle(manager);
            }
            // The service process can hold its file for a moment after stopping.
            var folder = Path.GetDirectoryName(Helper.InstallPath)!;
            for (var i = 0; i < 20 && Directory.Exists(folder); i++)
            {
                try { Directory.Delete(folder, recursive: true); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Thread.Sleep(250); }
            }
            // Leave the firewall as it was: rules it switched off back on, and its own rules gone.
            var state = HelperState.Load();
            failures.AddRange(AdminChanges.Apply(state.DisabledRules.Select(id => (ElevatedOp)new ElevatedOp.SetRuleEnabled(id, true))));
            if (AdminChanges.RemoveAllRules() is { } error) failures.Add(error);
            if (Directory.Exists(Helper.StateFolder)) Directory.Delete(Helper.StateFolder, recursive: true);
        }
        catch (Exception e) when (e is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException
            or System.ServiceProcess.TimeoutException)
        {
            failures.Add($"Remove the helper: {e.Message}");
        }
        return failures;
    }

    static void StopIfRunning()
    {
        try
        {
            using var controller = new ServiceController(Helper.ServiceName);
            if (controller.Status != ServiceControllerStatus.Stopped)
            {
                controller.Stop();
                controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            }
        }
        catch (InvalidOperationException)
        {
            // Not installed.
        }
    }

    static nint Check(nint handle) => handle != 0 ? handle : throw new Win32Exception();

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_DESCRIPTIONW { public nint lpDescription; }

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint OpenServiceW(nint manager, string name, uint access);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint CreateServiceW(nint manager, string name, string displayName, uint access, uint type, uint start,
        uint errorControl, string binaryPath, string? loadOrderGroup, nint tagId, string? dependencies, string? account, string? password);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfig2W(nint service, uint level, ref SERVICE_DESCRIPTIONW info);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeleteService(nint service);
}
