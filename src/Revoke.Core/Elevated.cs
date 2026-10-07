using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Revoke.Core;

/// <summary>A change that needs admin rights.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "op")]
[JsonDerivedType(typeof(StopService), "stopService")]
[JsonDerivedType(typeof(SetServiceStart), "setServiceStart")]
[JsonDerivedType(typeof(SetRuleEnabled), "setRuleEnabled")]
[JsonDerivedType(typeof(BlockLocalNetwork), "blockLocalNetwork")]
[JsonDerivedType(typeof(RemoveBlocks), "removeBlocks")]
[JsonDerivedType(typeof(SetMachineStartup), "setMachineStartup")]
public abstract record ElevatedOp
{
    public sealed record StopService(string Name) : ElevatedOp;
    public sealed record SetServiceStart(string Name, int Start) : ElevatedOp;
    public sealed record SetRuleEnabled(string Id, bool Enabled) : ElevatedOp;
    /// <summary>Keeps one program off the local network, over TCP and UDP.</summary>
    public sealed record BlockLocalNetwork(string ClientKey, string Label, string Program) : ElevatedOp;
    /// <summary>Removes every rule Revoke added for a client.</summary>
    public sealed record RemoveBlocks(string ClientKey) : ElevatedOp;
    /// <summary>Switches a machine-wide Run value on or off, the way Settings › Apps › Startup does.</summary>
    public sealed record SetMachineStartup(bool Wow64, string Name, bool Enabled) : ElevatedOp;
}

/// <summary>
/// Changes that need admin rights: services, firewall rules, and machine-wide startup
/// entries. The helper service makes the ones it allows without asking. The rest go
/// to the helper program run once as admin, behind one UAC prompt, which makes them the
/// same way (<see cref="AdminChanges"/>).
/// </summary>
public static class Elevated
{
    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static string Describe(ElevatedOp op) => op switch
    {
        ElevatedOp.StopService s => $"Stop {s.Name}",
        ElevatedOp.SetServiceStart s => $"Set {s.Name} to {Service.StartName(s.Start)}",
        ElevatedOp.SetRuleEnabled r => $"{(r.Enabled ? "Enable" : "Disable")} rule {r.Id}",
        ElevatedOp.BlockLocalNetwork b => $"Block {b.Program}",
        ElevatedOp.RemoveBlocks r => $"Unblock {r.ClientKey}",
        ElevatedOp.SetMachineStartup m => $"{(m.Enabled ? "Enable" : "Disable")} startup {m.Name}",
        _ => op.ToString(),
    };

    /// <summary>Makes the changes: through the helper service, if it's installed and allows
    /// them, and behind one UAC prompt for the rest. Returns why something failed, or null.</summary>
    public static string? Run(IReadOnlyCollection<ElevatedOp> ops)
    {
        if (ops.Count == 0) return null;
        var rest = ops;
        if (Helper.Send(ops) is { } reply)
        {
            if (reply.Error is not null) return reply.Error;
            rest = reply.Rejected.Select(i => ops.ElementAt(i)).ToList();
        }
        if (rest.Count == 0) return null;
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(rest.ToList(), Json)));
        return RunAsAdmin(["--apply", encoded]);
    }

    /// <summary>
    /// Runs the helper program once as admin, after the UAC prompt, and waits for it. The
    /// changes go on its command line, so nothing between the prompt and the program can
    /// swap them. It writes failures to a file named on the command line too.
    /// </summary>
    public static string? RunAsAdmin(IReadOnlyList<string> arguments)
    {
        if (!File.Exists(Helper.BundledPath)) return "The helper is missing from Revoke's folder.";
        var report = Path.Combine(Path.GetTempPath(), $"revoke-{Environment.ProcessId}-{Guid.NewGuid():N}.txt");
        var commandLine = string.Join(' ', arguments.Prepend(report).Prepend("--report").Select(QuoteArgument));
        if (commandLine.Length > 32_000) return "Too many changes at once. Try fewer apps at a time.";
        try
        {
            using var process = Process.Start(new ProcessStartInfo(Helper.BundledPath, commandLine)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null) return "The helper didn't start.";
            if (!process.WaitForExit(TimeSpan.FromMinutes(3))) return "The admin step took too long.";
            var failures = File.Exists(report) ? File.ReadAllText(report).Trim() : "";
            return process.ExitCode == 0 ? null
                : failures.Length > 0 ? failures.Split('\n')[0].Trim()
                : $"The admin step stopped with code {process.ExitCode}.";
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            return "Cancelled at the admin prompt.";
        }
        catch (Win32Exception e)
        {
            return e.Message;
        }
        finally
        {
            try { File.Delete(report); } catch (IOException) { }
        }
    }

    /// <summary>Quotes one argument the way CommandLineToArgvW reads it back.</summary>
    static string QuoteArgument(string argument)
    {
        if (argument.Length > 0 && !argument.Any(c => c is ' ' or '\t' or '"')) return argument;
        var sb = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var c in argument)
        {
            if (c == '\\') { backslashes++; continue; }
            sb.Append('\\', c == '"' ? backslashes * 2 + 1 : backslashes).Append(c);
            backslashes = 0;
        }
        return sb.Append('\\', backslashes * 2).Append('"').ToString();
    }
}
