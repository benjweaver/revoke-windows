using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace Revoke.Core;

/// <summary>A change that needs admin rights.</summary>
public abstract record ElevatedOp
{
    public sealed record StopService(string Name) : ElevatedOp;
    public sealed record SetServiceStart(string Name, int Start) : ElevatedOp;
    public sealed record SetRuleEnabled(string Id, bool Enabled) : ElevatedOp;
    /// <summary>Keeps one program off the local network, over TCP and UDP.</summary>
    public sealed record BlockLocalNetwork(string ClientKey, string Label, string Program) : ElevatedOp;
    /// <summary>Removes every rule Revoke added for a client.</summary>
    public sealed record RemoveBlocks(string ClientKey) : ElevatedOp;
    public sealed record SetMachineStartup(string Path, string Name, bool Enabled) : ElevatedOp;
}

/// <summary>
/// Changes that need admin rights: services, firewall rules, and machine-wide startup
/// entries. They're gathered into one PowerShell script and run behind a single UAC
/// prompt. The script goes on the command line, encoded, rather than into a file: a
/// file in a folder this user can write to could be swapped between being written
/// and being run as admin.
/// </summary>
public static class Elevated
{
    /// <summary>A PowerShell single-quoted string. PowerShell also ends single-quoted
    /// strings at curly quotes, so those are doubled too.</summary>
    public static string Quote(string text)
    {
        var sb = new StringBuilder("'");
        foreach (var c in text)
        {
            if (c is '\'' or '‘' or '’' or '‚' or '‛') sb.Append(c);
            sb.Append(c);
        }
        return sb.Append('\'').ToString();
    }

    static string Describe(ElevatedOp op) => op switch
    {
        ElevatedOp.StopService s => $"Stop {s.Name}",
        ElevatedOp.SetServiceStart s => $"Set {s.Name} to {Service.StartName(s.Start)}",
        ElevatedOp.SetRuleEnabled r => $"{(r.Enabled ? "Enable" : "Disable")} rule {r.Id}",
        ElevatedOp.BlockLocalNetwork b => $"Block {b.Program}",
        ElevatedOp.RemoveBlocks r => $"Unblock {r.ClientKey}",
        ElevatedOp.SetMachineStartup m => $"Startup {m.Name}",
        _ => op.ToString(),
    };

    static string Step(ElevatedOp op) => op switch
    {
        ElevatedOp.StopService s => $"Stop-Service -Name {Quote(s.Name)} -Force",
        ElevatedOp.SetServiceStart s => $"Set-Service -Name {Quote(s.Name)} -StartupType {Service.StartName(s.Start)}",
        ElevatedOp.SetRuleEnabled r => $"Set-NetFirewallRule -Name {Quote(r.Id)} -Enabled {(r.Enabled ? "True" : "False")}",
        ElevatedOp.BlockLocalNetwork b =>
            $"foreach ($p in 'TCP','UDP') {{ New-NetFirewallRule -DisplayName {Quote($"Revoke: keep {b.Label} off the local network")} " +
            $"-Group {Quote(Firewall.Group)} -Description {Quote(Firewall.DescriptionPrefix + b.ClientKey)} " +
            $"-Direction Outbound -Action Block -Program {Quote(b.Program)} -Protocol $p -RemotePort {Firewall.Ports} " +
            "-RemoteAddress $local | Out-Null }",
        ElevatedOp.RemoveBlocks r =>
            $"Get-NetFirewallRule -Group {Quote(Firewall.Group)} -ErrorAction SilentlyContinue | " +
            $"Where-Object {{ $_.Description -eq {Quote(Firewall.DescriptionPrefix + r.ClientKey)} }} | Remove-NetFirewallRule",
        ElevatedOp.SetMachineStartup m =>
            $"New-Item -Path {Quote(m.Path)} -Force -ErrorAction SilentlyContinue | Out-Null; " +
            $"Set-ItemProperty -Path {Quote(m.Path)} -Name {Quote(m.Name)} " +
            $"-Value ([byte[]]({string.Join(',', Startup.Approval(m.Enabled))})) -Type Binary",
        _ => throw new ArgumentOutOfRangeException(nameof(op)),
    };

    /// <summary>The whole script. Each step runs even if an earlier one failed, and
    /// failures are written to <paramref name="report"/> for Revoke to read back.</summary>
    public static string Script(IEnumerable<ElevatedOp> ops, string report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("$ProgressPreference = 'SilentlyContinue'");
        sb.AppendLine($"$local = @({string.Join(',', Firewall.LocalAddresses.Select(Quote))})");
        sb.AppendLine("$failed = New-Object System.Collections.Generic.List[string]");
        foreach (var op in ops)
        {
            sb.AppendLine($"try {{ {Step(op)} }} catch {{ $failed.Add({Quote(Describe(op))} + ': ' + $_.Exception.Message) }}");
        }
        sb.AppendLine($"$failed | Set-Content -LiteralPath {Quote(report)} -Encoding UTF8");
        sb.AppendLine("exit $failed.Count");
        return sb.ToString();
    }

    /// <summary>Runs the operations as admin, after the UAC prompt, and waits for them.
    /// Returns why it failed, or null.</summary>
    public static string? Run(IReadOnlyCollection<ElevatedOp> ops)
    {
        if (ops.Count == 0) return null;
        var report = Path.Combine(Path.GetTempPath(), $"revoke-{Environment.ProcessId}-{Guid.NewGuid():N}.txt");
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script(ops, report)));
        var arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded}";
        if (arguments.Length > 32_000) return "Too many changes for one prompt. Try fewer apps at a time.";
        var powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        try
        {
            using var process = Process.Start(new ProcessStartInfo(powershell, arguments)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null) return "PowerShell didn't start.";
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
}
