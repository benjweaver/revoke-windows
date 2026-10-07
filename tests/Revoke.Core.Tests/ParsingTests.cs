using System.Diagnostics;
using Xunit;

namespace Revoke.Core.Tests;

// Shares a collection with LiveTests, which walks this process's tree: they run one at a time.
[Collection("Processes")]
public class ParsingTests
{
    const string Manifest = """
        <Applications>
          <Application Id="Claude" Executable="app\Claude.exe" EntryPoint="Windows.FullTrustApplication">
            <Extensions><desktop:Extension Category="windows.startupTask">
              <desktop:StartupTask TaskId="ClaudeStartup" Enabled="false" DisplayName="Claude" />
            </desktop:Extension></Extensions>
          </Application>
          <Application Id="SshProxy" Executable="app/resources/claude-ssh-proxy.exe"/>
        </Applications>
        """;

    [Fact]
    public void ReadsTheManifest()
    {
        Assert.Equal(["Claude", "SshProxy"], Packages.Attributes(Manifest, "Application", "Id"));
        Assert.Equal(2, Packages.Attributes(Manifest, "Application", "Executable").Count);
        Assert.Equal([("ClaudeStartup", false)], Packages.StartupTasks(Manifest));
        // <Applications> is a different element.
        Assert.Single(Packages.Tags(Manifest, "Applications"));
    }

    [Fact]
    public void ParsesFirewallRules()
    {
        var rule = Firewall.Parse("{94F5}",
            @"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\WindowsApps\Claude_2.16120.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe|Name=Claude|Desc=Claude|EmbedCtxt={78E1}|");
        Assert.True(rule.Inbound && rule.Allow && rule.Active);
        Assert.Equal("Claude", rule.Name);
        Assert.Equal(Client.Package("Claude_pzs8sxrjxfjjc"), Client.FromPath(rule.Program!));
        Assert.Null(rule.RevokeClient);

        var ours = Firewall.Parse("x", @"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\a.exe|Name=Revoke|Desc=revoke:pkg:Claude_pzs8sxrjxfjjc|EmbedCtxt=Revoke|");
        Assert.Equal(Client.Package("Claude_pzs8sxrjxfjjc"), ours.RevokeClient);
    }

    [Fact]
    public void QuotesForPowerShell()
    {
        Assert.Equal("'Ben''s'", Elevated.Quote("Ben's"));
        Assert.Equal("'Ben\u2019\u2019s'", Elevated.Quote("Ben\u2019s"));
    }

    /// <summary>Parses (never runs) a script with every kind of step, names with quotes in.</summary>
    [Fact]
    public void PowerShellParsesTheScript()
    {
        var script = Elevated.Script(
        [
            new ElevatedOp.StopService("CoworkVMService"),
            new ElevatedOp.SetServiceStart("Ben's service", 3),
            new ElevatedOp.SetRuleEnabled("{94F51A85-530F-40C4-8BA9-DC2473F0E12D}", false),
            new ElevatedOp.BlockLocalNetwork(@"exe:c:\x\*\y.exe", "Ben\u2019s app", @"C:\Program Files\x\y.exe"),
            new ElevatedOp.RemoveBlocks("pkg:A_b"),
            new ElevatedOp.SetMachineStartup(Startup.MachineApprovalPath(false), "Thing", false),
        ], @"C:\Temp\report.txt");
        Assert.Equal(6, script.Split("try {").Length - 1);
        Assert.Contains("-RemotePort 1-52,54-65535", script);

        var path = Path.Combine(Path.GetTempPath(), $"revoke-parse-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(path, script, new System.Text.UTF8Encoding(true));
        try
        {
            var check = "$errors = $null; [void][System.Management.Automation.Language.Parser]::ParseFile(" +
                Elevated.Quote(path) + ", [ref]$null, [ref]$errors); if ($errors.Count) { $errors | % { $_.Message }; exit 1 }";
            using var process = Process.Start(new ProcessStartInfo("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", check])
            {
                RedirectStandardOutput = true,
            })!;
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, output + "\n" + script);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PowerShellCatchesABrokenScript()
    {
        // The check above has to be able to fail.
        using var process = Process.Start(new ProcessStartInfo("powershell.exe",
            ["-NoProfile", "-NonInteractive", "-Command",
             "$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput(\"try { Stop-Service -Name 'x }\", [ref]$null, [ref]$e); exit $e.Count"]))!;
        process.WaitForExit();
        Assert.NotEqual(0, process.ExitCode);
    }
}
