using System.Runtime.InteropServices;
using Xunit;

namespace Revoke.Core.Tests;

public partial class FirewallProgramsTests : IDisposable
{
    readonly string tempDir = Path.Combine(Path.GetTempPath(), $"revoke-fw-test-{Guid.NewGuid():N}");

    public FirewallProgramsTests() => Directory.CreateDirectory(tempDir);

    public void Dispose()
    {
        if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
    }

    [Theory]
    [InlineData(@"C:\Program Files\App\app.exe", true)]
    [InlineData(@"C:\Program Files\App\app.EXE", true)]
    [InlineData(@"C:\Users\Example\AppData\Local\Temp\is-setup.tmp\updater.tmp", false)]
    [InlineData(@"C:\Temp\installer.bat", false)]
    [InlineData(@"app.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsExecutableAcceptsOnlyFullyQualifiedExePaths(string? path, bool expected) =>
        Assert.Equal(expected, Firewall.IsExecutable(path));

    [LibraryImport("kernel32.dll", EntryPoint = "GetShortPathNameW", StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint GetShortPathNameW(string longPath, char* shortPath, uint size);

    static unsafe string ShortPath(string path)
    {
        var buffer = new char[1024];
        fixed (char* chars = buffer)
        {
            var length = GetShortPathNameW(path, chars, (uint)buffer.Length);
            Assert.InRange(length, 1u, (uint)buffer.Length - 1);
            return new string(chars, 0, (int)length);
        }
    }

    [Fact]
    public void ProgramsOfExcludesNonExeHelpersSuchAsInnoSetupTempUpdaters()
    {
        var appExe = Path.Combine(tempDir, "Code.exe");
        var helperExe = Path.Combine(tempDir, "helper.exe");
        var tempUpdater = Path.Combine(tempDir, "codesetup-stable-3.30.14.tmp");
        File.WriteAllBytes(appExe, []);
        File.WriteAllBytes(helperExe, []);
        File.WriteAllBytes(tempUpdater, []);

        var client = Client.FromPath(appExe);
        Client[] helpers = [Client.FromPath(ShortPath(helperExe)), Client.FromPath(tempUpdater)];

        var programs = Model.ProgramsOf(client, [], helpers);

        Assert.Equal([appExe, helperExe], programs, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProgramsOfExcludesNonExePackagePrograms()
    {
        var pkgDir = Path.Combine(tempDir, "WindowsApps", "Pkg_1.0.0.0_x64__abc123def456");
        Directory.CreateDirectory(pkgDir);
        var appExe = Path.Combine(pkgDir, "App.exe");
        var tempFile = Path.Combine(pkgDir, "update.tmp");
        File.WriteAllBytes(appExe, []);
        File.WriteAllBytes(tempFile, []);

        var client = Client.Package("Pkg_abc123def456");

        var programs = Model.ProgramsOf(client, [appExe, tempFile], []);

        Assert.Equal([appExe], programs, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParsesFirewallProtocolForCoverageChecks()
    {
        var rule = Firewall.Parse("id", @"v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|App=C:\Apps\app.exe|Desc=revoke-internet:exe:c:\apps\app.exe|EmbedCtxt=Revoke|");
        Assert.Equal(17, rule.Protocol);
        Assert.True(rule.Active);
        Assert.False(rule.Allow);
        Assert.False(rule.Inbound);
    }

    [Fact]
    public void CoverageRequiresActiveOutboundTcpAndUdpBlockRules()
    {
        const string program = @"C:\Apps\app.exe";
        FirewallRule Rule(int protocol, bool active = true, bool inbound = false, bool allow = false) =>
            new(Guid.NewGuid().ToString(), "Test", inbound, allow, active, program, null, Firewall.Group)
            { Protocol = protocol };

        var tcp = Rule(6);
        Assert.Equal([17], Firewall.MissingBlockProtocols(program, [tcp]));
        Assert.DoesNotContain(program, Firewall.FullyBlockedPrograms([tcp]));
        Assert.Equal([17], Firewall.MissingBlockProtocols(program,
            [tcp, Rule(17, active: false), Rule(17, inbound: true), Rule(17, allow: true)]));

        var both = new[] { tcp, Rule(17) };
        Assert.Empty(Firewall.MissingBlockProtocols(program, both));
        Assert.Contains(program, Firewall.FullyBlockedPrograms(both));
        Assert.Equal([6, 17], Firewall.MissingBlockProtocols(@"C:\Apps\other.exe", both));
    }

    [Fact]
    public void UpdatingAProgramAddsItsRulesWithoutRemovingExistingBlocks()
    {
        const string oldProgram = @"C:\Apps\Old\app.exe";
        const string newProgram = @"C:\Apps\New\app.exe";
        var client = Client.FromPath(oldProgram);
        FirewallRule Rule(int protocol) =>
            new(Guid.NewGuid().ToString(), "Test", false, false, true, oldProgram, null, Firewall.Group)
            { Protocol = protocol };
        var existing = new[] { Rule(6), Rule(17) };

        var network = Model.PlanFirewallRepair(client, "App", Pane.Network,
            [oldProgram, newProgram], existing, [], []);
        Assert.Equal(newProgram, Assert.IsType<ElevatedOp.BlockLocalNetwork>(Assert.Single(network)).Program);

        var internet = Model.PlanFirewallRepair(client, "App", Pane.Internet,
            [oldProgram, newProgram], existing, [], ["api.example.com"]);
        var added = Assert.IsType<ElevatedOp.BlockInternet>(Assert.Single(internet));
        Assert.Equal(newProgram, added.Program);
        Assert.Equal(["api.example.com"], added.Hosts);
    }

    [Fact]
    public void RepairAlsoDisablesNewInboundAllowRules()
    {
        const string program = @"C:\Apps\app.exe";
        var client = Client.FromPath(program);
        FirewallRule Block(int protocol) =>
            new(Guid.NewGuid().ToString(), "Block", false, false, true, program, null, Firewall.Group)
            { Protocol = protocol };
        var inbound = new FirewallRule("new-inbound-rule", "Allow", true, true, true, program, null, null);

        var planned = Model.PlanFirewallRepair(client, "App", Pane.Network,
            [program], [Block(6), Block(17)], [inbound], []);

        var disable = Assert.IsType<ElevatedOp.SetRuleEnabled>(Assert.Single(planned));
        Assert.Equal(inbound.Id, disable.Id);
        Assert.False(disable.Enabled);
    }
}
