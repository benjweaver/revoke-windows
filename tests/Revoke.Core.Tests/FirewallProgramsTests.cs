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
}
