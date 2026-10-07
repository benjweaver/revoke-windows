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
}
