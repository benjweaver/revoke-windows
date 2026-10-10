using Xunit;

namespace Revoke.Core.Tests;

public class ClientTests
{
    [Fact]
    public void PackagesComeFromInstallFolders()
    {
        Assert.Equal(Client.Package("Claude_pzs8sxrjxfjjc"),
            Client.FromPath(@"C:\Program Files\WindowsApps\Claude_2.16120.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe"));
        Assert.Equal(Client.Package("OpenAI.Codex_2p2nqsd0c76g0"),
            Client.FromPath(@"C:\Program Files\WindowsApps\OpenAI.Codex_26.1002.7124.0_x64__2p2nqsd0c76g0\app\resources\codex.exe"));
    }

    [Theory]
    [InlineData(@"C:\Users\Ben\AppData\Roaming\Claude\claude-code\2.1.284\claude.exe", @"c:\users\ben\appdata\roaming\claude\claude-code\*\claude.exe")]
    [InlineData(@"C:\Users\Ben\AppData\Local\OpenAI\Codex\bin\9691020b546a15b2\codex.exe", @"c:\users\ben\appdata\local\openai\codex\bin\*\codex.exe")]
    [InlineData(@"C:\x\app-1.0.9\Discord.exe", @"c:\x\*\discord.exe")]
    // Names that merely contain digits stay.
    [InlineData(@"C:\Program Files\7-Zip\7z.exe", @"c:\program files\7-zip\7z.exe")]
    [InlineData(@"C:\Windows\System32\x.exe", @"c:\windows\system32\x.exe")]
    public void VersionsAndHashesBecomeWildcards(string path, string pattern) => Assert.Equal(pattern, Client.Pattern(path));

    [Theory]
    [InlineData("Anthropic, PBC", "anthropic")]
    [InlineData("OpenAI OpCo, LLC", "openai")]
    [InlineData("OpenAI", "openai")]
    public void VendorsGroupByFirstWord(string publisher, string vendor) => Assert.Equal(vendor, Client.VendorKey(publisher));

    // Signers and install folders read from the apps on Windows 11.
    [Theory]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe", "Anysphere, Inc.", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\Devin\Devin.exe", "Exafunction, Inc.", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe", "Microsoft Corporation", true)]
    [InlineData(@"C:\Program Files\Microsoft VS Code Insiders\Code - Insiders.exe", "Microsoft Corporation", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\VSCodium\VSCodium.exe", "", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\Void\Void.exe", "", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\antigravity\Antigravity.exe", "", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\Kiro\Kiro.exe", "Amazon.com Services LLC", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\Trae\Trae.exe", "SPRING (SG) PTE. LTD", true)]
    [InlineData(@"C:\Users\dev\AppData\Local\Programs\GitHub Copilot\github.exe", "GitHub, Inc.", true)]
    // A shared signer alone isn't enough.
    [InlineData(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "Microsoft Corporation", false)]
    [InlineData(@"C:\Users\dev\AppData\Local\GitHubDesktop\GitHubDesktop.exe", "GitHub, Inc.", false)]
    [InlineData(@"C:\Program Files\Amazon\AWSCLIV2\aws.exe", "Amazon.com Services LLC", false)]
    // The folder has to be a whole folder of the program's path, not the program's name.
    [InlineData(@"C:\Tools\kiro.exe", "", false)]
    public void CodingAgentsAreWatchedByDefault(string path, string publisher, bool watched) =>
        Assert.Equal(watched, Settings.WatchedByDefault(Client.FromPath(path), publisher));

    [Fact]
    public void ProgramsComeOutOfCommandLines()
    {
        Assert.Equal(@"C:\a b\x.exe", Client.ProgramInCommand("\"C:\\a b\\x.exe\" -silent"));
        Assert.Equal(@"C:\a\x.EXE", Client.ProgramInCommand(@"C:\a\x.EXE --flag"));
    }

    [Fact]
    public void KeysRoundTrip()
    {
        foreach (var client in new[] { Client.Package("A_b"), Client.FromPath(@"c:\x\1.2.3\y.exe") })
            Assert.Equal(client, Client.FromKey(client.Key));
    }

    [Fact]
    public void NamesAndRolesMatchRevokeForMacOS()
    {
        Assert.Equal("Claude Code", Model.KnownName(@"C:\Users\Ben\AppData\Local\Microsoft\WinGet\Packages\Anthropic.ClaudeCode_Microsoft.Winget.Source_8wekyb3d8bbwe\claude.exe"));
        Assert.Equal("Claude Code", Model.KnownName(@"C:\Users\Ben\.local\bin\claude.exe"));
        Assert.Equal("Includes Codex", Model.RoleOf(Client.Package("OpenAI.Codex_2p2nqsd0c76g0")));
        Assert.Equal("Runs Claude's Code tab", Model.RoleOf(Client.FromPath(@"C:\Users\Ben\AppData\Roaming\Claude\claude-code\2.1.284\claude.exe")));
        Assert.Null(Model.RoleOf(Client.FromPath(@"C:\Users\Ben\.local\bin\claude.exe")));
        Assert.Null(Model.RoleOf(Client.Package("Claude_pzs8sxrjxfjjc")));
    }

    [Fact]
    public void ListsUseTheSerialComma()
    {
        Assert.Equal("", Model.List([]));
        Assert.Equal("Claude", Model.List(["Claude"]));
        Assert.Equal("Claude and ChatGPT", Model.List(["Claude", "ChatGPT"]));
        Assert.Equal("Claude, ChatGPT, and Claude Code", Model.List(["Claude", "ChatGPT", "Claude Code"]));
    }
}
