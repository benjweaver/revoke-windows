using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Xunit;

namespace Revoke.Core.Tests;

public class InternetHostsTests
{
    [Theory]
    [InlineData("anthropic.com", "anthropic.com")]
    [InlineData("  HTTPS://*.Api.Anthropic.COM:443/v1/messages?x=1  ", "api.anthropic.com")]
    [InlineData("http://openai.com:8080/chat", "openai.com")]
    [InlineData("*.*.cursor.sh.", "cursor.sh")]
    [InlineData(".claude.ai...", "claude.ai")]
    [InlineData("xn--bcher-kva.example.com", "xn--bcher-kva.example.com")]
    [InlineData("a-api.cursor-cdn.com", "a-api.cursor-cdn.com")]
    public void NormalizesValidHostNames(string input, string expected) =>
        Assert.Equal(expected, InternetHosts.Normalized(input));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("*.")]
    [InlineData("https:///path")]
    [InlineData("localhost")]
    [InlineData("intranet")]
    [InlineData("127.0.0.1")]
    [InlineData("160.79.104.10")]
    [InlineData("host.123")]
    [InlineData("[::1]")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("-bad.com")]
    [InlineData("bad-.com")]
    [InlineData("sub.-bad.com")]
    [InlineData("a..b.com")]
    [InlineData("bad_label.com")]
    [InlineData("exämple.com")]
    public void RejectsNonHostNamesAndInvalidLabels(string input) =>
        Assert.Null(InternetHosts.Normalized(input));

    [Fact]
    public void RejectsOverlongLabelsAndHostNames()
    {
        var label63 = new string('a', 63);
        var label64 = new string('a', 64);
        Assert.Equal($"{label63}.com", InternetHosts.Normalized($"{label63}.com"));
        Assert.Null(InternetHosts.Normalized($"{label64}.com"));

        // 253 characters is the maximum DNS name length; 254 is rejected.
        var maxHost = $"{new string('a', 63)}.{new string('b', 63)}.{new string('c', 63)}.{new string('d', 57)}.com";
        Assert.Equal(253, maxHost.Length);
        Assert.Equal(maxHost, InternetHosts.Normalized(maxHost));
        Assert.Null(InternetHosts.Normalized("a" + maxHost));
    }

    [Fact]
    public void ParsesAndDeduplicatesHostListsPreservingOrder()
    {
        var parsed = InternetHosts.Parse(
            "github.com, https://api.github.com:443/v1\n*.GITHUB.COM\tpypi.org, localhost, 1.1.1.1, files.pythonhosted.org., api.github.com");

        Assert.Equal(["github.com", "api.github.com", "pypi.org", "files.pythonhosted.org"], parsed);
        Assert.Empty(InternetHosts.Parse(""));
        Assert.Empty(InternetHosts.Parse("  , \t \n "));
    }

    [Fact]
    public void MatchesExactAndSubdomainsWhileRejectingSuffixAndPrefixTricks()
    {
        string[] allowed = ["anthropic.com", "claude.ai"];

        Assert.True(InternetHosts.Matches("anthropic.com", allowed));
        Assert.True(InternetHosts.Matches("HTTPS://API.Anthropic.com:443/v1", allowed));
        Assert.True(InternetHosts.Matches("a.b.claude.ai", allowed));

        // Suffix and subdomain-prefix attacks must not match.
        Assert.False(InternetHosts.Matches("notanthropic.com", allowed));
        Assert.False(InternetHosts.Matches("anthropic.com.evil.org", allowed));
        Assert.False(InternetHosts.Matches("evil-claude.ai", allowed));
        Assert.False(InternetHosts.Matches("127.0.0.1", allowed));
        Assert.False(InternetHosts.Matches("", allowed));

        // Allowing a subdomain does not allow the parent apex domain.
        Assert.False(InternetHosts.Matches("anthropic.com", ["api.anthropic.com"]));
        Assert.True(InternetHosts.Matches("v1.api.anthropic.com", ["api.anthropic.com"]));
    }

    [Fact]
    public void ResolvesBuiltInAndExtraHostsForClients()
    {
        var claude = Client.Package("Claude_pzs8sxrjxfjjc");
        Assert.Equal(
            ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"],
            InternetHosts.ForClient(claude, "Anthropic, PBC", []));

        var chatgpt = Client.Package("OpenAI.Codex_2p2nqsd0c76g0");
        Assert.Equal(
            ["chatgpt.com", "oaistatic.com", "oaiusercontent.com", "openai.com"],
            InternetHosts.ForClient(chatgpt, "OpenAI OpCo, LLC", []));

        var cursor = Client.FromPath(@"C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe");
        Assert.Equal(
            ["cursor-cdn.com", "cursor.com", "cursor.sh", "cursorapi.com"],
            InternetHosts.ForClient(cursor, "Anysphere, Inc.", []));
        // Unsigned or differently signed Cursor builds still get Cursor's hosts by path.
        Assert.Equal(
            ["cursor-cdn.com", "cursor.com", "cursor.sh", "cursorapi.com"],
            InternetHosts.ForClient(cursor, "", []));

        var deepseek = Client.FromPath(@"C:\Program Files\DeepSeek\deepseek.exe");
        Assert.Equal(
            ["deepseek.com", "github.com"],
            InternetHosts.ForClient(deepseek, "DeepSeek", ["https://github.com/org/repo", "deepseek.com"]));

        var other = Client.FromPath(@"C:\Users\dev\AppData\Local\Programs\VSCodium\VSCodium.exe");
        Assert.Equal(
            ["github.com", "open-vsx.org"],
            InternetHosts.ForClient(other, "", ["open-vsx.org", "*.github.com", "invalid"]));

        string[] expectedAntigravity =
        [
            "accounts.google.com",
            "antigravity.google",
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "oauth2.googleapis.com",
            "www.googleapis.com",
        ];
        var antigravity = Client.FromPath(@"C:\Users\dev\AppData\Local\Programs\Antigravity\Antigravity.exe");
        Assert.Equal(expectedAntigravity, InternetHosts.ForClient(antigravity, "Google LLC", []));
        // Unsigned or differently signed Antigravity builds and helper exes still get Antigravity's hosts by path.
        Assert.Equal(expectedAntigravity, InternetHosts.ForClient(antigravity, "", []));
        var antigravityHelper = Client.FromPath(@"C:\Users\dev\AppData\Local\Programs\Antigravity\resources\app\bin\language_server_windows_x64.exe");
        Assert.Equal(
            expectedAntigravity,
            InternetHosts.ForClient(antigravityHelper, "", ["https://accounts.google.com/o/oauth2/auth", "antigravity.google"]));
    }

    [Fact]
    public void MatchesAntigravityHostsWithoutOpeningAllOfGoogleOrGoogleApis()
    {
        var antigravity = Client.FromPath(@"C:\Users\dev\AppData\Local\Programs\Antigravity\Antigravity.exe");
        var allowed = InternetHosts.ForClient(antigravity, "", []);

        Assert.True(InternetHosts.Matches("antigravity.google", allowed));
        Assert.True(InternetHosts.Matches("api.antigravity.google", allowed));
        Assert.True(InternetHosts.Matches("accounts.google.com", allowed));
        Assert.True(InternetHosts.Matches("oauth2.googleapis.com", allowed));
        Assert.True(InternetHosts.Matches("www.googleapis.com", allowed));
        Assert.True(InternetHosts.Matches("cloudcode-pa.googleapis.com", allowed));
        Assert.True(InternetHosts.Matches("daily-cloudcode-pa.googleapis.com", allowed));
        Assert.True(InternetHosts.Matches("generativelanguage.googleapis.com", allowed));

        Assert.False(InternetHosts.Matches("google.com", allowed));
        Assert.False(InternetHosts.Matches("mail.google.com", allowed));
        Assert.False(InternetHosts.Matches("googleapis.com", allowed));
        Assert.False(InternetHosts.Matches("evil.googleapis.com", allowed));
    }

    [Fact]
    public void CandidateHostsExpandBareDomainsWithoutPrefixingExplicitSubdomains()
    {
        var candidates = InternetHosts.CandidateHosts(
            [
                "antigravity.google",
                "anthropic.com",
                "accounts.google.com",
                "https://OAUTH2.googleapis.com/token",
                "daily-cloudcode-pa.googleapis.com",
                "accounts.google.com",
            ]);

        // Bare domains keep themselves, CommonPrefixes, and matching KnownSubdomains.
        Assert.Contains("antigravity.google", candidates);
        Assert.Contains("api.antigravity.google", candidates);
        Assert.Contains("www.antigravity.google", candidates);
        Assert.Contains("anthropic.com", candidates);
        Assert.Contains("api.anthropic.com", candidates);
        Assert.Contains("a-api.anthropic.com", candidates);

        // Explicit subdomains are preserved as-is and do not get CommonPrefixes prepended.
        Assert.Contains("accounts.google.com", candidates);
        Assert.Contains("oauth2.googleapis.com", candidates);
        Assert.Contains("daily-cloudcode-pa.googleapis.com", candidates);
        Assert.DoesNotContain("api.accounts.google.com", candidates);
        Assert.DoesNotContain("www.accounts.google.com", candidates);
        Assert.DoesNotContain("api.oauth2.googleapis.com", candidates);
        Assert.DoesNotContain("www.daily-cloudcode-pa.googleapis.com", candidates);
    }

    [Fact]
    public void ComplementRangesExcludeNonInternetLocalSubnetsAndAllowedIpsAndMergeAdjacentIntervals()
    {
        var allowedIps = new[]
        {
            IPAddress.Parse("1.1.1.1"),
            IPAddress.Parse("1.1.1.2"),
            IPAddress.Parse("::ffff:1.1.1.3"), // IPv4-mapped IPv6 merges with 1.1.1.1-1.1.1.2
            IPAddress.Parse("160.79.104.10"),
            IPAddress.Parse("2607:6bc0::10"),
            IPAddress.Parse("2607:6bc0::11"),
        };
        var localSubnets = new[]
        {
            (IPAddress.Parse("100.64.1.5"), 10),   // 100.64.0.0/10
            (IPAddress.Parse("2001:db8::1"), 32),  // 2001:db8::/32
        };

        var ranges = InternetHosts.ComplementRanges(allowedIps, localSubnets);
        var (v4, v6) = ParseRanges(ranges);

        // Complement intervals must be sorted, disjoint, and non-adjacent (adjacent holes were merged).
        for (var i = 1; i < v4.Count; i++)
            Assert.True(v4[i - 1].End + 1u < v4[i].Start, $"IPv4 ranges {v4[i - 1]} and {v4[i]} overlap or touch");
        for (var i = 1; i < v6.Count; i++)
            Assert.True(v6[i - 1].End + UInt128.One < v6[i].Start, $"IPv6 ranges {v6[i - 1]} and {v6[i]} overlap or touch");

        // Adjacent allowed IPs 1.1.1.1..1.1.1.3 must be merged into a single excluded gap.
        Assert.Contains("1.0.0.0-1.1.1.0", ranges);
        Assert.Contains(ranges, r => r.StartsWith("1.1.1.4-", StringComparison.Ordinal));

        // Non-Internet IPv4 addresses are excluded (not blocked by the internet rule).
        foreach (var ip in new[]
        {
            "0.0.0.0", "0.255.255.255",
            "10.0.0.1", "10.255.255.254",
            "127.0.0.1", "127.255.255.255",
            "169.254.1.1",
            "172.16.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.255.254",
            "224.0.0.1", "255.255.255.255",
            "100.64.0.1", "100.127.255.254", // local subnet 100.64.0.0/10
            "1.1.1.1", "1.1.1.2", "1.1.1.3", "160.79.104.10", // allowed IPs
        })
        {
            Assert.False(ContainsV4(v4, IPAddress.Parse(ip)), $"{ip} should be excluded from blocked ranges");
        }

        // Unallowed public IPv4 addresses are covered (blocked).
        foreach (var ip in new[]
        {
            "1.0.0.0", "1.1.1.0", "1.1.1.4",
            "8.8.8.8", "9.9.9.9",
            "160.79.104.9", "160.79.104.11",
            "172.15.255.255", "172.32.0.0",
            "192.167.255.255", "192.169.0.0",
            "223.255.255.255",
        })
        {
            Assert.True(ContainsV4(v4, IPAddress.Parse(ip)), $"{ip} should be covered by blocked ranges");
        }

        // Non-Internet, local subnet, and allowed IPv6 addresses are excluded.
        foreach (var ip in new[]
        {
            "::", "::1",
            "fc00::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "ff02::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db8::dead:beef", // local subnet 2001:db8::/32
            "2607:6bc0::10", "2607:6bc0::11", // allowed IPs
        })
        {
            Assert.False(ContainsV6(v6, IPAddress.Parse(ip)), $"{ip} should be excluded from blocked ranges");
        }

        // Unallowed public IPv6 addresses are covered (blocked).
        foreach (var ip in new[]
        {
            "::2",
            "2001:4860:4860::8888",
            "2607:6bc0::9", "2607:6bc0::12",
            "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fec0::1",
        })
        {
            Assert.True(ContainsV6(v6, IPAddress.Parse(ip)), $"{ip} should be covered by blocked ranges");
        }
    }

    [Fact]
    public void DistinguishesInternetRulesFromLocalNetworkRules()
    {
        var localRule = Firewall.Parse("{1}",
            @"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\a.exe|Name=Revoke|Desc=revoke:pkg:Claude_pzs8sxrjxfjjc|EmbedCtxt=Revoke|");
        Assert.Equal(Client.Package("Claude_pzs8sxrjxfjjc"), localRule.RevokeClient);
        Assert.Null(localRule.RevokeInternetClient);

        var internetRule = Firewall.Parse("{2}",
            @"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\a.exe|Name=Revoke|Desc=revoke-internet:pkg:Claude_pzs8sxrjxfjjc|EmbedCtxt=Revoke|");
        Assert.Equal(Client.Package("Claude_pzs8sxrjxfjjc"), internetRule.RevokeInternetClient);
        Assert.Null(internetRule.RevokeClient);

        var foreignRule = Firewall.Parse("{3}",
            @"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\a.exe|Name=Other|Desc=revoke-internet:pkg:Claude_pzs8sxrjxfjjc|EmbedCtxt=Other|");
        Assert.Null(foreignRule.RevokeClient);
        Assert.Null(foreignRule.RevokeInternetClient);
    }

    [Fact]
    public void HelperPolicyChecksAndSerializesInternetBlockOperations()
    {
        var policy = new HelperPolicy([], [], [], new HelperState(), _ => null);
        var notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");

        Assert.Null(policy.Check(new ElevatedOp.BlockInternet("exe:x", "X", notepad, ["anthropic.com", "claude.ai"])));
        Assert.NotNull(policy.Check(new ElevatedOp.BlockInternet("exe:x", "X", @"C:\nowhere\missing.exe", ["anthropic.com"])));
        Assert.NotNull(policy.Check(new ElevatedOp.BlockInternet("exe:x", "X", "relative.exe", ["anthropic.com"])));
        Assert.NotNull(policy.Check(new ElevatedOp.BlockInternet("exe:x", new string('L', 201), notepad, ["anthropic.com"])));
        Assert.NotNull(policy.Check(new ElevatedOp.BlockInternet(new string('k', 1001), "X", notepad, ["anthropic.com"])));
        Assert.NotNull(policy.Check(new ElevatedOp.BlockInternet("exe:x", "X", notepad, [new string('a', 254)])));
        Assert.NotNull(policy.Check(new ElevatedOp.BlockInternet("exe:x", "X", notepad, [.. Enumerable.Repeat("a.com", 201)])));

        Assert.Null(policy.Check(new ElevatedOp.RemoveInternetBlocks("pkg:Claude_pzs8sxrjxfjjc")));
        Assert.NotNull(policy.Check(new ElevatedOp.RemoveInternetBlocks(new string('k', 1001))));

        List<ElevatedOp> ops =
        [
            new ElevatedOp.BlockInternet("pkg:Claude_pzs8sxrjxfjjc", "Claude", notepad, ["anthropic.com", "claude.ai"]),
            new ElevatedOp.RemoveInternetBlocks("pkg:Claude_pzs8sxrjxfjjc"),
        ];
        var json = JsonSerializer.Serialize(new HelperRequest(ops), Helper.Json);
        var roundTripped = JsonSerializer.Deserialize<HelperRequest>(json, Helper.Json)!.Ops;
        var block = Assert.IsType<ElevatedOp.BlockInternet>(roundTripped[0]);
        Assert.Equal("pkg:Claude_pzs8sxrjxfjjc", block.ClientKey);
        Assert.Equal("Claude", block.Label);
        Assert.Equal(notepad, block.Program);
        Assert.Equal(["anthropic.com", "claude.ai"], block.Hosts);
        Assert.Equal(new ElevatedOp.RemoveInternetBlocks("pkg:Claude_pzs8sxrjxfjjc"), roundTripped[1]);
    }

    [Fact]
    public void ParsesInternetAccessRequestUrl()
    {
        var req = AccessRequest.Parse("revoke://request?access=internet&minutes=10&reason=Push");
        Assert.NotNull(req);
        Assert.Equal(Pane.Internet, req.Pane);
        Assert.Equal(10, req.Minutes);
        Assert.Equal("Push", req.Reason);
        Assert.Null(req.ClaimedApp);
    }

    static (List<(uint Start, uint End)> V4, List<(UInt128 Start, UInt128 End)> V6) ParseRanges(IEnumerable<string> ranges)
    {
        var v4 = new List<(uint Start, uint End)>();
        var v6 = new List<(UInt128 Start, UInt128 End)>();
        foreach (var range in ranges)
        {
            var dash = range.IndexOf('-');
            var first = IPAddress.Parse(dash >= 0 ? range[..dash] : range);
            var second = IPAddress.Parse(dash >= 0 ? range[(dash + 1)..] : range);
            if (first.AddressFamily == AddressFamily.InterNetwork)
                v4.Add((ToUInt32(first), ToUInt32(second)));
            else
                v6.Add((ToUInt128(first), ToUInt128(second)));
        }
        return (v4, v6);
    }

    static bool ContainsV4(List<(uint Start, uint End)> ranges, IPAddress ip)
    {
        var v = ToUInt32(ip);
        return ranges.Any(r => v >= r.Start && v <= r.End);
    }

    static bool ContainsV6(List<(UInt128 Start, UInt128 End)> ranges, IPAddress ip)
    {
        var v = ToUInt128(ip);
        return ranges.Any(r => v >= r.Start && v <= r.End);
    }

    static uint ToUInt32(IPAddress ip)
    {
        Span<byte> bytes = stackalloc byte[4];
        ip.TryWriteBytes(bytes, out _);
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    static UInt128 ToUInt128(IPAddress ip)
    {
        Span<byte> bytes = stackalloc byte[16];
        ip.TryWriteBytes(bytes, out _);
        return BinaryPrimitives.ReadUInt128BigEndian(bytes);
    }
}
