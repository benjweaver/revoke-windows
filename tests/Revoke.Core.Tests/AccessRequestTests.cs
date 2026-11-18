using Xunit;

namespace Revoke.Core.Tests;

public class AccessRequestTests
{
    [Fact]
    public void ParsesValidRequestsAndRejectsInvalidOnes()
    {
        var req = AccessRequest.Parse("revoke://request?access=local-network&minutes=10&reason=Reach%20the%20VM");
        Assert.NotNull(req);
        Assert.Equal(Pane.Network, req.Pane);
        Assert.Equal(10, req.Minutes);
        Assert.Equal("Reach the VM", req.Reason);
        Assert.Null(req.ClaimedApp);

        // Privacy permissions map to their panes.
        Assert.Equal(Pane.Camera, AccessRequest.Parse("revoke://request?access=camera")?.Pane);
        Assert.Equal(Pane.Microphone, AccessRequest.Parse("revoke://request?access=microphone")?.Pane);
        Assert.Equal(Pane.Location, AccessRequest.Parse("revoke://request?access=location")?.Pane);
        Assert.Equal(Pane.Screen, AccessRequest.Parse("revoke://request?access=screen-recording")?.Pane);

        // Running, startup, service, and links cannot be requested.
        Assert.Null(AccessRequest.Parse("revoke://request?access=running"));
        Assert.Null(AccessRequest.Parse("revoke://request?access=links"));
        Assert.Null(AccessRequest.Parse("revoke://request?access=startup"));
        Assert.Null(AccessRequest.Parse("revoke://request?access=service"));
        Assert.Null(AccessRequest.Parse("https://example.com/?access=local-network"));
        Assert.Null(AccessRequest.Parse("revoke://other?access=local-network"));
        Assert.Null(AccessRequest.Parse("revoke://request?access=internet&reason=" + new string('x', AccessRequest.MaxUrlChars)));
    }

    [Fact]
    public async Task BoundsPipeLinesBeforeTheSenderCloses()
    {
        using var exact = new StreamReader(new MemoryStream(System.Text.Encoding.UTF8.GetBytes("abc\r\nextra")));
        Assert.Equal("abc", await BoundedLine.ReadAsync(exact, 3, CancellationToken.None));

        using var tooLong = new StreamReader(new MemoryStream(System.Text.Encoding.UTF8.GetBytes("abcd\n")));
        Assert.Null(await BoundedLine.ReadAsync(tooLong, 3, CancellationToken.None));

        using var noNewline = new StreamReader(new MemoryStream(System.Text.Encoding.UTF8.GetBytes("abc")));
        Assert.Equal("abc", await BoundedLine.ReadAsync(noNewline, 3, CancellationToken.None));
    }

    [Fact]
    public void ClampsMinutesAndFirstParameterWins()
    {
        var low = AccessRequest.Parse("revoke://request?access=local-network&minutes=0");
        Assert.Equal(1, low?.Minutes);

        var high = AccessRequest.Parse("revoke://request?access=local-network&minutes=9999");
        Assert.Equal(AccessRequest.MaxMinutes, high?.Minutes);

        var dup = AccessRequest.Parse("revoke://request?access=local-network&reason=First&reason=Second&minutes=15&minutes=240");
        Assert.Equal("First", dup?.Reason);
        Assert.Equal(15, dup?.Minutes);
    }

    [Fact]
    public void EscapesAndCapsReason()
    {
        var longReason = new string('x', AccessRequest.ReasonLimit + 50);
        var req = AccessRequest.Parse($"revoke://request?access=local-network&reason={longReason}");
        Assert.Equal(AccessRequest.ReasonLimit, req?.Reason?.Length);

        var rtl = AccessRequest.Parse("revoke://request?access=local-network&reason=check%20\u202Etxt");
        Assert.Equal(@"check \u202Etxt", rtl?.Reason);
    }

    [Fact]
    public void TracesAppsBehindRequestingProcess()
    {
        Proc P(uint pid, uint parent, string path, long started = 10) =>
            new(pid, parent, Path.GetFileName(path), path, null, started);

        var procs = new[]
        {
            P(10, 1, @"C:\Apps\Claude\claude.exe", 1),
            P(20, 10, @"C:\Windows\System32\cmd.exe", 2),
            P(30, 20, @"C:\Program Files\Revoke\Revoke.exe", 3),
        };

        var apps = AccessRequest.AppsBehind(30, procs, selfPid: 1);
        Assert.Equal([Client.FromPath(@"C:\Windows\System32\cmd.exe"), Client.FromPath(@"C:\Apps\Claude\claude.exe")], apps);

        // A packaged process uses its package family instead of its raw path.
        var packaged = new[]
        {
            new Proc(10, 1, "claude.exe", @"C:\Program Files\WindowsApps\Claude\claude.exe", "Claude_abc123", 1),
            P(20, 10, @"C:\Windows\System32\cmd.exe", 2),
        };
        Assert.Equal([Client.FromPath(@"C:\Windows\System32\cmd.exe"), Client.Package("Claude_abc123")],
            AccessRequest.AppsBehind(20, packaged, selfPid: 1));

        // A reused PID with a later start time stops the walk.
        var reused = new[]
        {
            P(10, 1, @"C:\Apps\Claude\claude.exe", 100),
            P(20, 10, @"C:\Windows\System32\cmd.exe", 2),
            P(30, 20, @"C:\Program Files\Revoke\Revoke.exe", 3),
        };
        Assert.Equal([Client.FromPath(@"C:\Windows\System32\cmd.exe")], AccessRequest.AppsBehind(30, reused, selfPid: 1));
    }

    [Fact]
    public void DescribesArbitraryDurationsAccurately()
    {
        Assert.Equal("1 minute", Settings.Describe(1));
        Assert.Equal("15 minutes", Settings.Describe(15));
        Assert.Equal("1 hour", Settings.Describe(60));
        Assert.Equal("1 hour 59 minutes", Settings.Describe(119));
        Assert.Equal("2 hours", Settings.Describe(120));
        Assert.Equal("2 hours 1 minute", Settings.Describe(121));
    }
}
