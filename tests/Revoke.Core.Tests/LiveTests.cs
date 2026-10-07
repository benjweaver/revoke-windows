using System.Diagnostics;
using Xunit;

namespace Revoke.Core.Tests;

/// <summary>Tests against this PC. They only read, except for stopping processes they start.</summary>
[Collection("Processes")]
public class LiveTests(ITestOutputHelper output)
{
    /// <summary>Stops a real process tree: cmd, and the ping it starts.</summary>
    [Fact]
    public void StopsAProcessAndWhatItStarted()
    {
        // Revoke never stops itself, even when asked to stop its own tree.
        var me = Processes.List().Single(p => p.Pid == (uint)Environment.ProcessId);
        var (none, noErrors) = Processes.KillTree([me], me.Pid);
        Assert.Equal(0, none);
        Assert.Empty(noErrors);

        using var parent = Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 60 127.0.0.1 > nul") { CreateNoWindow = true })!;
        Proc? child = null;
        for (var i = 0; i < 50 && child is null; i++)
        {
            var procs = Processes.List();
            var below = Processes.Descendants(procs, new HashSet<uint> { (uint)parent.Id });
            child = procs.FirstOrDefault(p => below.Contains(p.Pid) && p.Name.Equals("PING.EXE", StringComparison.OrdinalIgnoreCase));
            if (child is null) Thread.Sleep(100);
        }
        Assert.NotNull(child);

        var root = Processes.List().Single(p => p.Pid == (uint)parent.Id);
        var (killed, errors) = Processes.KillTree([root], (uint)Environment.ProcessId);
        Assert.Empty(errors);
        Assert.True(killed >= 2, $"killed {killed}");
        parent.WaitForExit();
        Assert.DoesNotContain(Processes.List(), p => p.Pid == child.Pid && p.Started == child.Started);
    }

    /// <summary>
    /// The Running switch, end to end, on a stand-in app: a copy of ping.exe under a name
    /// of its own, watched by a throwaway settings file. Nothing else is watched, so
    /// nothing else can be stopped.
    /// </summary>
    [Fact]
    public void RevokingRunningStopsAWatchedApp()
    {
        var folder = Directory.CreateTempSubdirectory("revoke-test-");
        var previous = Settings.FilePath;
        Settings.FilePath = Path.Combine(folder.FullName, "settings.json");
        try
        {
            var exe = Path.Combine(folder.FullName, "revoke-standin.exe");
            File.Copy(Path.Combine(Environment.SystemDirectory, "PING.EXE"), exe);
            using var standIn = Process.Start(new ProcessStartInfo(exe, "-n 60 127.0.0.1") { CreateNoWindow = true })!;
            var client = Client.FromPath(exe);

            try
            {
                // Watch only the stand-in. Unwatching an app can bring its helpers up as rows
                // of their own (the stand-in is one of Claude's, since Claude Code ran this
                // test), so this repeats until only the stand-in is left.
                var settings = new Settings { Added = [client.Key] };
                var model = new Model(settings);
                for (var i = 0; i < 5 && model.Snapshot.Watched.Any(r => r.Client != client); i++)
                {
                    foreach (var row in model.Snapshot.Watched.Where(r => r.Client != client)) settings.Removed.Add(row.Client.Key);
                    model.Refresh();
                }
                string Rows() => string.Join("; ", model.Snapshot.Watched.Select(r => $"{r.Name} running={r.IsOn(Pane.Running)} procs={r.Processes}"));
                output.WriteLine($"watched: {Rows()}");
                Assert.True(model.Snapshot.Watched.Select(r => r.Client).SequenceEqual([client]), $"watched: {Rows()}");
                Assert.True(model.Snapshot.Watched[0].IsOn(Pane.Running), $"watched: {Rows()}");

                var activity = model.Revoke([client], [Pane.Running], null, allowAdmin: false);
                output.WriteLine($"{activity.Text}; after: {Rows()}");
                Assert.False(activity.IsError, activity.Text);
                Assert.True(standIn.WaitForExit(2000), "the stand-in is still running");
                Assert.False(model.RowFor(client)?.IsOn(Pane.Running) ?? false, $"after: {Rows()}");
            }
            finally
            {
                if (!standIn.HasExited) standIn.Kill();
            }
        }
        finally
        {
            Settings.FilePath = previous;
            for (var i = 0; i < 20; i++)
            {
                try { folder.Delete(recursive: true); break; }
                catch (UnauthorizedAccessException) { Thread.Sleep(100); }
                catch (IOException) { Thread.Sleep(100); }
            }
        }
    }

    /// <summary>
    /// The installed helper, end to end: the pipe, the check that it's the real service,
    /// the policy, and running the script as SYSTEM. Every request is harmless: removing
    /// blocks for an app that doesn't exist, and two the helper has to decline.
    /// </summary>
    [Fact]
    public void TheInstalledHelperMakesAllowedChangesAndDeclinesTheRest()
    {
        Assert.SkipUnless(Helper.IsInstalled, "The helper isn't installed.");
        List<ElevatedOp> ops =
        [
            new ElevatedOp.RemoveBlocks("exe:c:\\revoke-probe\\does-not-exist.exe"),
            new ElevatedOp.StopService("EventLog"),
            new ElevatedOp.SetRuleEnabled("{00000000-0000-0000-0000-000000000000}", true),
        ];
        var watch = Stopwatch.StartNew();
        var reply = Helper.Send(ops);
        output.WriteLine($"reply in {watch.ElapsedMilliseconds} ms: error={reply?.Error ?? "none"}, declined=[{string.Join(", ", reply?.Rejected ?? [])}]");
        Assert.NotNull(reply);
        Assert.Null(reply.Error);
        Assert.Equal([1, 2], reply.Rejected);
        Assert.Equal(System.ServiceProcess.ServiceControllerStatus.Running,
            new System.ServiceProcess.ServiceController("EventLog").Status);
    }

    /// <summary>
    /// The native admin changes, run as this user. Removing Revoke's blocks for an app
    /// that doesn't exist reads the firewall and deletes nothing, so it succeeds; stopping
    /// a service that doesn't exist fails, and says so. Nothing here changes the PC.
    /// </summary>
    [Fact]
    public void AdminChangesReportWhatFailed()
    {
        var watch = Stopwatch.StartNew();
        var failures = AdminChanges.Apply(
        [
            new ElevatedOp.RemoveBlocks(@"exe:c:\revoke-probe\does-not-exist.exe"),
            new ElevatedOp.StopService("RevokeNoSuchService"),
        ]);
        output.WriteLine($"{watch.ElapsedMilliseconds} ms: {string.Join(" | ", failures)}");
        Assert.Single(failures);
        Assert.StartsWith("Stop RevokeNoSuchService:", failures[0]);
    }

    /// <summary>Reads everything and prints what the panel would show.</summary>
    [Fact]
    public void ReadsThisPc()
    {
        var watch = Stopwatch.StartNew();
        var model = new Model(new Settings());
        var first = watch.Elapsed;
        watch.Restart();
        model.Refresh();
        output.WriteLine($"first read {first.TotalMilliseconds:F0} ms, refresh {watch.Elapsed.TotalMilliseconds:F0} ms");
        output.WriteLine(model.Snapshot.Status);
        foreach (var row in model.Snapshot.AllRows)
        {
            var cells = string.Join(" ", Model.AllPanes.Select(p => row.Cells[p] switch
            {
                { Stale: true } => "stale",
                { Enabled: false, InUse: true } => "in-use",
                { Enabled: false } => "-",
                { On: true, InUse: true } => "IN-USE",
                { On: true } => "ON",
                _ => "off",
            }).Select(s => s.PadRight(7)));
            output.WriteLine($"{(row.Watched ? "W" : " ")} {row.Name,-22} {cells} procs={row.Processes} window={row.HasWindow} icon={row.Icon is not null} helpers=[{string.Join(", ", row.Helpers)}]");
        }
        Assert.NotEmpty(model.Snapshot.AllRows);
    }
}
