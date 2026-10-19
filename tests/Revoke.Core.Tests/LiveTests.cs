using System.Diagnostics;
using System.ServiceProcess;
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

    /// <summary>The quick look at packages names the same ones the full read finds, or the
    /// model would read them all every minute, or miss a change.</summary>
    [Fact]
    public void NamesThePackagesItReads() =>
        Assert.True(Packages.FullNames().SetEquals(Packages.Installed().Select(p => p.FullName)));

    /// <summary>Whether each service runs, as the service manager says, and not for one that
    /// isn't there.</summary>
    [Fact]
    public void ReadsWhetherServicesRun()
    {
        var all = ServiceController.GetServices();
        var services = all.Select(s => new Service(s.ServiceName, s.DisplayName, Client.Package("test"), "", 3, false)).ToList();
        services.Add(new Service($"revoke-test-{Guid.NewGuid():N}", "", Client.Package("test"), "", 3, true));
        var read = Services.WithStatus(services);
        Assert.Contains(read, s => s.Name == "RpcSs" && s.Running);
        Assert.False(read[^1].Running);
        // A service can start or stop meanwhile, so any that differ are asked about again.
        var differ = read.SkipLast(1).Where(s => s.Running != Running(s.Name)).ToList();
        Assert.All(Services.WithStatus(differ), s => Assert.Equal(Running(s.Name), s.Running));
        foreach (var service in all) service.Dispose();

        static bool Running(string name)
        {
            using var controller = new ServiceController(name);
            return controller.Status != ServiceControllerStatus.Stopped;
        }
    }

    /// <summary>The listing says what each process runs and when it started, the second time
    /// too, when it remembers processes it has seen rather than opening them again.</summary>
    [Fact]
    public void ListsProcessesWithTheirProgramsAndStartTimes()
    {
        using var me = Process.GetCurrentProcess();
        foreach (var listed in new[] { Processes.List(), Processes.List() })
        {
            var self = listed.Single(p => p.Pid == (uint)me.Id);
            Assert.Equal(Environment.ProcessPath, self.Path, ignoreCase: true);
            Assert.Equal(Path.GetFileName(Environment.ProcessPath), self.Name, ignoreCase: true);
            Assert.Equal(new DateTimeOffset(me.StartTime), Processes.Time(self.Started));
            Assert.Contains(listed, p => p.Pid == self.Parent);
            Assert.Contains(listed, p => p.Pid == 4 && p.Name == "System");
        }
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
        var previousLog = Log.FilePath;
        Settings.FilePath = Path.Combine(folder.FullName, "settings.json");
        // What the test does goes in a log of its own, not the person's.
        Log.FilePath = Path.Combine(folder.FullName, "Revoke.log");
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
            Log.FilePath = previousLog;
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

    /// <summary>
    /// Switches a real inbound allow rule off and on by its ID, as Revoke does for an app's
    /// "allow access" rules, then deletes it. Needs admin, so it only runs elevated.
    /// </summary>
    [Fact]
    public void SwitchesAnInboundRuleOffAndOnByItsId()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        Assert.SkipUnless(new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator),
            "Changing firewall rules needs admin.");
        var name = $"Revoke test {Guid.NewGuid():N}";
        void Netsh(string arguments)
        {
            using var netsh = Process.Start(new ProcessStartInfo("netsh.exe", arguments) { CreateNoWindow = true, UseShellExecute = false })!;
            netsh.WaitForExit();
            Assert.Equal(0, netsh.ExitCode);
        }
        FirewallRule Rule() => Firewall.Read()!.Single(r => r.Name == name);
        Netsh($"advfirewall firewall add rule name=\"{name}\" dir=in action=allow program=\"{Environment.SystemDirectory}\\PING.EXE\" enable=yes");
        try
        {
            var id = Rule().Id;
            Assert.True(Rule().Active);
            Assert.Empty(AdminChanges.Apply([new ElevatedOp.SetRuleEnabled(id, false)]));
            Assert.False(Rule().Active);
            Assert.Empty(AdminChanges.Apply([new ElevatedOp.SetRuleEnabled(id, true)]));
            Assert.True(Rule().Active);
        }
        finally
        {
            Netsh($"advfirewall firewall delete rule name=\"{name}\"");
        }
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
