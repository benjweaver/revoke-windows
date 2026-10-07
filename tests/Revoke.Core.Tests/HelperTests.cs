using System.Text.Json;
using Xunit;

namespace Revoke.Core.Tests;

/// <summary>What the helper agrees to do without a UAC prompt. Anything a program running
/// as the user could send it has to be safe to do.</summary>
public class HelperTests
{
    const string Claude = @"C:\Program Files\WindowsApps\Claude_2.16120.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe";
    const string Backup = @"C:\Program Files\Backup\agent.exe";

    static HelperPolicy Policy(HelperState? state = null) => new(
        [
            new FirewallRule("{in-allow}", "Claude", Inbound: true, Allow: true, Active: true, Claude, null, null),
            new FirewallRule("{out-allow}", "Claude", Inbound: false, Allow: true, Active: true, Claude, null, null),
            new FirewallRule("{in-block}", "Something", Inbound: true, Allow: false, Active: true, Backup, null, null),
        ],
        [
            new Service("CoworkVMService", "Claude", Client.FromPath(Claude), Claude, Start: 2, Running: true),
            new Service("BackupAgent", "Backup", Client.FromPath(Backup), Backup, Start: 2, Running: true),
        ],
        [(false, "Claude", Claude), (false, "Backup", Backup)],
        state ?? new HelperState(),
        program => program == Claude ? "Anthropic, PBC" : "Backup Corp");

    [Fact]
    public void SwitchesOffInboundAllowRulesOnly()
    {
        var policy = Policy();
        Assert.Null(policy.Check(new ElevatedOp.SetRuleEnabled("{in-allow}", false)));
        Assert.NotNull(policy.Check(new ElevatedOp.SetRuleEnabled("{out-allow}", false)));
        Assert.NotNull(policy.Check(new ElevatedOp.SetRuleEnabled("{in-block}", false)));
        Assert.NotNull(policy.Check(new ElevatedOp.SetRuleEnabled("{missing}", false)));
    }

    [Fact]
    public void SwitchesBackOnOnlyWhatItSwitchedOff()
    {
        Assert.NotNull(Policy().Check(new ElevatedOp.SetRuleEnabled("{in-allow}", true)));
        Assert.NotNull(Policy().Check(new ElevatedOp.SetRuleEnabled("{in-block}", true)));
        var state = new HelperState { DisabledRules = ["{in-allow}"] };
        Assert.Null(Policy(state).Check(new ElevatedOp.SetRuleEnabled("{in-allow}", true)));
    }

    [Fact]
    public void BlocksOnlyProgramsThatExist()
    {
        var notepad = Path.Combine(Environment.SystemDirectory, "notepad.exe");
        Assert.Null(Policy().Check(new ElevatedOp.BlockLocalNetwork("exe:x", "X", notepad)));
        Assert.NotNull(Policy().Check(new ElevatedOp.BlockLocalNetwork("exe:x", "X", @"C:\nowhere\x.exe")));
        Assert.NotNull(Policy().Check(new ElevatedOp.BlockLocalNetwork("exe:x", "X", "relative.exe")));
        Assert.Null(Policy().Check(new ElevatedOp.RemoveBlocks("pkg:Claude_pzs8sxrjxfjjc")));
    }

    [Fact]
    public void TouchesOnlyWatchedDevelopersServices()
    {
        var policy = Policy();
        Assert.Null(policy.Check(new ElevatedOp.StopService("CoworkVMService")));
        Assert.Null(policy.Check(new ElevatedOp.SetServiceStart("CoworkVMService", 3)));
        Assert.NotNull(policy.Check(new ElevatedOp.StopService("BackupAgent")));
        Assert.NotNull(policy.Check(new ElevatedOp.SetServiceStart("BackupAgent", 3)));
        Assert.NotNull(policy.Check(new ElevatedOp.StopService("NoSuchService")));
    }

    [Fact]
    public void PutsBackOnlyTheStartTypeItChanged()
    {
        Assert.NotNull(Policy().Check(new ElevatedOp.SetServiceStart("CoworkVMService", 2)));
        Assert.NotNull(Policy().Check(new ElevatedOp.SetServiceStart("CoworkVMService", 4)));
        var state = new HelperState { ServiceStarts = { ["CoworkVMService"] = 2 } };
        Assert.Null(Policy(state).Check(new ElevatedOp.SetServiceStart("CoworkVMService", 2)));
        Assert.NotNull(Policy(state).Check(new ElevatedOp.SetServiceStart("CoworkVMService", 4)));
    }

    [Fact]
    public void SwitchesOnlyWatchedDevelopersMachineStartup()
    {
        Assert.Null(Policy().Check(new ElevatedOp.SetMachineStartup(false, "Claude", false)));
        Assert.NotNull(Policy().Check(new ElevatedOp.SetMachineStartup(false, "Backup", false)));
        // The 32-bit list has no Claude entry.
        Assert.NotNull(Policy().Check(new ElevatedOp.SetMachineStartup(true, "Claude", false)));
    }

    [Fact]
    public void ChangesSurviveTheTripOverThePipe()
    {
        List<ElevatedOp> ops =
        [
            new ElevatedOp.StopService("CoworkVMService"),
            new ElevatedOp.SetServiceStart("CoworkVMService", 3),
            new ElevatedOp.SetRuleEnabled("{in-allow}", false),
            new ElevatedOp.BlockLocalNetwork("pkg:A_b", "Ben\u2019s app", @"C:\a.exe"),
            new ElevatedOp.RemoveBlocks("pkg:A_b"),
            new ElevatedOp.SetMachineStartup(true, "Claude", true),
        ];
        var json = JsonSerializer.Serialize(new HelperRequest(ops), Helper.Json);
        Assert.DoesNotContain('\n', json);
        Assert.Equal(ops, JsonSerializer.Deserialize<HelperRequest>(json, Helper.Json)!.Ops);
        // Unknown kinds of change don't deserialize into something the helper would run.
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<HelperRequest>(
            """{"ops":[{"op":"runAnything","command":"calc"}]}""", Helper.Json));
    }

    [Fact]
    public void PublishersOfPackagedProgramsComeFromTheirManifests()
    {
        // A "WindowsApps" folder anywhere else is just a folder.
        Assert.Null(HelperPolicy.PublisherOf(@"C:\Users\Public\WindowsApps\Claude_1.0.0.0_x64__pzs8sxrjxfjjc\x.exe"));
        // notepad.exe is signed by Microsoft through a catalog, not inside the file.
        Assert.Null(HelperPolicy.PublisherOf(Path.Combine(Environment.SystemDirectory, "notepad.exe")));
    }

    /// <summary>Revoke recognizes the helper by asking the service manager which process the
    /// service runs as, which works for a standard user (unlike reading a SYSTEM process's path).</summary>
    [Fact]
    public void ReadsAServicesProcessWithoutAdmin()
    {
        var pid = Helper.ServiceProcessId("EventLog");
        Assert.NotNull(pid);
        Assert.Contains(Processes.List(), p => p.Pid == pid && p.Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Null(Helper.ServiceProcessId("NoSuchServiceAnywhere"));
    }
}
