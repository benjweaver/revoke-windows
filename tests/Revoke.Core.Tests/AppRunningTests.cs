using Xunit;

namespace Revoke.Core.Tests;

public class AppRunningTests
{
    const string Family = "OpenAI.Codex_2p2nqsd0c76g0";
    const string Package = @"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__2p2nqsd0c76g0";
    static readonly string ServiceProgram = $@"{Package}\app\resources\codex-windows-sandbox-service.exe";
    static readonly Service Sandbox = new("CodexSandboxService.OpenAI.Codex", "Codex Sandbox", Client.Package(Family),
        ServiceProgram, 3, true, Packaged: true);

    static Proc Services => new(700, 4, "services.exe", @"C:\Windows\System32\services.exe", null, 10);
    static Proc ServiceProc => new(900, 700, "codex-windows-sandbox-service.exe", ServiceProgram, Family, 20);
    static Proc ChatGpt => new(1000, 50, "ChatGPT.exe", $@"{Package}\app\ChatGPT.exe", Family, 30);

    static bool Running(Proc[] all) =>
        Model.AppRunning(all, all.Where(p => p.Family == Family), [Sandbox], Family);

    [Fact]
    public void ServiceAloneDoesNotCountAsTheApp()
    {
        Assert.False(Running([Services, ServiceProc]));
    }

    [Fact]
    public void AppWindowCountsAsRunning()
    {
        Assert.True(Running([Services, ServiceProc, ChatGpt]));
    }

    [Fact]
    public void WhatTheServiceStartedDoesNotCountEvenWithThePackageIdentity()
    {
        var runner = new Proc(901, 900, "codex-command-runner.exe", $@"{Package}\app\codex-command-runner.exe", Family, 25);
        Assert.False(Running([Services, ServiceProc, runner]));
    }

    [Fact]
    public void ServiceProcessWithoutAPathIsMatchedByName()
    {
        var hidden = ServiceProc with { Path = null };
        Assert.False(Running([Services, hidden]));
    }

    [Fact]
    public void CodexCliFromATerminalCountsAsChatGpt()
    {
        var cli = new Proc(2000, 1900, "codex.exe", @"C:\Users\user\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.exe", null, 40);
        Assert.True(Running([Services, ServiceProc, cli]));
    }

    [Fact]
    public void CodexTheServiceStartedDoesNotCount()
    {
        var spawned = new Proc(902, 900, "codex.exe", @"C:\Users\user\AppData\Local\OpenAI\Codex\bin\1\codex.exe", null, 26);
        Assert.False(Running([Services, ServiceProc, spawned]));
    }

    [Fact]
    public void CodexCliKeepsOnlyChatGptsServices()
    {
        Proc[] all = [new(2000, 1900, "codex.exe", @"C:\tools\codex.exe", null, 40)];
        Assert.False(Model.AppRunning(all, [], [Sandbox], "Claude_pzs8sxrjxfjjc"));
    }

    [Fact]
    public void CodexInsideChatGptsPackageIsNotACli()
    {
        Assert.False(Model.CodexCliRunning([new(3000, 1000, "codex.exe", $@"{Package}\app\codex.exe", Family, 50)]));
        Assert.True(Model.CodexCliRunning([new(3000, 1000, "CODEX.EXE", @"C:\tools\codex.exe", null, 50)]));
        Assert.False(Model.CodexCliRunning([ChatGpt]));
    }
}
