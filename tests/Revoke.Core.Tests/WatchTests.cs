using Xunit;

namespace Revoke.Core.Tests;

public class WatchTests
{
    [Fact]
    public void CompleteExitCountsAsClosingAndReopeningArmsItAgain()
    {
        var watch = new Model.Watch();
        Assert.False(watch.Closed(running: true, hasWindow: true));
        Assert.True(watch.Closed(running: false, hasWindow: false));
        Assert.False(watch.Closed(running: false, hasWindow: false));
        Assert.False(watch.Closed(running: true, hasWindow: true));
        Assert.True(watch.Closed(running: false, hasWindow: false));
    }

    [Fact]
    public void TrayAppsCloseAfterTwoTicksWithoutAWindow()
    {
        var watch = new Model.Watch();
        Assert.False(watch.Closed(running: true, hasWindow: true));
        Assert.False(watch.Closed(running: true, hasWindow: false));
        Assert.True(watch.Closed(running: true, hasWindow: false));
        Assert.False(watch.Closed(running: true, hasWindow: false));
    }

    [Fact]
    public void ReplacingAWindowDoesNotCountAsClosing()
    {
        var watch = new Model.Watch();
        Assert.False(watch.Closed(running: true, hasWindow: true));
        Assert.False(watch.Closed(running: true, hasWindow: false));
        Assert.False(watch.Closed(running: true, hasWindow: true));
        Assert.False(watch.Closed(running: true, hasWindow: false));
        Assert.True(watch.Closed(running: true, hasWindow: false));
    }

    [Fact]
    public void HelpersThatNeverHadAWindowDoNotTriggerClosing()
    {
        var watch = new Model.Watch();
        Assert.False(watch.Closed(running: true, hasWindow: false));
        Assert.False(watch.Closed(running: true, hasWindow: false));
        Assert.False(watch.Closed(running: false, hasWindow: false));
    }
}
