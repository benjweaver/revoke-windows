using Microsoft.Win32;
using Xunit;

namespace Revoke.Core.Tests;

public class RegistryWatchTests
{
    /// <summary>A watch says a key changed when it or anything under it did, and only then.</summary>
    [Fact]
    public void SaysWhenAKeyOrAnythingUnderItChanged()
    {
        var path = $@"Software\revoke-test-{Guid.NewGuid():N}";
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(path);
            using var watch = new RegistryWatch(Registry.CurrentUser, path, subtree: true);
            Assert.True(watch.Changed());
            Assert.False(watch.Changed());

            using (var below = key.CreateSubKey(@"shell\open\command")) below.SetValue(null, "agent.exe \"%1\"");
            Assert.True(SoonChanged(watch));
            AssertQuiet(watch);

            key.SetValue("URL Protocol", "");
            Assert.True(SoonChanged(watch));
            AssertQuiet(watch);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(path, throwOnMissingSubKey: false);
        }
    }

    /// <summary>A key that isn't there can't be watched, so it's always read.</summary>
    [Fact]
    public void AlwaysSaysAMissingKeyChanged()
    {
        using var watch = new RegistryWatch(Registry.CurrentUser, $@"Software\revoke-test-{Guid.NewGuid():N}", subtree: true);
        Assert.True(watch.Changed());
        Assert.True(watch.Changed());
    }

    /// <summary>Once it has said so, it says nothing more until something else changes. A burst
    /// of changes can show twice: Windows keeps the ones made after the first notice for the
    /// next watch, so none is missed.</summary>
    static void AssertQuiet(RegistryWatch watch)
    {
        for (var i = 0; i < 50 && watch.Changed(); i++) Thread.Sleep(20);
        Thread.Sleep(200);
        Assert.False(watch.Changed());
    }

    /// <summary>Windows sets the event as the change is made, but give it a moment.</summary>
    static bool SoonChanged(RegistryWatch watch)
    {
        for (var i = 0; i < 50; i++)
        {
            if (watch.Changed()) return true;
            Thread.Sleep(20);
        }
        return false;
    }
}
