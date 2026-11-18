using System.Text.Json;
using Xunit;

namespace Revoke.Core.Tests;

public class SettingsTests
{
    [Fact]
    public void RepairsNullCollectionsFromMalformedSavedSettings()
    {
        var settings = JsonSerializer.Deserialize<Settings>("""
            {"Added":null,"Removed":null,"Hidden":null,"DisabledRules":null,
             "ServiceStarts":null,"KeepStopped":["ExampleService"],"BlockLinks":null,
             "ExtraInternetHosts":null,"LimitMinutes":999}
            """);

        Assert.NotNull(settings);
        settings.RepairAfterLoad();

        Assert.Empty(settings.Added);
        Assert.Empty(settings.Removed);
        Assert.Empty(settings.Hidden);
        Assert.Empty(settings.DisabledRules);
        Assert.Empty(settings.ServiceStarts);
        Assert.Contains("exampleservice", settings.KeepStopped);
        Assert.Empty(settings.BlockLinks);
        Assert.Empty(settings.ExtraInternetHosts);
        Assert.Equal(30, settings.LimitMinutes);
    }
}
