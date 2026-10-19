using Xunit;

namespace Revoke.Core.Tests;

/// <summary>Which of a package's logo files the panel and settings draw.</summary>
public class LogoTests
{
    // ChatGPT's, trimmed: its Store logo (icon.png) and plain unplated logos are white.
    static readonly string[] ChatGpt =
    [
        "icon.png", "Square44x44Logo.png", "Square44x44Logo.scale-200.png",
        "Square44x44Logo.targetsize-16_altform-lightunplated.png", "Square44x44Logo.targetsize-16_altform-unplated.png",
        "Square44x44Logo.targetsize-24_altform-lightunplated.png", "Square44x44Logo.targetsize-24_altform-unplated.png",
        "Square44x44Logo.targetsize-48_altform-lightunplated.png", "Square44x44Logo.targetsize-48_altform-unplated.png",
        "Square44x44Logo.targetsize-256_altform-lightunplated.png", "Square44x44Logo.targetsize-256_altform-unplated.png",
    ];

    [Fact]
    public void PicksTheUnplatedLogoForEachBackground()
    {
        Assert.Equal("Square44x44Logo.targetsize-48_altform-unplated.png", Packages.Unplated(ChatGpt, "Square44x44Logo", "unplated"));
        Assert.Equal("Square44x44Logo.targetsize-48_altform-lightunplated.png", Packages.Unplated(ChatGpt, "Square44x44Logo", "lightunplated"));
    }

    [Fact]
    public void TakesTheBiggestWhenNoneIsBigEnough()
    {
        string[] small = ["Logo.targetsize-16_altform-unplated.png", "Logo.targetsize-32_altform-unplated.png", "Logo.targetsize-24_altform-unplated.png"];
        Assert.Equal("Logo.targetsize-32_altform-unplated.png", Packages.Unplated(small, "Logo", "unplated"));
        Assert.Null(Packages.Unplated(small, "Logo", "lightunplated"));
        Assert.Null(Packages.Unplated(["Logo.png", "Logo.scale-200.png"], "Logo", "unplated"));
    }

    [Fact]
    public void UsesTheLightLogoOnlyOnLightBackgrounds()
    {
        var logo = new AppLogo(@"C:\app\dark.png", @"C:\app\light.png");
        Assert.Equal(@"C:\app\light.png", logo.For(lightBackground: true));
        Assert.Equal(@"C:\app\dark.png", logo.For(lightBackground: false));
        Assert.Equal(@"C:\app\only.png", new AppLogo(@"C:\app\only.png").For(lightBackground: true));
    }
}
