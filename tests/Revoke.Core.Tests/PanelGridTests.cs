using Xunit;

namespace Revoke.Core.Tests;

public class PanelGridTests
{
    [Fact]
    public void LayoutKeepsRoomForAppAndSwitchColumns()
    {
        Assert.Equal(11, PanelGrid.ColumnCount);
        Assert.Equal(876, PanelGrid.MinimumWidth);
        Assert.Equal(256, PanelGrid.MinimumWidth - PanelGrid.Padding - PanelGrid.ColumnCount * PanelGrid.ColumnWidth);
        Assert.DoesNotContain(Pane.Running, PanelGrid.AccessPanes);
        Assert.Contains(Pane.Internet, PanelGrid.AccessPanes);
    }

    [Theory]
    [InlineData(Pane.Running, true, true, false)]
    [InlineData(Pane.Internet, true, true, true)]
    [InlineData(Pane.Camera, true, false, false)]
    [InlineData(Pane.Links, false, true, false)]
    [InlineData(Pane.Links, true, true, true)]
    [InlineData(Pane.Service, true, true, true)]
    public void AllAccessIncludesOnlyRevocableAccess(Pane pane, bool on, bool enabled, bool expected)
    {
        var row = new Row(Client.Package("Test_test"), "Test", "", null, true,
            new Dictionary<Pane, Cell> { [pane] = new(on, false, enabled, false, false, "") },
            0, false, [], [], null);
        Assert.Equal(expected, PanelGrid.AllAccessOn(row));
    }
}
