namespace Revoke.Core;

/// <summary>Shared sizing and aggregate state for the panel grid.</summary>
public static class PanelGrid
{
    public const double ColumnWidth = 52;
    public const double AppWidth = 256;
    public const double Padding = 48;
    public static int ColumnCount => Enum.GetValues<Pane>().Length + 1;
    public static double MinimumWidth => AppWidth + Padding + ColumnCount * ColumnWidth;
    public static bool AllAccessOn(Row row) => row.Cells.Any(pair =>
        pair.Key != Pane.Running && pair.Value.Enabled && pair.Value.On);
    public static readonly Pane[] AccessPanes = Enum.GetValues<Pane>().Where(p => p != Pane.Running).ToArray();
}
