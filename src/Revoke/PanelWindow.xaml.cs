using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Shapes;
using Revoke.Core;
using Windows.Graphics;
using Windows.UI;

namespace Revoke;

/// <summary>The panel above the tray icon: one switch per app and column.</summary>
public sealed partial class PanelWindow : Window
{
    const double PanelWidth = 660;
    const double ColumnWidth = 52;

    static readonly (Pane Pane, string Glyph, string Short, string Tip)[] Panes =
    [
        (Pane.Running, "", "Running", "Running: the app, its helpers and services"),
        (Pane.Startup, "", "Startup", "Starts by itself: at sign-in, or as a service with Windows"),
        (Pane.Screen, "", "Screen", "Screen capture (Settings › Privacy & security › Screenshots and apps)"),
        (Pane.Camera, "", "Camera", "Camera"),
        (Pane.Microphone, "", "Mic", "Microphone"),
        (Pane.Location, "", "Location", "Location"),
        (Pane.Network, "", "Network", "Local network: devices on your network connecting to it, and it connecting to them"),
    ];

    readonly Controller controller;
    readonly Dictionary<Client, RowView> rows = [];
    readonly Dictionary<string, BitmapImage> images = [];
    List<string> order = [];
    TrayIcon.RECT anchor;
    DateTime hiddenAt;
    bool updating;

    internal PanelWindow(Controller controller)
    {
        this.controller = controller;
        InitializeComponent();
        BuildColumnTitles();

        var presenter = OverlappedPresenter.Create();
        presenter.IsMaximizable = false;
        presenter.IsMinimizable = false;
        presenter.IsResizable = false;
        presenter.IsAlwaysOnTop = true;
        presenter.SetBorderAndTitleBar(hasBorder: true, hasTitleBar: false);
        AppWindow.SetPresenter(presenter);
        AppWindow.IsShownInSwitchers = false;

        Activated += (_, e) =>
        {
            if (e.WindowActivationState == WindowActivationState.Deactivated) Hide();
        };
        AppWindow.Closing += (_, e) =>
        {
            // Alt+F4 hides the panel; quitting is in the tray menu and settings.
            e.Cancel = true;
            Hide();
        };
        controller.Changed += Render;
        Render(controller.View);
    }

    public bool IsShown => AppWindow.IsVisible;

    /// <summary>Shows the panel above the tray icon, or hides it if it's showing. A click on
    /// the icon hides the panel by taking focus away first, so that click doesn't reopen it.</summary>
    internal void Toggle(TrayIcon.RECT iconRect)
    {
        if (IsShown)
        {
            Hide();
            return;
        }
        if (DateTime.UtcNow - hiddenAt < TimeSpan.FromMilliseconds(300)) return;
        anchor = iconRect;
        Place();
        AppWindow.Show();
        Activate();
        TrayIcon.SetForegroundWindow(Microsoft.UI.Win32Interop.GetWindowFromWindowId(AppWindow.Id));
        // Apps may have started or quit since the last tick.
        _ = controller.RefreshAsync();
    }

    void Hide()
    {
        if (!AppWindow.IsVisible) return;
        AppWindow.Hide();
        hiddenAt = DateTime.UtcNow;
    }

    /// <summary>Sizes the panel to its content and puts it next to the taskbar, by the icon.</summary>
    void Place()
    {
        var center = new PointInt32((anchor.left + anchor.right) / 2, (anchor.top + anchor.bottom) / 2);
        var area = DisplayArea.GetFromPoint(center, DisplayAreaFallback.Nearest).WorkArea;
        var scale = DpiAt(center) / 96.0;
        Root.Measure(new Windows.Foundation.Size(PanelWidth, double.PositiveInfinity));
        var w = (int)Math.Ceiling(PanelWidth * scale);
        var h = Math.Min((int)Math.Ceiling(Root.DesiredSize.Height * scale), area.Height);
        var margin = (int)(12 * scale);
        int x, y;
        if (anchor.left >= area.X + area.Width)
        {
            // Taskbar on the right.
            x = area.X + area.Width - w - margin;
            y = Math.Clamp(center.Y - h / 2, area.Y + margin, area.Y + area.Height - h - margin);
        }
        else if (anchor.right <= area.X)
        {
            // Taskbar on the left.
            x = area.X + margin;
            y = Math.Clamp(center.Y - h / 2, area.Y + margin, area.Y + area.Height - h - margin);
        }
        else
        {
            x = Math.Clamp(center.X - w / 2, area.X + margin, Math.Max(area.X, area.X + area.Width - w - margin));
            // Taskbar at the top, or (usually) the bottom.
            y = anchor.bottom <= area.Y ? area.Y + margin : area.Y + area.Height - h - margin;
        }
        // Windows 11 puts invisible resize borders around a bordered window, so the size
        // asked for is the client area's, and the frame goes around it.
        var frameW = AppWindow.Size.Width - AppWindow.ClientSize.Width;
        var frameH = AppWindow.Size.Height - AppWindow.ClientSize.Height;
        AppWindow.MoveAndResize(new RectInt32(x - frameW / 2, Math.Max(area.Y, y) - frameH / 2, w + frameW, h + frameH));
    }

    void Render(View view)
    {
        updating = true;
        var snapshot = view.Snapshot;
        Status.Text = snapshot.Status;
        FirewallNotice.IsOpen = !snapshot.CanReadFirewall;
        RevokeAll.IsEnabled = !view.Busy;
        Spinner.IsActive = view.Busy;
        Activity.Text = view.Activity is { Text.Length: > 0 } a ? $"{a.At:t} · {a.Text}" : "";
        Activity.Foreground = (Brush)Application.Current.Resources[view.Activity?.IsError == true
            ? "SystemFillColorCriticalBrush" : "TextFillColorSecondaryBrush"];
        ToolTipService.SetToolTip(Activity, string.IsNullOrEmpty(Activity.Text) ? null : Activity.Text);
        Footnote.Text = "Switching camera, microphone, location or screen capture on opens Settings, because only you can grant access there."
            + (view.HelperInstalled ? "" : " Services and firewall rules ask for admin, unless you install the helper in Settings.");

        // Sections and rows, rebuilt only when the set or order changes, so a switch with
        // keyboard focus keeps it across the updates every couple of seconds.
        var newOrder = new List<string> { "#watched" };
        newOrder.AddRange(snapshot.Watched.Select(r => r.Client.Key));
        if (snapshot.Watched.Count == 0) newOrder.Add("#none");
        if (snapshot.Others.Count > 0)
        {
            newOrder.Add("#others");
            newOrder.AddRange(snapshot.Others.Select(r => r.Client.Key));
        }
        foreach (var row in snapshot.AllRows)
        {
            if (!rows.TryGetValue(row.Client, out var rowView)) rows[row.Client] = rowView = new RowView(this, row.Client);
            rowView.Update(row, view.Busy, !view.HelperInstalled);
        }
        foreach (var gone in rows.Keys.Where(c => !snapshot.AllRows.Any(r => r.Client == c)).ToList()) rows.Remove(gone);
        if (!newOrder.SequenceEqual(order))
        {
            order = newOrder;
            List.Children.Clear();
            foreach (var key in order)
            {
                List.Children.Add(key switch
                {
                    "#watched" => SectionTitle("Watched"),
                    "#others" => SectionTitle("Other apps that can capture the screen"),
                    "#none" => new TextBlock
                    {
                        Text = "No watched apps are installed or running.",
                        Margin = new Thickness(8, 4, 8, 4),
                        Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
                    },
                    _ => rows[Client.FromKey(key)!].Root,
                });
            }
        }
        updating = false;
        if (IsShown) Place();
    }

    static TextBlock SectionTitle(string text) => new()
    {
        Text = text,
        Margin = new Thickness(8, 8, 8, 4),
        Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"],
        FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
        Foreground = (Brush)Application.Current.Resources["TextFillColorTertiaryBrush"],
    };

    void BuildColumnTitles()
    {
        AddColumns(Columns);
        for (var i = 0; i < Panes.Length; i++)
        {
            var (_, glyph, label, tip) = Panes[i];
            var stack = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, Spacing = 2 };
            stack.Children.Add(new FontIcon { Glyph = glyph, FontSize = 14 });
            stack.Children.Add(new TextBlock { Text = label, FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center });
            ToolTipService.SetToolTip(stack, tip);
            Grid.SetColumn(stack, i + 1);
            stack.Opacity = 0.7;
            Columns.Children.Add(stack);
        }
    }

    static void AddColumns(Grid grid)
    {
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        foreach (var _ in Panes) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(ColumnWidth) });
    }

    ImageSource? Image(string? path)
    {
        if (path is null) return null;
        if (!images.TryGetValue(path, out var image))
        {
            images[path] = image = new BitmapImage(new Uri(path)) { DecodePixelWidth = 48 };
        }
        return image;
    }

    async void Switch_Toggled(Client client, Pane pane, ToggleSwitch toggle)
    {
        if (updating) return;
        var on = toggle.IsOn;
        await controller.ActAsync(m => m.Set(client, pane, on));
    }

    async void RevokeAll_Click(object sender, RoutedEventArgs e) => await controller.ActAsync(m => m.RevokeAll());

    void Settings_Click(object sender, RoutedEventArgs e)
    {
        Hide();
        App.Current.ShowSettings();
    }

    void Root_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Escape) Hide();
    }

    /// <summary>One app's row, kept across updates.</summary>
    sealed class RowView
    {
        public Grid Root { get; } = new() { Padding = new Thickness(8, 6, 8, 6), CornerRadius = new CornerRadius(4), BorderThickness = new Thickness(1) };
        readonly Image icon = new() { Width = 24, Height = 24 };
        readonly Border glyph = new() { Width = 24, Height = 24, CornerRadius = new CornerRadius(4) };
        readonly TextBlock letter = new() { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, FontSize = 12 };
        readonly TextBlock name = new() { TextTrimming = TextTrimming.CharacterEllipsis };
        readonly TextBlock detail = new() { FontSize = 11, TextTrimming = TextTrimming.CharacterEllipsis };
        readonly Dictionary<Pane, CellView> cells = [];
        readonly PanelWindow panel;

        public RowView(PanelWindow panel, Client client)
        {
            this.panel = panel;
            var resources = Application.Current.Resources;
            Root.Background = (Brush)resources["CardBackgroundFillColorDefaultBrush"];
            Root.BorderBrush = (Brush)resources["CardStrokeColorDefaultBrush"];
            detail.Foreground = (Brush)resources["TextFillColorTertiaryBrush"];
            glyph.Background = (Brush)resources["ControlFillColorSecondaryBrush"];
            glyph.Child = letter;
            AddColumns(Root);

            var app = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, VerticalAlignment = VerticalAlignment.Center };
            var icons = new Grid();
            icons.Children.Add(glyph);
            icons.Children.Add(icon);
            app.Children.Add(icons);
            var text = new StackPanel();
            text.Children.Add(name);
            text.Children.Add(detail);
            app.Children.Add(text);
            ToolTipService.SetToolTip(app, client.Key);
            Root.Children.Add(app);

            for (var i = 0; i < Panes.Length; i++)
            {
                var pane = Panes[i].Pane;
                var cell = new CellView(Panes[i].Tip);
                cell.Switch.Toggled += (_, _) => panel.Switch_Toggled(client, pane, cell.Switch);
                Grid.SetColumn(cell.Root, i + 1);
                Root.Children.Add(cell.Root);
                cells[pane] = cell;
            }
        }

        public void Update(Row row, bool busy, bool askForAdmin)
        {
            name.Text = row.Name;
            letter.Text = row.Name[..1].ToUpperInvariant();
            icon.Source = panel.Image(row.Icon);
            glyph.Visibility = row.Icon is null ? Visibility.Visible : Visibility.Collapsed;
            detail.Text = Detail(row);
            ToolTipService.SetToolTip(detail, row.Helpers.Count > 0 ? "Helpers: " + Model.List(row.Helpers) : null);
            foreach (var (pane, cell) in cells) cell.Update(row.Cells[pane], row.Name, busy, askForAdmin);
        }

        static string Detail(Row row)
        {
            if (row.Deadline is { } deadline) return $"Stops at {deadline:t}";
            if (!row.IsOn(Pane.Running)) return "Not running";
            var parts = new List<string>();
            if (row.Processes > 0)
            {
                // Desktop tools like Claude Code run in a terminal and never have a window of their own.
                parts.Add(row.HasWindow ? "Open" : row.Client.Kind == ClientKind.Package ? "Running in the background" : "Running");
            }
            if (row.Helpers.Count > 0) parts.Add(row.Helpers.Count == 1 ? row.Helpers[0] : $"{row.Helpers.Count} helpers");
            if (row.Services.Count > 0) parts.Add("service");
            return parts.Count > 0 ? string.Join(" + ", parts) : "Running";
        }
    }

    sealed class CellView
    {
        public Grid Root { get; } = new() { Height = 32 };
        public ToggleSwitch Switch { get; } = new()
        {
            OnContent = null,
            OffContent = null,
            // The template keeps room for an On/Off label; this panel has none.
            MinWidth = 0,
            Width = 40,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
        };
        readonly TextBlock dash = new() { Text = "–", HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        // Using it right now: camera, microphone, location or screen capture.
        readonly Ellipse live = new()
        {
            Width = 8, Height = 8,
            HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 2, 4, 0),
            Fill = new SolidColorBrush(Color.FromArgb(255, 0xE8, 0x11, 0x23)),
        };
        // Blocked once, but the app has updated since.
        readonly FontIcon stale = new()
        {
            Glyph = "", FontSize = 11,
            HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 0, 2, 0),
            Foreground = (Brush)Application.Current.Resources["SystemFillColorCautionBrush"],
        };
        readonly string column;

        public CellView(string column)
        {
            this.column = column;
            dash.Foreground = (Brush)Application.Current.Resources["TextFillColorTertiaryBrush"];
            Root.Children.Add(Switch);
            Root.Children.Add(dash);
            Root.Children.Add(live);
            Root.Children.Add(stale);
        }

        public void Update(Cell cell, string appName, bool busy, bool askForAdmin)
        {
            Switch.Visibility = cell.Enabled ? Visibility.Visible : Visibility.Collapsed;
            dash.Visibility = cell.Enabled ? Visibility.Collapsed : Visibility.Visible;
            live.Visibility = cell.InUse ? Visibility.Visible : Visibility.Collapsed;
            stale.Visibility = cell.Stale ? Visibility.Visible : Visibility.Collapsed;
            if (Switch.IsOn != cell.On) Switch.IsOn = cell.On;
            Switch.IsEnabled = !busy;
            var help = cell.NeedsAdmin && cell.Enabled && askForAdmin ? cell.Help + " (asks for admin)" : cell.Help;
            ToolTipService.SetToolTip(Root, help);
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(Switch, $"{column} for {appName}");
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(Switch, help);
        }
    }

    // The DPI of the monitor at a point, to size the panel before it's on that monitor.

    static uint DpiAt(PointInt32 point)
    {
        var monitor = MonitorFromPoint(new POINT { x = point.X, y = point.Y }, 2); // MONITOR_DEFAULTTONEAREST
        return GetDpiForMonitor(monitor, 0, out var dpi, out _) == 0 ? dpi : 96;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct POINT { public int x, y; }

    [DllImport("user32.dll")]
    static extern nint MonitorFromPoint(POINT point, uint flags);

    [DllImport("shcore.dll")]
    static extern int GetDpiForMonitor(nint monitor, int type, out uint dpiX, out uint dpiY);
}
