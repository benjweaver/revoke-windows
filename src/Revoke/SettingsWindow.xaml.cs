using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Revoke.Core;
using Windows.Graphics;

namespace Revoke;

/// <summary>The settings window: automatic stops, which apps are watched, and sign-in.</summary>
public sealed partial class SettingsWindow : Window
{
    readonly Controller controller;
    readonly Dictionary<Client, (Grid Card, ToggleSwitch Switch)> appCards = [];
    List<Client> appOrder = [];
    bool updating;

    internal SettingsWindow(Controller controller)
    {
        this.controller = controller;
        InitializeComponent();
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "icon.ico"));
        // The title bar follows light and dark mode, as the content does.
        AppWindow.TitleBar.PreferredTheme = Microsoft.UI.Windowing.TitleBarTheme.UseDefaultAppMode;
        var scale = GetDpiForWindow(Microsoft.UI.Win32Interop.GetWindowFromWindowId(AppWindow.Id)) / 96.0;
        AppWindow.Resize(new SizeInt32((int)(560 * scale), (int)(760 * scale)));

        foreach (var minutes in Settings.TimeLimits)
        {
            Limit.Items.Add(new ComboBoxItem { Content = Settings.Describe(minutes), Tag = minutes });
        }
        controller.Changed += Render;
        Closed += (_, _) => controller.Changed -= Render;
        Render(controller.View);
    }

    void Render(View view)
    {
        updating = true;
        RevokeOnClose.IsOn = view.RevokeOnClose;
        RevokeAfterLimit.IsOn = view.RevokeAfterLimit;
        RevokeOnLock.IsOn = view.RevokeOnLock;
        LaunchAtLogin.IsOn = view.LaunchAtLogin;
        Limit.SelectedIndex = Array.IndexOf(Settings.TimeLimits, view.LimitMinutes);
        Limit.IsEnabled = view.RevokeAfterLimit;

        foreach (var app in view.Known)
        {
            if (!appCards.TryGetValue(app.Client, out var card)) appCards[app.Client] = card = MakeCard(app);
            if (card.Switch.IsOn != app.Watched) card.Switch.IsOn = app.Watched;
        }
        var order = view.Known.Select(a => a.Client).ToList();
        if (!order.SequenceEqual(appOrder))
        {
            appOrder = order;
            Apps.Children.Clear();
            foreach (var client in order) Apps.Children.Add(appCards[client].Card);
            if (order.Count == 0)
            {
                Apps.Children.Add(new TextBlock { Text = "Open an app to add it here.", Margin = new Thickness(2, 0, 0, 0) });
            }
        }
        updating = false;
    }

    (Grid, ToggleSwitch) MakeCard(KnownApp app)
    {
        var card = new Grid { Style = FindStyle("Card") };
        card.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        card.ColumnDefinitions.Add(new ColumnDefinition());
        card.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        FrameworkElement icon = app.Icon is { } path
            ? new Image { Source = new BitmapImage(new Uri(path)) { DecodePixelWidth = 48 }, Width = 24, Height = 24 }
            : new Border
            {
                Width = 24, Height = 24, CornerRadius = new CornerRadius(4),
                Background = (Brush)Application.Current.Resources["ControlFillColorSecondaryBrush"],
                Child = new TextBlock
                {
                    Text = app.Name[..1].ToUpperInvariant(), FontSize = 12,
                    HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                },
            };
        icon.VerticalAlignment = VerticalAlignment.Center;
        card.Children.Add(icon);

        var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        text.Children.Add(new TextBlock { Text = app.Name });
        text.Children.Add(new TextBlock
        {
            Text = app.Publisher.Length > 0 ? app.Publisher : "Unsigned",
            Style = FindStyle("Hint"),
        });
        ToolTipService.SetToolTip(text, app.Client.Key);
        Grid.SetColumn(text, 1);
        card.Children.Add(text);

        var toggle = new ToggleSwitch { IsOn = app.Watched };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(toggle, $"Watch {app.Name}");
        toggle.Toggled += async (_, _) =>
        {
            if (!updating) await controller.SetWatchedAsync(app.Client, toggle.IsOn);
        };
        Grid.SetColumn(toggle, 2);
        card.Children.Add(toggle);
        return (card, toggle);
    }

    Style FindStyle(string key) => (Style)((StackPanel)((ScrollViewer)Content).Content).Resources[key];

    async void Option_Toggled(object sender, RoutedEventArgs e)
    {
        if (updating) return;
        var toggle = (ToggleSwitch)sender;
        var on = toggle.IsOn;
        if (toggle == LaunchAtLogin)
        {
            controller.SetLaunchAtLogin(on);
            return;
        }
        await controller.ChangeSettingsAsync(settings =>
        {
            if (toggle == RevokeOnClose) settings.RevokeOnClose = on;
            else if (toggle == RevokeOnLock) settings.RevokeOnLock = on;
            else if (toggle == RevokeAfterLimit) settings.SetRevokeAfterLimit(on);
        });
    }

    async void Limit_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (updating || Limit.SelectedItem is not ComboBoxItem { Tag: int minutes }) return;
        await controller.ChangeSettingsAsync(settings => settings.LimitMinutes = minutes);
    }

    void Quit_Click(object sender, RoutedEventArgs e) => App.Current.Quit();

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern uint GetDpiForWindow(nint hwnd);
}
