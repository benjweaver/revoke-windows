using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;
using Revoke.Core;
using Windows.Foundation;
using Windows.Graphics;
using Windows.System;

namespace Revoke;

/// <summary>
/// A topmost confirmation window for link prompts and access requests. No is always the
/// default, and long links open at line 1 in a scrollable monospaced box.
/// </summary>
public sealed partial class PromptWindow : Window
{
    readonly TaskCompletionSource<bool> result = new();
    bool answered;

    PromptWindow(string header, string? detail, bool monospaceDetail, string body, string? question)
    {
        InitializeComponent();
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "icon.ico"));
        AppWindow.TitleBar.PreferredTheme = TitleBarTheme.UseDefaultAppMode;
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsAlwaysOnTop = true;
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
            presenter.IsResizable = false;
        }

        HeaderText.Text = header;
        if (detail is not null)
        {
            DetailBox.Text = detail;
            DetailBox.FontFamily = new Microsoft.UI.Xaml.Media.FontFamily(monospaceDetail ? "Consolas" : "Segoe UI Variable");
            DetailBox.Visibility = Visibility.Visible;
        }
        BodyText.Text = body;
        if (question is not null)
        {
            QuestionText.Text = question;
            QuestionText.Visibility = Visibility.Visible;
        }

        Root.KeyDown += (_, e) =>
        {
            if (e.Key == VirtualKey.Escape)
            {
                e.Handled = true;
                Finish(false);
            }
        };
        Closed += (_, _) =>
        {
            if (!answered) result.TrySetResult(false);
        };
        Root.Loaded += (_, _) =>
        {
            SizeAndCenter();
            if (DetailBox.Visibility == Visibility.Visible)
            {
                DetailBox.Select(0, 0);
            }
            NoButton.Focus(FocusState.Programmatic);
        };
    }

    public static Task<bool> AskLinkAsync(LinkPrompt prompt)
    {
        var header = prompt.Handler.IsFile
            ? $"{prompt.Who} wants to open this file in {prompt.AppName}:"
            : $"{prompt.Who} wants to open {prompt.AppName} with this link:";

        var warning = prompt.Handler.IsFile
            ? $"Open it only if you just opened it yourself. A file can carry instructions for {prompt.AppName}."
            : $"Open it only if you just clicked it yourself. A link can carry instructions for {prompt.AppName}, like a prompt for it to run.";

        if (prompt.Shown.IsLong)
        {
            warning += $" This {(prompt.Handler.IsFile ? "path" : "link")} is long. Scroll through all of it before you decide.";
        }
        if (prompt.Shown.Omitted > 0)
        {
            warning += $"\n\nThe {(prompt.Handler.IsFile ? "path" : "link")} was cut after {Links.HardLimit:N0} characters ({prompt.Shown.Omitted:N0} left out).";
        }

        var window = new PromptWindow(header, prompt.Shown.Text, monospaceDetail: true, warning, $"Open {prompt.AppName}?");
        window.Activate();
        return window.result.Task;
    }

    public static Task<bool> AskAccessAsync(string header, string? reason, string body)
    {
        var window = new PromptWindow(header, reason, monospaceDetail: false, body, null);
        window.Activate();
        return window.result.Task;
    }

    void SizeAndCenter()
    {
        var hwnd = Microsoft.UI.Win32Interop.GetWindowFromWindowId(AppWindow.Id);
        var scale = GetDpiForWindow(hwnd) / 96.0;
        const double widthDip = 480;
        Root.Measure(new Size(widthDip, double.PositiveInfinity));
        var heightDip = Math.Clamp(Root.DesiredSize.Height + 48, 220, 620);
        var width = (int)Math.Ceiling(widthDip * scale);
        var height = (int)Math.Ceiling(heightDip * scale);
        var area = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        var x = area.X + (area.Width - width) / 2;
        var y = area.Y + (area.Height - height) / 2;
        AppWindow.MoveAndResize(new RectInt32(x, y, width, height));
    }

    void No_Click(object sender, RoutedEventArgs e) => Finish(false);

    void Yes_Click(object sender, RoutedEventArgs e) => Finish(true);

    void Finish(bool allow)
    {
        if (answered) return;
        answered = true;
        result.TrySetResult(allow);
        Close();
    }

    [LibraryImport("user32.dll")]
    private static partial uint GetDpiForWindow(nint hwnd);
}
