using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace Revoke;

/// <summary>Revoke lives in the notification area: no main window, a panel above its
/// icon, and a settings window on request.</summary>
public partial class App : Application
{
    const string InstanceName = @"Local\dev.benjweaver.Revoke";

    public static new App Current => (App)Application.Current;

    Mutex? instance;
    EventWaitHandle? showSettings;
    TrayIcon? tray;
    Controller? controller;
    PanelWindow? panel;
    SettingsWindow? settings;

    public App()
    {
        InitializeComponent();
        // Closing the settings window leaves Revoke running in the tray.
        DispatcherShutdownMode = DispatcherShutdownMode.OnExplicitShutdown;
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        // Windows opened Revoke in an app's place, for a link or a file: ask, then go. This
        // runs beside the Revoke in the tray, or without it, and needs nothing else.
        var command = Environment.GetCommandLineArgs();
        if (command is [_, Revoke.Core.Links.Flag, var key, var verb, var target])
        {
            Revoke.Core.Links.Handle(key, verb, target);
            Exit();
            return;
        }
        // The uninstaller puts every app's own entries back. Inside another app's container
        // that would change nothing, so it says so with exit code 2 instead.
        if (command is [_, "--restore-links"])
        {
            if (Revoke.Core.Container.IsCaptured()) Environment.Exit(2);
            Revoke.Core.Links.UnblockAll();
            Environment.Exit(0);
        }
        // Started from inside another app's container (a terminal in Claude Code or Codex,
        // say), nothing Revoke changed would really change. Start again outside it.
        if (Revoke.Core.Container.IsCaptured())
        {
            Revoke.Core.Container.RelaunchOutside(Environment.ProcessPath!);
            Exit();
            return;
        }

        // One Revoke at a time: opening it again brings up its settings.
        instance = new Mutex(true, InstanceName, out var first);
        if (!first)
        {
            if (EventWaitHandle.TryOpenExisting(InstanceName + ".show", out var other)) other.Set();
            Exit();
            return;
        }
        var ui = DispatcherQueue.GetForCurrentThread();
        showSettings = new EventWaitHandle(false, EventResetMode.AutoReset, InstanceName + ".show");
        new Thread(() =>
        {
            while (showSettings.WaitOne()) ui.TryEnqueue(ShowSettings);
        }) { IsBackground = true, Name = "Revoke single instance" }.Start();

        controller = new Controller(ui);
        tray = new TrayIcon();
        tray.Selected += rect => panel?.Toggle(rect);
        tray.Command += command =>
        {
            switch (command)
            {
                case TrayIcon.MenuCommand.RevokeAll: _ = controller.ActAsync(m => m.RevokeAll()); break;
                case TrayIcon.MenuCommand.EndAll: _ = controller.ActAsync(m => m.EndAll()); break;
                case TrayIcon.MenuCommand.Settings: ShowSettings(); break;
                case TrayIcon.MenuCommand.Quit: Quit(); break;
            }
        };
        tray.Locked += reason => _ = controller.LockedAsync(reason);
        controller.Changed += view => tray.Update(view.Snapshot.Exposed, view.Snapshot.Status);

        await controller.StartAsync();
        panel = new PanelWindow(controller);
        // Settings open by themselves only the first time, to set Revoke up.
        var background = command.Contains("--background");
        if (controller.FirstRun && !background) ShowSettings();
    }

    public void ShowSettings()
    {
        if (controller is null) return;
        if (settings is null)
        {
            settings = new SettingsWindow(controller);
            settings.Closed += (_, _) => settings = null;
        }
        settings.Activate();
    }

    public void Quit()
    {
        tray?.Dispose();
        instance?.ReleaseMutex();
        Exit();
    }
}
