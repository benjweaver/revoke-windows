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
                case TrayIcon.MenuCommand.Settings: ShowSettings(); break;
                case TrayIcon.MenuCommand.Quit: Quit(); break;
            }
        };
        tray.Locked += reason => _ = controller.LockedAsync(reason);
        controller.Changed += view => tray.Update(view.Snapshot.Exposed, view.Snapshot.Status);

        await controller.StartAsync();
        panel = new PanelWindow(controller);
        // Settings open by themselves only the first time, to set Revoke up.
        var background = Environment.GetCommandLineArgs().Contains("--background");
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
