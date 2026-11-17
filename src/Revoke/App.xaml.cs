using System.Diagnostics;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Revoke.Core;

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
    AccessRequestServer? requestServer;
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
        if (command is [_, Links.Flag, ..])
        {
            if (command is not [_, _, var key, var verb, var target])
            {
                Console.Error.WriteLine($"Revoke: {Links.Flag} expects <key> <verb> <target>.");
                Environment.Exit(2);
                return;
            }
            var prompt = Links.PreparePrompt(key, verb, target);
            if (prompt is null)
            {
                Links.ShowMessage("Revoke stopped something opening an app, but the app's entry is gone, so it can't be opened from here.");
            }
            else
            {
                var allow = await PromptWindow.AskLinkAsync(prompt);
                if (Links.AnswerPrompt(prompt, allow) is { } err)
                {
                    Links.ShowMessage($"Couldn't open {prompt.AppName}: {err}", error: true);
                }
            }
            Exit();
            return;
        }
        if (command is [_, AccessRequest.RequestFlag, ..])
        {
            if (command is not [_, _, var requestUrl])
            {
                Console.Error.WriteLine("Revoke: --request expects a revoke://request?... URL.");
                Environment.Exit(2);
                return;
            }
            Environment.Exit(AccessRequestServer.SendFromCli(requestUrl, printResult: true));
            return;
        }
        if (command is [_, AccessRequest.RequestUrlFlag, ..])
        {
            if (command is not [_, _, var protocolUrl])
            {
                Console.Error.WriteLine("Revoke: --request-url expects a revoke://request?... URL.");
                Environment.Exit(2);
                return;
            }
            Environment.Exit(AccessRequestServer.SendFromCli(protocolUrl, printResult: false));
            return;
        }
        // The uninstaller puts every app's own entries back. Inside another app's container
        // that would change nothing, so it says so with exit code 2 instead. It asks first,
        // because any process running as the person can run it.
        if (command is [_, "--restore-links", ..])
        {
            if (command.Length != 2)
            {
                Console.Error.WriteLine("Revoke: --restore-links takes no extra arguments.");
                Environment.Exit(2);
                return;
            }
            if (Container.IsCaptured()) Environment.Exit(2);
            if (!Links.ConfirmRestore())
            {
                Console.Error.WriteLine("Revoke: left the links as they are.");
                Environment.Exit(1);
            }
            var selfPid = Environment.ProcessId;
            foreach (var other in Process.GetProcessesByName("Revoke").Where(p => p.Id != selfPid))
            {
                try
                {
                    if (!string.Equals(other.MainModule?.FileName, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                        continue;
                    other.Kill();
                    other.WaitForExit(5000);
                }
                catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { }
            }
            var saved = Settings.Load();
            saved.BlockLinks.Clear();
            try { saved.Save(); }
            catch (IOException e)
            {
                Links.ShowMessage($"Couldn't save the links setting: {e.Message}", error: true);
                Environment.Exit(1);
                return;
            }
            Links.UnblockAll();
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
        tray.Selected += (rect, keyboard) => panel?.Toggle(rect, keyboard);
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
        AccessRequest.TryRegisterProtocol();
        requestServer = new AccessRequestServer(controller, ui);
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
        requestServer?.Dispose();
        tray?.Dispose();
        instance?.ReleaseMutex();
        Exit();
    }
}
