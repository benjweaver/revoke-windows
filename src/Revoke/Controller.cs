using Microsoft.UI.Dispatching;
using Microsoft.Win32;
using Revoke.Core;

namespace Revoke;

/// <summary>Everything the windows show, captured at one moment.</summary>
sealed record View(
    Snapshot Snapshot,
    Activity? Activity,
    bool Busy,
    bool RevokeOnClose,
    bool RevokeAfterLimit,
    int LimitMinutes,
    bool RevokeOnLock,
    bool LaunchAtLogin,
    bool HelperInstalled,
    bool HelperCurrent,
    bool HelperRunning,
    bool AskBeforeStoppingServices,
    bool ServicesStartOnDemand,
    IReadOnlyList<KnownApp> Known,
    IReadOnlyList<KnownApp> Hidden)
{
    public static readonly View Empty = new(Snapshot.Empty, null, false, true, false, 30, false, false, false, true, false, true, false, [], []);
}

/// <summary>
/// Owns the model. Every read and change runs off the UI thread, one at a time, so
/// the panel never freezes, not even while the admin prompt is up. After each one,
/// the windows and the tray icon get a fresh <see cref="View"/>.
/// </summary>
sealed class Controller
{
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(2);

    readonly DispatcherQueue ui;
    readonly SemaphoreSlim gate = new(1, 1);
    readonly DispatcherQueueTimer timer;
    Model? model;
    bool busy;

    public View View { get; private set; } = View.Empty;

    /// <summary>Raised on the UI thread after every change.</summary>
    public event Action<View>? Changed;

    public Controller(DispatcherQueue ui)
    {
        this.ui = ui;
        timer = ui.CreateTimer();
        timer.Interval = TickInterval;
        timer.Tick += (_, _) => _ = Background(m => m.Tick());
    }

    public async Task StartAsync()
    {
        await gate.WaitAsync();
        try
        {
            var view = await Task.Run(() =>
            {
                model = new Model();
                return Capture(model);
            });
            Publish(view);
        }
        finally
        {
            gate.Release();
        }
        timer.Start();
    }

    public bool FirstRun
    {
        get
        {
            if (model is null || model.Settings.SetUp) return false;
            model.Settings.SetUp = true;
            try { model.Settings.Save(); } catch (IOException) { }
            return true;
        }
    }

    /// <summary>Reads everything again now, as when the panel opens.</summary>
    public Task RefreshAsync() => Background(m => { m.Refresh(force: true); return null; });

    /// <summary>A change the person asked for: the UI shows it's busy until it's done.</summary>
    public async Task<Activity?> ActAsync(Func<Model, Activity> action)
    {
        busy = true;
        Publish(View with { Busy = true });
        try
        {
            await gate.WaitAsync();
            try
            {
                var (activity, view) = await Task.Run(() =>
                {
                    var activity = action(model!);
                    return (activity, Capture(model!));
                });
                busy = false;
                Publish(view);
                return activity;
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            if (busy)
            {
                busy = false;
                Publish(View with { Busy = false });
            }
        }
    }

    /// <summary>Background work: ticks, refreshes and the automatic revocations. Ticks and
    /// refreshes are skipped, rather than queued, while something else holds the model;
    /// changes the person made <paramref name="wait"/> their turn.</summary>
    async Task Background(Func<Model, Activity?> work, bool wait = false)
    {
        if (model is null) return;
        if (wait) await gate.WaitAsync();
        else if (!await gate.WaitAsync(0)) return;
        try
        {
            Publish(await Task.Run(() =>
            {
                work(model);
                return Capture(model);
            }));
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>The session locked or the PC is going to sleep.</summary>
    public Task LockedAsync(string reason) => Background(m => m.Locked(reason), wait: true);

    public Task ChangeSettingsAsync(Action<Settings> change) => Background(m =>
    {
        change(m.Settings);
        m.Settings.Save();
        m.Refresh();
        return null;
    }, wait: true);

    public Task SetWatchedAsync(Client client, bool watched) => Background(m =>
    {
        m.SetWatched(client, watched);
        return null;
    }, wait: true);

    public Task SetHiddenAsync(Client client, bool hidden) => Background(m =>
    {
        m.SetHidden(client, hidden);
        return null;
    }, wait: true);

    /// <summary>Installs, updates or removes the helper, behind one UAC prompt.</summary>
    public Task<Activity?> SetHelperAsync(bool install) => ActAsync(_ =>
    {
        var error = install ? Helper.Install() : Helper.Uninstall();
        return error is not null
            ? Activity.Now($"Couldn't {(install ? "install" : "remove")} the helper: {error}", true)
            : Activity.Now(install ? "Installed the helper: no more admin prompts for watched apps" : "Removed the helper");
    });

    public void SetLaunchAtLogin(bool on)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        if (on) key.SetValue("Revoke", $"\"{Environment.ProcessPath}\" --background");
        else key.DeleteValue("Revoke", throwOnMissingValue: false);
        Publish(View with { LaunchAtLogin = LaunchAtLogin() });
    }

    static bool LaunchAtLogin() => Registry.CurrentUser.OpenSubKey(RunKey)?.GetValue("Revoke") is string;

    View Capture(Model m) => new(
        m.Snapshot,
        m.LastActivity,
        busy,
        m.Settings.RevokeOnClose,
        m.Settings.RevokeAfterLimit,
        m.Settings.LimitMinutes,
        m.Settings.RevokeOnLock,
        LaunchAtLogin(),
        Helper.IsInstalled,
        Helper.IsCurrent,
        Helper.IsRunning,
        m.Settings.AskBeforeStoppingServices,
        m.Settings.ServicesStartOnDemand,
        m.KnownApps(),
        m.HiddenApps());

    void Publish(View view)
    {
        if (!ui.HasThreadAccess)
        {
            ui.TryEnqueue(() => Publish(view));
            return;
        }
        View = view;
        Changed?.Invoke(view);
    }
}
