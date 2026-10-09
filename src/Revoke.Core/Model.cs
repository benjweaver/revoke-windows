using System.Diagnostics;

namespace Revoke.Core;

/// <summary>A column in the panel.</summary>
public enum Pane { Running, Startup, Service, Links, Screen, Camera, Microphone, Location, Network }

/// <param name="On">Orange: the app can do this now.</param>
/// <param name="InUse">Doing it this moment (camera, microphone, location, screen capture).</param>
/// <param name="Enabled">Whether the switch does anything. Off for things Windows doesn't let
/// one app change, like a desktop program's camera access.</param>
/// <param name="NeedsAdmin">Switching it raises the admin prompt.</param>
/// <param name="Stale">Revoke blocked it, but the app has updated since and the block no longer
/// covers the new version.</param>
/// <param name="Caution">Off in a way that can break the app, like a service Revoke keeps stopped.</param>
/// <param name="Active">For a switch that says whether something may run, whether it's running
/// right now; null where that doesn't apply.</param>
public sealed record Cell(bool On, bool InUse, bool Enabled, bool NeedsAdmin, bool Stale, string Help,
    bool Caution = false, bool? Active = null);

/// <param name="Icon">The app's logo file, for packaged apps.</param>
/// <param name="Deadline">When the time limit will stop it.</param>
public sealed record Row(
    Client Client,
    string Name,
    string Publisher,
    string? Icon,
    bool Watched,
    IReadOnlyDictionary<Pane, Cell> Cells,
    int Processes,
    bool HasWindow,
    IReadOnlyList<string> Services,
    IReadOnlyList<string> Helpers,
    DateTimeOffset? Deadline,
    int RunningServices = 0)
{
    public bool IsOn(Pane pane) => Cells.TryGetValue(pane, out var cell) && cell.On;
}

/// <param name="Exposed">Any watched app running or able to capture the screen: the tray lock opens.</param>
public sealed record Snapshot(IReadOnlyList<Row> Watched, IReadOnlyList<Row> Others, bool CanReadFirewall, string Status, bool Exposed)
{
    public static readonly Snapshot Empty = new([], [], true, "Reading…", false);

    public IEnumerable<Row> AllRows => Watched.Concat(Others);
}

public sealed record Activity(DateTimeOffset At, string Text, bool IsError)
{
    public static Activity Now(string text, bool isError = false) => new(DateTimeOffset.Now, text, isError);
}

public sealed record KnownApp(Client Client, string Name, string Publisher, bool Watched, string? Icon);

/// <summary>What every source says right now, gathered into one row per app, and
/// everything that revokes access. Not thread-safe: one caller at a time.</summary>
public sealed class Model
{
    public static readonly Pane[] AllPanes = Enum.GetValues<Pane>();

    /// <summary>What automatic revocations take away: everything that needs no admin prompt.
    /// Links too, so nothing can open an app that was stopped while nobody's looking.</summary>
    static readonly Pane[] Automatic = [Pane.Running, Pane.Startup, Pane.Links, Pane.Screen, Pane.Camera, Pane.Microphone, Pane.Location];

    /// <summary>Facts about a client gathered from every source.</summary>
    sealed class Facts
    {
        public string? Name;
        public string? Publisher;
        public Package? Package;
        public List<Proc> Procs = [];
        public Dictionary<Capability, ConsentEntry> Consent = [];
        public List<StartupEntry> Startup = [];
        public List<Service> Services = [];
        public List<LinkHandler> Links = [];
        public List<FirewallRule> Inbound = [];
        public List<FirewallRule> Blocks = [];
        /// <summary>Programs that belong to the client, for firewall rules.</summary>
        public HashSet<string> Programs = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Watched programs this app started, which show in its row rather than their own.</summary>
        public List<Client> Helpers = [];
        public Client? HelperOf;
    }

    /// <summary>Per-client memory between ticks, for the automatic revocations.</summary>
    sealed class Watch
    {
        public bool HadWindow;
        public int WindowlessTicks;
        /// <summary>Everything the client was running last tick, and what those started, so
        /// helpers it leaves behind when it quits can be stopped too.</summary>
        public List<Proc> Tree = [];
    }

    public Settings Settings { get; }
    public Snapshot Snapshot { get; private set; } = Snapshot.Empty;
    public Activity? LastActivity { get; private set; }

    List<Package> packages = [];
    List<Service> services = [];
    DateTime packagesRead = DateTime.MinValue;
    readonly Dictionary<string, string?> signers = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, string?> descriptions = new(StringComparer.OrdinalIgnoreCase);
    SortedDictionary<Client, Facts> facts = [];
    List<Proc> procs = [];
    HashSet<uint> windows = [];
    readonly Dictionary<Client, Watch> watches = [];
    readonly uint self = (uint)Environment.ProcessId;

    public Model(Settings? settings = null)
    {
        Settings = settings ?? Settings.Load();
        Refresh(force: true);
    }

    // Reading

    /// <summary>Reads everything again. Packages and services change rarely and are read at
    /// most once a minute unless forced.</summary>
    public void Refresh(bool force = false)
    {
        if (force || DateTime.UtcNow - packagesRead > TimeSpan.FromMinutes(1))
        {
            packages = Packages.Installed();
            services = Services.Read();
            packagesRead = DateTime.UtcNow;
        }
        services = Services.WithStatus(services);
        procs = Processes.List();
        windows = Processes.WithWindows();
        // Read every time, so an app registering its links again is caught within a tick.
        var links = Links.Read();

        var all = new SortedDictionary<Client, Facts>();
        Facts For(Client client) => all.TryGetValue(client, out var f) ? f : all[client] = new Facts();

        foreach (var package in packages)
        {
            var f = For(Client.Package(package.Family));
            f.Name = package.Name;
            f.Publisher = package.Publisher;
            f.Package = package;
            foreach (var exe in package.Executables) f.Programs.Add(Path.Combine(package.InstallPath, exe));
        }
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        foreach (var proc in procs)
        {
            if (proc.Pid == self) continue;
            Client client;
            if (proc.Family is { } family) client = Client.Package(family);
            else if (proc.Path is { } path && !path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase)) client = Client.FromPath(path);
            else continue;
            var f = For(client);
            if (proc.Path is { } p) f.Programs.Add(p);
            f.Procs.Add(proc);
        }
        var consent = Consent.Read();
        foreach (var (client, entries) in consent.Entries) For(client).Consent = entries;
        foreach (var entry in Startup.Read(packages)) For(entry.Client).Startup.Add(entry);
        foreach (var service in services)
        {
            var f = For(service.Client);
            f.Programs.Add(service.Program);
            f.Services.Add(service);
        }
        foreach (var handler in links)
        {
            var f = For(handler.Client);
            if (handler.Program is { } program && File.Exists(program)) f.Programs.Add(program);
            f.Links.Add(handler);
        }
        var rules = Firewall.Read();
        foreach (var rule in rules ?? [])
        {
            if (rule.RevokeClient is { } client)
            {
                For(client).Blocks.Add(rule);
            }
            else if (rule.Inbound && rule.Allow && rule.Program is { } program)
            {
                var f = For(Client.FromPath(program));
                if (File.Exists(program)) f.Programs.Add(program);
                f.Inbound.Add(rule);
            }
        }
        // Rules Revoke switched off no longer show as active, but stay this client's.
        foreach (var (key, f) in all)
        {
            var ours = Settings.DisabledRules.GetValueOrDefault(key.Key) ?? [];
            f.Inbound.RemoveAll(r => !r.Active && !ours.Contains(r.Id));
        }

        // Desktop programs get their name and developer from their files.
        foreach (var (client, f) in all)
        {
            if (f.Package is not null) continue;
            var path = f.Procs.Select(p => p.Path).FirstOrDefault(p => p is not null) ?? f.Programs.FirstOrDefault();
            if (path is null) continue;
            if (!signers.TryGetValue(path, out var publisher)) signers[path] = publisher = Signer.Organization(path);
            f.Publisher = publisher;
            f.Name = KnownName(path) ?? Description(path) ?? FallbackName(client);
        }
        FoldHelpers(all);
        blockedPrograms = (rules ?? []).Where(r => r.RevokeClient is not null && r.Active && r.Program is not null)
            .Select(r => r.Program!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        facts = all;
        Snapshot = Build(rules is not null, consent.GloballyOn);
    }

    HashSet<string> blockedPrograms = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Agents start helpers of their own (Codex runs node, node_repl and a code-mode
    /// host, all signed by OpenAI). A watched program whose every process was started by
    /// another watched app is that app's helper: it's stopped along with the app, so it
    /// shows in the app's row. Once the app quits, a helper still running gets its own row.
    /// </summary>
    void FoldHelpers(SortedDictionary<Client, Facts> all)
    {
        var watched = all.Where(kv => Settings.IsWatched(kv.Key, kv.Value.Publisher ?? "") && kv.Value.Procs.Count > 0).ToList();
        foreach (var (client, f) in watched)
        {
            if (client.Kind != ClientKind.Exe || f.Startup.Count > 0 || f.Services.Count > 0 || f.Links.Count > 0 || f.Inbound.Count > 0 || f.Blocks.Count > 0)
                continue;
            var pids = f.Procs.Select(p => p.Pid).ToHashSet();
            // The app furthest up the tree wins, so Codex's helpers fold into ChatGPT when ChatGPT started Codex.
            Client? owner = null;
            var ownerSize = -1;
            foreach (var (other, of) in watched)
            {
                if (other == client) continue;
                var below = Processes.Descendants(procs, of.Procs.Select(p => p.Pid).ToHashSet());
                if (pids.IsSubsetOf(below) && below.Count > ownerSize)
                {
                    owner = other;
                    ownerSize = below.Count;
                }
            }
            if (owner is null) continue;
            f.HelperOf = owner;
            all[owner].Helpers.Add(client);
        }
        // A helper's helpers belong to the top app too.
        foreach (var (_, f) in all)
        {
            while (f.HelperOf is { } up && all[up].HelperOf is { } top) f.HelperOf = top;
        }
        foreach (var (_, f) in all) f.Helpers.Clear();
        foreach (var (client, f) in all)
        {
            if (f.HelperOf is { } owner) all[owner].Helpers.Add(client);
        }
    }

    Snapshot Build(bool canReadFirewall, Dictionary<Capability, bool> globallyOn)
    {
        var watched = new List<Row>();
        var others = new List<Row>();
        foreach (var (client, f) in facts)
        {
            var isWatched = Settings.IsWatched(client, f.Publisher ?? "");
            var screenAllowed = f.Consent.TryGetValue(Capability.ScreenCapture, out var screen) && screen.Access == Access.Allowed && !screen.Shared;
            // Desktop programs that have only ever touched the shared switches, and aren't
            // running, have nothing left to revoke.
            var present = f.Package is not null || f.Procs.Count > 0 || f.Startup.Count > 0 || f.Services.Count > 0
                || f.Links.Count > 0 || f.Inbound.Count > 0 || f.Blocks.Count > 0;
            if (!present || !(isWatched || screenAllowed) || f.HelperOf is not null) continue;
            if (!isWatched && Settings.Hidden.Contains(client.Key)) continue;
            (isWatched ? watched : others).Add(MakeRow(client, f, isWatched, globallyOn));
        }
        watched.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
        others.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
        var exposed = watched.Where(r => r.IsOn(Pane.Running) || r.IsOn(Pane.Screen)).Select(r => r.Name).ToList();
        var status = exposed.Count switch
        {
            0 => "Watched apps are stopped",
            1 => $"{exposed[0]} is running",
            _ => $"{List(exposed)} are running",
        };
        return new Snapshot(watched, others, canReadFirewall, status, exposed.Count > 0);
    }

    Row MakeRow(Client client, Facts f, bool watched, Dictionary<Capability, bool> globallyOn)
    {
        var name = f.Name ?? FallbackName(client);
        var packaged = f.Package is not null;
        var cells = new Dictionary<Pane, Cell>();

        // Running: anything of the app's running right now, its service included.
        var runningServices = f.Services.Where(s => s.Running).ToList();
        var running = f.Procs.Count > 0 || runningServices.Count > 0;
        string help;
        if (running)
        {
            var parts = new List<string>();
            if (f.Procs.Count > 0) parts.Add($"{f.Procs.Count} process{(f.Procs.Count == 1 ? "" : "es")}");
            if (runningServices.Count > 0) parts.Add($"the {List(runningServices.Select(s => s.Name))} service");
            help = $"{name} is running ({string.Join(" and ", parts)}). Switch off to stop it, everything it started, and its service.";
            if (runningServices.Count > 0)
                help += " The service can start again with Windows or when the app asks; switch Service off to keep it stopped.";
        }
        else
        {
            help = packaged ? $"{name} isn't running. Switch on to open it." : $"{name} isn't running.";
        }
        // Packaged services let any user stop them; others need admin.
        cells[Pane.Running] = new Cell(running, false, running || packaged, runningServices.Any(s => !s.Packaged), false, help);

        // Startup: opening at sign-in, as Task Manager's Startup apps list shows it.
        var enabledItems = f.Startup.Where(e => e.Enabled).ToList();
        var opensAtSignIn = enabledItems.Count > 0;
        help = opensAtSignIn ? $"{name} opens when you sign in. Switch off to stop that."
            : f.Startup.Count > 0 ? $"{name} doesn't open when you sign in. Switch on to let it again."
            : $"{name} has no startup entry.";
        cells[Pane.Startup] = new Cell(opensAtSignIn, false, f.Startup.Count > 0,
            enabledItems.Any(e => e.Item is StartupItem.Run { Machine: true }), false, help);

        // Service: whether a Windows service the app installed may run. Task Manager's
        // Startup apps list leaves these out. Off once switched off: Revoke stops it, and
        // keeps it stopped. (Whether it's running right now shows under Running.)
        var kept = f.Services.Where(s => Settings.KeepStopped.Contains(s.Name)).ToList();
        var serviceOn = f.Services.Any(s => !kept.Contains(s));
        var serviceNames = List(f.Services.Select(s => s.Name));
        if (f.Services.Count == 0)
        {
            help = $"{name} has no Windows service.";
        }
        else if (serviceOn)
        {
            var what = new List<string>();
            if (runningServices.Count > 0) what.Add("is running");
            what.Add(f.Services.Any(s => s.StartsWithWindows) ? "starts with Windows" : "starts only when an app starts it");
            var system = f.Services.Any(s => s.RunsAsSystem) ? ", which runs as SYSTEM," : "";
            help = $"{serviceNames}{system} {string.Join(" and ", what)}.{StartsOnDemand(f.Services)} Switch off to stop it and keep it stopped.";
        }
        else if (kept.Count > 0)
        {
            // How it would come back, from how Windows has it set up.
            var comesBack = kept.Any(s => s.StartsWithWindows)
                ? kept.Any(s => s.HasStartTrigger) ? "it still starts with Windows, and whenever an app asks for it," : "it still starts with Windows,"
                : kept.Any(s => s.HasStartTrigger) ? "Windows still starts it whenever an app asks for it," : null;
            help = kept.Any(s => s.Packaged) && comesBack is not null
                ? $"Revoke keeps {serviceNames} stopped. Windows only lets {name}'s installer change how it starts, so {comesBack} and Revoke stops it each time. Features of {name} that need it won't work. Switch on to let it run."
                : $"Revoke keeps {serviceNames} stopped. Features of {name} that need it won't work. Switch on to let it run.";
        }
        var serviceAdmin = f.Services.Any(s => !s.Packaged);
        cells[Pane.Service] = new Cell(serviceOn, false, f.Services.Count > 0, serviceAdmin, false, help,
            Caution: !serviceOn && kept.Count > 0,
            Active: f.Services.Count > 0 ? runningServices.Count > 0 : null);

        // Links: whether web pages, documents and other apps can open it with a link or a
        // file, which can carry a prompt for it, or Revoke stands in and asks first.
        var open = f.Links.Where(h => !h.Blocked).ToList();
        var ways = WaysToOpen(f);
        if (f.Links.Count == 0)
            help = $"Nothing else opens {name} with a link or a file.";
        else if (open.Count > 0)
            help = $"Web pages, documents and other apps can open {name} with {ways}, which can carry instructions for it. Switch off to have Revoke ask you first, every time.";
        else
            help = $"Revoke asks you before {ways} open {name}, and shows what they carry. Switch on to let them open it directly.";
        cells[Pane.Links] = new Cell(open.Count > 0, false, f.Links.Count > 0, false, false, help);

        // Privacy switches
        foreach (var pane in new[] { Pane.Screen, Pane.Camera, Pane.Microphone, Pane.Location })
        {
            var capability = CapabilityOf(pane)!.Value;
            var entry = f.Consent.GetValueOrDefault(capability) ?? new ConsentEntry(Access.Unset, false, false, null);
            var global = globallyOn.GetValueOrDefault(capability, true);
            var what = Title(pane).ToLowerInvariant();
            if (!packaged)
            {
                cells[pane] = new Cell(false, entry.InUse, false, false, false, entry.InUse
                    ? $"{name} is using the {what} now. Windows has one switch for all desktop apps, so Revoke can't switch off {name} alone; stopping it ends the use."
                    : $"Windows has one {what} switch for all desktop apps, so this can only be changed for every desktop app at once, in Settings.");
                continue;
            }
            help = entry.Access switch
            {
                _ when entry.InUse => $"{name} is using the {what} now. Switch off to revoke it.",
                Access.Allowed when global => $"{name} has {what} access. Switch off to revoke it.",
                Access.Allowed => $"{name} is allowed, but {what} is switched off for all apps.",
                Access.Ask => $"Windows asks before {name} can use the {what}. Switch off to deny it outright, or on to open Settings.",
                Access.Denied => $"Off. Switching on opens Settings, where only you can grant {what} access.",
                _ => $"{name} hasn't asked for {what} access. Switching on opens Settings.",
            };
            cells[pane] = new Cell(entry.Access == Access.Allowed && global, entry.InUse, true, false, false, help);
        }

        // Local network: blocked once Revoke's rules cover every program, including the
        // helpers', whichever row added them.
        var activeInbound = f.Inbound.Where(r => r.Active).ToList();
        var programs = ProgramsOf(client, f);
        var covered = programs.Count(blockedPrograms.Contains);
        var blocked = f.Blocks.Count > 0 || (programs.Count > 0 && covered == programs.Count);
        var stale = blocked && covered < programs.Count;
        var networkOn = activeInbound.Count > 0 || !blocked;
        if (stale)
            help = $"{name} has updated since Revoke blocked it, and the block doesn't cover the new version. Switch off to block it again.";
        else if (blocked && activeInbound.Count == 0)
            help = $"Revoke keeps {name} off your local network. Switch on to stop blocking it.";
        else if (activeInbound.Count > 0)
            help = $"Devices on your network can connect to {name} ({activeInbound.Count} firewall rule{(activeInbound.Count == 1 ? "" : "s")}). Switch off to close those and keep it off your local network.";
        else
            help = $"{name} can reach devices on your local network. Switch off to block it.";
        cells[Pane.Network] = new Cell(networkOn || stale, false, programs.Count > 0 || blocked, true, stale, help);

        var helpers = f.Helpers.Select(h => facts.GetValueOrDefault(h)?.Name ?? FallbackName(h)).Distinct().ToList();
        return new Row(client, name, f.Publisher ?? "", f.Package?.Logo, watched, cells,
            f.Procs.Count + f.Helpers.Sum(h => facts.GetValueOrDefault(h)?.Procs.Count ?? 0),
            f.Procs.Any(p => windows.Contains(p.Pid)), f.Services.Select(s => s.Name).ToList(), helpers, DeadlineOf(f), f.Services.Count(s => s.Running));
    }

    /// <summary>"claude:// links", "codex:// links and .csv and .skill files".</summary>
    static string WaysToOpen(Facts f)
    {
        var schemes = (f.Links.Any(h => !h.IsFile) ? f.Package?.Protocols ?? [] : [])
            .Concat(f.Links.Select(h => h.Scheme).OfType<string>())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(s => $"{s}://")
            .ToList();
        var files = f.Links.Any(h => h.IsFile) ? f.Package?.FileTypes ?? [] : [];
        var parts = new List<string>();
        if (schemes.Count > 0) parts.Add($"{List(schemes)} links");
        else if (f.Links.Any(h => !h.IsFile)) parts.Add("links");
        if (files.Count > 0) parts.Add($"{List(files)} files");
        else if (f.Links.Any(h => h.IsFile)) parts.Add("files");
        return string.Join(" and ", parts);
    }

    /// <summary>The programs a client's firewall rules should cover: the ones it has run,
    /// declares, or has rules for, that exist now. For a desktop program that updates
    /// into new folders, every version that's there.</summary>
    List<string> ProgramsOf(Client client, Facts f)
    {
        var programs = (client.Kind == ClientKind.Package ? f.Programs.Where(client.MatchesPath) : Client.Expand(client.Id))
            .Concat(f.Helpers.SelectMany(h => Client.Expand(h.Id)));
        return programs.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    DateTimeOffset? DeadlineOf(Facts f)
    {
        if (!Settings.RevokeAfterLimit) return null;
        var starts = f.Procs.Where(p => p.Started != 0).Select(p => p.Started).ToList();
        if (starts.Count == 0) return null;
        var started = Processes.Time(starts.Min());
        if (Settings.LimitStart > started) started = Settings.LimitStart;
        return started.AddMinutes(Settings.LimitMinutes);
    }

    public Row? RowFor(Client client) => Snapshot.AllRows.FirstOrDefault(r => r.Client == client);

    string DisplayName(Client client) => RowFor(client)?.Name ?? facts.GetValueOrDefault(client)?.Name ?? FallbackName(client);

    /// <summary>Apps the settings window can offer to watch: watched ones, apps with windows
    /// open, and packaged apps with anything in the lists.</summary>
    public List<KnownApp> KnownApps() => facts
        .Where(kv =>
        {
            var (client, f) = (kv.Key, kv.Value);
            return Settings.IsWatched(client, f.Publisher ?? "") || Settings.Removed.Contains(client.Key)
                || f.Procs.Any(p => windows.Contains(p.Pid))
                || (f.Package is not null && (f.Consent.Count > 0 || f.Startup.Count > 0 || f.Inbound.Count > 0));
        })
        .Select(kv => new KnownApp(kv.Key, kv.Value.Name ?? FallbackName(kv.Key), kv.Value.Publisher ?? "",
            Settings.IsWatched(kv.Key, kv.Value.Publisher ?? ""), kv.Value.Package?.Logo))
        .OrderByDescending(a => a.Watched)
        .ThenBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
        .ToList();

    /// <summary>Apps hidden from the panel's list of other apps.</summary>
    public List<KnownApp> HiddenApps() => Settings.Hidden
        .Select(Client.FromKey).OfType<Client>()
        .Select(client => facts.GetValueOrDefault(client) is { } f
            ? new KnownApp(client, f.Name ?? FallbackName(client), f.Publisher ?? "", false, f.Package?.Logo)
            : new KnownApp(client, FallbackName(client), "", false, null))
        .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
        .ToList();

    /// <summary>Hides an app from the panel's list of other apps, or shows it again. Its
    /// access isn't changed.</summary>
    public void SetHidden(Client client, bool hidden)
    {
        if (hidden) Settings.Hidden.Add(client.Key);
        else Settings.Hidden.Remove(client.Key);
        Settings.Save();
        Refresh();
    }

    public void SetWatched(Client client, bool watched)
    {
        Settings.SetWatched(client, facts.GetValueOrDefault(client)?.Publisher ?? "", watched);
        Settings.Save();
        Refresh();
    }

    // Changing access

    /// <summary>A switch in the panel. Granting a privacy switch opens Settings, where only
    /// the person can grant access, as on macOS.</summary>
    public Activity Set(Client client, Pane pane, bool on)
    {
        if (!on) return Revoke([client], [pane], null, allowAdmin: true);
        string text;
        var isError = false;
        try
        {
            text = Grant(client, pane);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            text = $"Couldn't switch on {Title(pane).ToLowerInvariant()} for {DisplayName(client)}: {e.Message}";
            isError = true;
        }
        Refresh(force: true);
        return LastActivity = Activity.Now(text, isError);
    }

    string Grant(Client client, Pane pane)
    {
        var name = DisplayName(client);
        var f = facts.GetValueOrDefault(client) ?? throw new InvalidOperationException("Revoke can't find it any more.");
        switch (pane)
        {
            case Pane.Running:
                var package = f.Package ?? throw new InvalidOperationException("Only packaged apps can be opened from here.");
                var app = package.Apps.FirstOrDefault() ?? throw new InvalidOperationException("It has no app to open.");
                Open($@"shell:AppsFolder\{package.Family}!{app}");
                return $"Opened {name}";

            case Pane.Startup:
                var ops = new List<ElevatedOp>();
                foreach (var entry in f.Startup)
                {
                    if (entry.Item is StartupItem.Run { Machine: true } run)
                        ops.Add(new ElevatedOp.SetMachineStartup(run.Wow64, run.Name, true));
                    else
                        Startup.Set(entry.Item, true);
                }
                if (Elevated.Run(ops) is { } error) throw new InvalidOperationException(error);
                return $"{name} opens when you sign in again";

            case Pane.Service:
                foreach (var service in f.Services) Settings.KeepStopped.Remove(service.Name);
                Settings.Save();
                // Back to how each started before Revoke changed it, where Revoke can change
                // that at all (not packaged services), unless they're meant to start on demand.
                var starts = f.Services
                    .Where(s => !s.Packaged && !Settings.ServicesStartOnDemand
                        && Settings.ServiceStarts.TryGetValue(s.Name, out var start) && start != s.Start)
                    .Select(s => (ElevatedOp)new ElevatedOp.SetServiceStart(s.Name, Settings.ServiceStarts[s.Name]))
                    .ToList();
                if (Elevated.Run(starts) is { } failure) throw new InvalidOperationException(failure);
                foreach (var service in f.Services) Settings.ServiceStarts.Remove(service.Name);
                Settings.Save();
                // Start what any user may start; the rest starts with Windows, or when the app asks.
                var started = f.Services.Where(s => s.StartsWithWindows || s.Packaged).Count(s => Services.TrySet(s.Name, running: true));
                return started > 0 ? $"Started {List(f.Services.Select(s => s.Name))}" : $"{List(f.Services.Select(s => s.Name))} can run again";

            case Pane.Links:
                Settings.BlockLinks.Remove(client.Key);
                Settings.Save();
                foreach (var handler in f.Links) Links.Unblock(handler);
                return $"{name} opens from links and files again";

            case Pane.Network:
                var restore = new List<ElevatedOp> { new ElevatedOp.RemoveBlocks(client.Key) };
                restore.AddRange((Settings.DisabledRules.GetValueOrDefault(client.Key) ?? []).Select(id => new ElevatedOp.SetRuleEnabled(id, true)));
                if (Elevated.Run(restore) is { } failed) throw new InvalidOperationException(failed);
                Settings.DisabledRules.Remove(client.Key);
                Settings.Save();
                return $"Stopped blocking the local network for {name}";

            default:
                Open(Consent.SettingsUri(CapabilityOf(pane)!.Value));
                return $"Opened Settings to grant {Title(pane).ToLowerInvariant()} access";
        }
    }

    /// <summary>
    /// Revokes <paramref name="panes"/> for every client. Parts that need admin rights are
    /// gathered into one prompt, or skipped when <paramref name="allowAdmin"/> is false, as
    /// for the automatic revocations, which shouldn't raise a prompt out of nowhere.
    /// <paramref name="reason"/> finishes "… when …"; null means the person asked.
    /// </summary>
    public Activity Revoke(IReadOnlyList<Client> clients, IReadOnlyList<Pane> panes, string? reason, bool allowAdmin)
    {
        Refresh(force: true);
        var before = clients.Select(RowFor).OfType<Row>().ToDictionary(r => r.Client);
        var errors = new List<string>();
        var ops = new List<ElevatedOp>();
        var disabled = new List<(Client, List<string>)>();
        var serviceStarts = new List<(string, int)>();
        var keepStopped = new List<string>();
        var blockLinks = new List<string>();
        var killed = 0;
        var killedFor = new HashSet<Client>();

        foreach (var client in clients)
        {
            var name = DisplayName(client);
            if (!facts.TryGetValue(client, out var f)) continue;
            foreach (var pane in panes)
            {
                switch (pane)
                {
                    case Pane.Running:
                        var (n, errs) = Processes.KillTree(f.Procs, self);
                        killed += n;
                        if (n > 0) killedFor.Add(client);
                        errors.AddRange(errs.Select(e => $"{name}: {e}"));
                        // Packaged services, and many others, let any user stop them.
                        foreach (var service in f.Services.Where(s => s.Running))
                        {
                            if (!Services.TrySet(service.Name, running: false)) ops.Add(new ElevatedOp.StopService(service.Name));
                        }
                        break;

                    case Pane.Startup:
                        foreach (var entry in f.Startup.Where(e => e.Enabled))
                        {
                            if (entry.Item is StartupItem.Run { Machine: true } run)
                            {
                                ops.Add(new ElevatedOp.SetMachineStartup(run.Wow64, run.Name, false));
                                continue;
                            }
                            try { Startup.Set(entry.Item, false); }
                            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { errors.Add($"{name}: {e.Message}"); }
                        }
                        break;

                    case Pane.Service:
                        foreach (var service in f.Services)
                        {
                            keepStopped.Add(service.Name);
                            // Many services, and every packaged one, let any user stop them.
                            if (service.Running && !Services.TrySet(service.Name, running: false))
                                ops.Add(new ElevatedOp.StopService(service.Name));
                            // Only Windows' package installer can change how a packaged service
                            // starts, so Revoke keeps those stopped instead.
                            if (service.StartsWithWindows && !service.Packaged)
                            {
                                ops.Add(new ElevatedOp.SetServiceStart(service.Name, 3));
                                serviceStarts.Add((service.Name, service.Start));
                            }
                        }
                        break;

                    case Pane.Links:
                        if (f.Links.Count == 0) break;
                        blockLinks.Add(client.Key);
                        foreach (var handler in f.Links.Where(h => !h.Blocked || h.Moved))
                        {
                            try { Links.Block(handler); }
                            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException) { errors.Add($"{name}: {e.Message}"); }
                        }
                        break;

                    case Pane.Network:
                        var active = f.Inbound.Where(r => r.Active).Select(r => r.Id).ToList();
                        ops.AddRange(active.Select(id => new ElevatedOp.SetRuleEnabled(id, false)));
                        // Rebuilt whole, so an update's new programs are covered.
                        ops.Add(new ElevatedOp.RemoveBlocks(client.Key));
                        ops.AddRange(ProgramsOf(client, f).Select(p => new ElevatedOp.BlockLocalNetwork(client.Key, name, p)));
                        if (active.Count > 0) disabled.Add((client, active));
                        break;

                    default:
                        if (client.Family is not { } family) break;
                        var capability = CapabilityOf(pane)!.Value;
                        // Nothing to take away from an app that never asked.
                        if (!f.Consent.TryGetValue(capability, out var consent) || consent.Access is Access.Denied or Access.Unset) break;
                        try { Consent.Deny(family, capability); }
                        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { errors.Add($"{name}: {e.Message}"); }
                        break;
                }
            }
        }

        if (keepStopped.Count > 0 || blockLinks.Count > 0)
        {
            Settings.KeepStopped.UnionWith(keepStopped);
            Settings.BlockLinks.UnionWith(blockLinks);
            try { Settings.Save(); }
            catch (IOException e) { errors.Add(e.Message); }
        }

        var skippedAdmin = false;
        if (ops.Count > 0)
        {
            if (!allowAdmin)
            {
                skippedAdmin = true;
            }
            else if (Elevated.Run(ops) is { } error)
            {
                errors.Add(error);
            }
            else
            {
                foreach (var (client, ids) in disabled)
                {
                    var list = Settings.DisabledRules.TryGetValue(client.Key, out var l) ? l : Settings.DisabledRules[client.Key] = [];
                    list.AddRange(ids.Except(list).ToList());
                }
                foreach (var (service, start) in serviceStarts) Settings.ServiceStarts.TryAdd(service, start);
                try { Settings.Save(); }
                catch (IOException e) { errors.Add(e.Message); }
            }
        }

        Refresh(force: true);
        // Say only what this changed: an app that quit by itself meanwhile wasn't stopped by
        // Revoke, and switches that were already off weren't revoked.
        var changed = clients
            .Where(before.ContainsKey)
            .Select(c =>
            {
                var old = before[c];
                var now = RowFor(c);
                var off = panes.Where(p => old.IsOn(p) && now?.IsOn(p) != true).ToHashSet();
                if (killedFor.Contains(c)) off.Add(Pane.Running);
                return (old.Name, Off: off);
            })
            .Where(c => c.Off.Count > 0)
            .ToList();
        var stopped = changed.Where(c => c.Off.Contains(Pane.Running)).Select(c => c.Name).ToList();
        var revokedFor = changed.Where(c => c.Off.Any(p => p != Pane.Running)).Select(c => c.Name).ToList();
        var revokedPanes = panes.Where(p => p != Pane.Running && changed.Any(c => c.Off.Contains(p)));
        var revokedWhat = List(revokedPanes.Select(p => Title(p).ToLowerInvariant()));
        string text;
        if (errors.Count > 0)
        {
            var what = panes.Count == 1 ? Title(panes[0]).ToLowerInvariant() : "access";
            text = $"Couldn't revoke {what}: {errors[0]}";
        }
        else if (changed.Count == 0)
        {
            // Automatic runs often find nothing to do; only answer a click.
            if (reason is not null) return LastActivity ?? Activity.Now("");
            text = "Nothing to revoke";
        }
        else if (revokedFor.Count == 0)
        {
            text = $"Stopped {List(stopped)}{(panes is [Pane.Running] && killed > 0 ? $" ({killed} processes)" : "")}";
        }
        else if (stopped.Count == 0)
        {
            text = $"Revoked {revokedWhat} for {List(revokedFor)}";
        }
        else if (stopped.SequenceEqual(revokedFor))
        {
            text = $"Stopped {List(stopped)} and revoked {(stopped.Count == 1 ? "its" : "their")} {revokedWhat}";
        }
        else
        {
            text = $"Stopped {List(stopped)}, and revoked {revokedWhat} for {List(revokedFor)}";
        }
        if (reason is not null) text += $" when {reason}";
        if (skippedAdmin) text += ". Services and firewall rules need you to click Revoke All";
        return LastActivity = Activity.Now(text, errors.Count > 0);
    }

    /// <summary>Stops and revokes everything for every watched app.</summary>
    public Activity RevokeAll() => Revoke(Snapshot.Watched.Select(r => r.Client).ToList(), AllPanes, null, allowAdmin: true);

    /// <summary>Stops every watched app, everything they started, and their services, as
    /// switching Running off does, and leaves the other switches as they are.</summary>
    public Activity EndAll()
    {
        Refresh(force: true);
        var running = Snapshot.Watched.Where(r => r.IsOn(Pane.Running)).Select(r => r.Client).ToList();
        if (running.Count == 0) return LastActivity = Activity.Now("No watched apps are running");
        return Revoke(running, [Pane.Running], null, allowAdmin: true);
    }

    // Automatic revoking

    /// <summary>Runs every couple of seconds: refreshes, then revokes what the settings say
    /// should go. Returns what it did, if anything.</summary>
    public Activity? Tick()
    {
        Refresh();
        var due = new List<(Client, string)>();
        var orphans = new List<Proc>();
        var now = DateTimeOffset.Now;
        var alive = procs.Select(p => (p.Pid, p.Started)).ToHashSet();

        foreach (var row in Snapshot.Watched)
        {
            var own = facts.GetValueOrDefault(row.Client)?.Procs ?? [];
            var roots = own.Select(p => p.Pid).ToHashSet();
            var below = Processes.Descendants(procs, roots);
            var watch = watches.TryGetValue(row.Client, out var w) ? w : watches[row.Client] = new Watch();

            if (Settings.RevokeOnClose)
            {
                if (own.Count == 0)
                {
                    // It quit. Whatever it started that's still running was left behind.
                    if (watch.HadWindow) orphans.AddRange(watch.Tree.Where(p => alive.Contains((p.Pid, p.Started))));
                    watch.HadWindow = false;
                    watch.WindowlessTicks = 0;
                }
                else if (row.HasWindow)
                {
                    watch.HadWindow = true;
                    watch.WindowlessTicks = 0;
                }
                else if (watch.HadWindow && ++watch.WindowlessTicks >= 2)
                {
                    // Two ticks without a window, so a window being replaced doesn't count.
                    watch.HadWindow = false;
                    due.Add((row.Client, "its last window closed"));
                }
            }
            watch.Tree = procs.Where(p => roots.Contains(p.Pid) || below.Contains(p.Pid)).ToList();

            if (row.Deadline is { } deadline && deadline <= now) due.Add((row.Client, "its time limit ran out"));
        }

        Activity? activity = KeepServicesStopped() ?? KeepServicesOnDemand();
        activity = KeepLinksBlocked() ?? activity;
        if (orphans.Count > 0)
        {
            var (n, _) = Processes.KillTree(orphans, self);
            if (n > 0) activity = LastActivity = Activity.Now($"Stopped {n} process{(n == 1 ? "" : "es")} a watched app left running when it quit");
        }
        foreach (var (client, reason) in due) activity = Revoke([client], Automatic, reason, allowAdmin: false);
        return activity;
    }

    /// <summary>
    /// Stops services switched off in Revoke that started again: at boot, or because their
    /// app started them. As the user where Windows allows it, through the helper otherwise,
    /// and never with a UAC prompt, which mustn't appear out of nowhere.
    /// </summary>
    Activity? KeepServicesStopped()
    {
        var started = services.Where(s => s.Running && Settings.KeepStopped.Contains(s.Name)).ToList();
        if (started.Count == 0) return null;
        var stopped = started.Where(s => Services.TrySet(s.Name, running: false)).Select(s => s.Name).ToList();
        var rest = started.Where(s => !stopped.Contains(s.Name)).Select(s => (ElevatedOp)new ElevatedOp.StopService(s.Name)).ToList();
        if (rest.Count > 0 && Helper.Send(rest) is { Error: null } reply)
        {
            stopped.AddRange(rest.Where((_, i) => !reply.Rejected.Contains(i)).Select(op => ((ElevatedOp.StopService)op).Name));
        }
        if (stopped.Count == 0) return null;
        return LastActivity = Activity.Now($"Stopped {List(stopped)}, which Revoke keeps stopped");
    }

    /// <summary>
    /// Takes links and files back from apps Revoke asks about, when the app registers
    /// itself for them again (an update re-registers a packaged app's), or when Revoke has
    /// moved. Needs no admin rights, so it's done
    /// without asking.
    /// </summary>
    Activity? KeepLinksBlocked()
    {
        if (Settings.BlockLinks.Count == 0) return null;
        var retaken = new List<string>();
        var changed = false;
        foreach (var (client, f) in facts)
        {
            if (!Settings.BlockLinks.Contains(client.Key)) continue;
            foreach (var handler in f.Links.Where(h => !h.Blocked || h.Moved))
            {
                try
                {
                    Links.Block(handler);
                    changed = true;
                    if (!handler.Blocked) retaken.Add(f.Name ?? FallbackName(client));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException) { }
            }
        }
        if (!changed) return null;
        Refresh();
        if (retaken.Count == 0) return null;
        var names = retaken.Distinct().ToList();
        return LastActivity = Activity.Now($"{List(names)} registered {(names.Count == 1 ? "its" : "their")} links again, so Revoke took them back");
    }

    /// <summary>
    /// Switches the option that watched apps' services start only when the apps start them,
    /// not with Windows. On, they're set to Manual (from the next restart); off, they go back
    /// to how they started before.
    /// </summary>
    public Activity SetServicesStartOnDemand(bool on)
    {
        Settings.ServicesStartOnDemand = on;
        Settings.Save();
        Refresh(force: true);
        var watchedServices = WatchedServices();
        List<ElevatedOp> ops;
        if (on)
        {
            ops = watchedServices.Where(s => s.StartsWithWindows).Select(s => (ElevatedOp)new ElevatedOp.SetServiceStart(s.Name, 3)).ToList();
            foreach (var service in watchedServices.Where(s => s.StartsWithWindows)) Settings.ServiceStarts.TryAdd(service.Name, service.Start);
        }
        else
        {
            ops = watchedServices
                .Where(s => Settings.ServiceStarts.TryGetValue(s.Name, out var start) && start != s.Start && !Settings.KeepStopped.Contains(s.Name))
                .Select(s => (ElevatedOp)new ElevatedOp.SetServiceStart(s.Name, Settings.ServiceStarts[s.Name]))
                .ToList();
        }
        var error = Elevated.Run(ops);
        if (error is null && !on)
        {
            foreach (var op in ops.OfType<ElevatedOp.SetServiceStart>()) Settings.ServiceStarts.Remove(op.Name);
        }
        Settings.Save();
        Refresh(force: true);
        var names = List(ops.OfType<ElevatedOp.SetServiceStart>().Select(o => o.Name));
        return LastActivity = error is not null ? Activity.Now($"Couldn't change how services start: {error}", true)
            : ops.Count == 0 ? Activity.Now(on ? "Watched apps' services already start only when asked" : "Watched apps' services start as they did")
            : Activity.Now(on ? $"{names} will start only when an app starts it, from the next restart" : $"{names} starts with Windows again");
    }

    /// <summary>
    /// While services are meant to start on demand, this sets any that start with Windows to
    /// Manual: ones the option hasn't reached yet, like on a new install once the helper is
    /// there, and ones an app update set back. Through the helper only: never with a UAC
    /// prompt, which mustn't appear out of nowhere.
    /// </summary>
    Activity? KeepServicesOnDemand()
    {
        if (!Settings.ServicesStartOnDemand) return null;
        var reset = WatchedServices().Where(s => s.StartsWithWindows && !Settings.KeepStopped.Contains(s.Name)).ToList();
        // Asking a helper that isn't running would wait for its pipe on every tick.
        if (reset.Count == 0 || !Helper.IsRunning) return null;
        var ops = reset.Select(s => (ElevatedOp)new ElevatedOp.SetServiceStart(s.Name, 3)).ToList();
        if (Helper.Send(ops) is not { Error: null } reply) return null;
        var changed = reset.Where((_, i) => !reply.Rejected.Contains(i)).ToList();
        if (changed.Count == 0) return null;
        var again = changed.Where(s => Settings.ServiceStarts.ContainsKey(s.Name)).ToList();
        var first = changed.Except(again).ToList();
        foreach (var service in first) Settings.ServiceStarts[service.Name] = service.Start;
        if (first.Count > 0) Settings.Save();
        // Reread at the next minute's refresh; the registry already says Manual.
        packagesRead = DateTime.MinValue;
        return LastActivity = Activity.Now(first.Count > 0
            ? $"Set {List(first.Select(s => s.Name))} to start only when an app starts it, from the next restart"
            : $"Set {List(again.Select(s => s.Name))} to start only when an app starts it again, after an update changed it");
    }

    List<Service> WatchedServices() =>
        Snapshot.Watched.SelectMany(r => facts.GetValueOrDefault(r.Client)?.Services ?? [])
            .Concat(Snapshot.Watched.SelectMany(r => facts.GetValueOrDefault(r.Client)?.Helpers ?? [])
                .SelectMany(h => facts.GetValueOrDefault(h)?.Services ?? []))
            .DistinctBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>The session locked or the PC is going to sleep.</summary>
    public Activity? Locked(string reason) =>
        Settings.RevokeOnLock ? Revoke(Snapshot.Watched.Select(r => r.Client).ToList(), Automatic, reason, allowAdmin: false) : null;

    // Helpers

    public static Capability? CapabilityOf(Pane pane) => pane switch
    {
        Pane.Screen => Capability.ScreenCapture,
        Pane.Camera => Capability.Camera,
        Pane.Microphone => Capability.Microphone,
        Pane.Location => Capability.Location,
        _ => null,
    };

    public static string Title(Pane pane) => pane switch
    {
        Pane.Running => "Running",
        Pane.Startup => "Startup",
        Pane.Service => "Service",
        Pane.Links => "Links",
        Pane.Screen => "Screen capture",
        Pane.Camera => "Camera",
        Pane.Microphone => "Microphone",
        Pane.Location => "Location",
        _ => "Local network",
    };

    static void Open(string target) => Process.Start(new ProcessStartInfo("explorer.exe", target) { UseShellExecute = false });

    static string FallbackName(Client client) => client.Kind == ClientKind.Package
        ? client.Id.Split('_')[0]
        : Path.GetFileNameWithoutExtension(client.Id.Split('\\')[^1]);

    /// <summary>Clearer names for programs whose own names are confusing in a list.</summary>
    internal static string? KnownName(string path)
    {
        var pattern = Client.Pattern(path);
        if (pattern.EndsWith(@"\claude\claude-code\*\claude.exe") || pattern.EndsWith(@"\.local\bin\claude.exe")) return "Claude Code";
        if (pattern.EndsWith(@"\openai\codex\bin\*\codex.exe")) return "Codex CLI";
        if (pattern.EndsWith(@"\codex-computer-use-swift.exe")) return "Codex Computer Use";
        return null;
    }

    /// <summary>The program's description, as Task Manager shows it.</summary>
    string? Description(string path)
    {
        if (descriptions.TryGetValue(path, out var cached)) return cached;
        string? description = null;
        try { description = FileVersionInfo.GetVersionInfo(path).FileDescription?.Trim(); }
        catch (FileNotFoundException) { }
        return descriptions[path] = string.IsNullOrEmpty(description) ? null : description;
    }

    /// <summary>A sentence for services Windows starts on demand (a start trigger, like
    /// Claude's CoworkVMService starting when something connects to its pipe), or "".</summary>
    static string StartsOnDemand(IEnumerable<Service> services) =>
        services.Any(s => s.HasStartTrigger) ? " Windows also starts it whenever an app asks for it." : "";

    /// <summary>"A", "A and B", "A, B and C".</summary>
    public static string List(IEnumerable<string> items)
    {
        var list = items.ToList();
        return list.Count switch
        {
            0 => "",
            1 => list[0],
            _ => $"{string.Join(", ", list[..^1])} and {list[^1]}",
        };
    }
}
