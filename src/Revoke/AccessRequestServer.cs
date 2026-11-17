using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.UI.Dispatching;
using Revoke.Core;

namespace Revoke;

/// <summary>
/// Listens for <c>Revoke --request</c> and <c>revoke://request</c> calls from apps,
/// checks who asked from the connecting process's own parent chain, and shows a prompt.
/// </summary>
sealed partial class AccessRequestServer : IDisposable
{
    static readonly TimeSpan QuietAfterNo = TimeSpan.FromSeconds(60);

    readonly Controller controller;
    readonly DispatcherQueue ui;
    readonly CancellationTokenSource stopping = new();
    readonly SemaphoreSlim connections = new(16);
    readonly Dictionary<string, DateTimeOffset> declined = [];
    readonly Queue<(AccessRequest Request, List<Client> Apps, bool IsClaimed, TaskCompletionSource<string> Answer)> waiting = new();
    bool isAsking;

    public AccessRequestServer(Controller controller, DispatcherQueue ui)
    {
        this.controller = controller;
        this.ui = ui;
        Task.Run(() => ListenAsync(stopping.Token));
    }

    public void Dispose() => stopping.Cancel();

    static PipeSecurity Security()
    {
        var security = new PipeSecurity();
        if (WindowsIdentity.GetCurrent().User is { } user)
            security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    async Task ListenAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            var reserved = false;
            try
            {
                await connections.WaitAsync(token);
                reserved = true;
                pipe = NamedPipeServerStreamAcl.Create(AccessRequest.PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, Security());
                await pipe.WaitForConnectionAsync(token);
                var connected = pipe;
                pipe = null;
                reserved = false;
                _ = ServeAndReleaseAsync(connected, token);
            }
            catch (OperationCanceledException)
            {
                if (pipe is not null) await pipe.DisposeAsync();
                return;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                if (pipe is not null) await pipe.DisposeAsync();
            }
            finally
            {
                if (reserved) connections.Release();
            }
        }
    }

    async Task ServeAndReleaseAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        try { await ServeAsync(pipe, token); }
        catch (Exception e) { Log.Write($"Couldn't serve an access request: {e.Message}"); }
        finally { connections.Release(); }
    }

    async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        await using var owned = pipe;
        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            readDeadline.CancelAfter(TimeSpan.FromSeconds(5));
            var url = await BoundedLine.ReadAsync(reader, AccessRequest.MaxUrlChars, readDeadline.Token);
            var request = AccessRequest.Parse(url);
            if (request is null)
            {
                _ = controller.NoteAsync("Ignored a request for access that Revoke couldn't read");
                await writer.WriteLineAsync("ignored".AsMemory(), token);
                return;
            }

            // Trace the caller's process tree right now while the client process is still waiting.
            var apps = GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var clientPid) && clientPid != 0
                ? AccessRequest.AppsBehind(clientPid, Processes.List(), (uint)Environment.ProcessId)
                : [];

            var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!ui.TryEnqueue(() =>
            {
                try
                {
                    var (resolvedApps, isClaimed) = ResolveApps(apps, request);
                    waiting.Enqueue((request, resolvedApps, isClaimed, tcs));
                    _ = ProcessQueueAsync();
                }
                catch (Exception e)
                {
                    Log.Write($"Couldn't queue an access request: {e.Message}");
                    tcs.TrySetResult("ignored");
                }
            })) tcs.TrySetResult("ignored");

            var answer = await tcs.Task.WaitAsync(token);
            await writer.WriteLineAsync(answer.AsMemory(), token);
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or UnauthorizedAccessException) { }
    }

    (List<Client> Apps, bool IsClaimed) ResolveApps(List<Client> traced, AccessRequest request)
    {
        var known = controller.View.Snapshot.AllRows.Select(r => r.Client).ToHashSet();
        var matched = traced.Where(known.Contains).ToList();
        if (matched.Count > 0) return (matched, false);
        if (request.ClaimedApp is { } claimed)
        {
            var match = controller.View.Snapshot.AllRows.FirstOrDefault(r =>
                r.Client.Key.Equals(claimed, StringComparison.OrdinalIgnoreCase)
                || r.Name.Equals(claimed, StringComparison.OrdinalIgnoreCase));
            if (match is not null) return ([match.Client], true);
        }
        return ([], false);
    }

    async Task ProcessQueueAsync()
    {
        if (isAsking || waiting.Count == 0) return;
        isAsking = true;
        try
        {
            while (waiting.Count > 0)
            {
                var (request, apps, isClaimed, tcs) = waiting.Dequeue();
                try { tcs.TrySetResult(await HandleAsync(request, apps, isClaimed)); }
                catch (Exception e)
                {
                    Log.Write($"Couldn't answer an access request: {e.Message}");
                    tcs.TrySetResult("ignored");
                }
            }
        }
        finally
        {
            isAsking = false;
        }
    }

    async Task<string> HandleAsync(AccessRequest request, List<Client> apps, bool isClaimed)
    {
        var what = Model.Title(request.Pane).ToLowerInvariant();
        if (apps.Count == 0)
        {
            await controller.NoteAsync($"Something asked for {what}, but Revoke couldn't tell which app it was");
            return "ignored";
        }

        Client primary = apps[0];
        var primaryName = primary.Key;
        foreach (var candidate in apps)
        {
            var (watched, name) = await controller.InspectClientAsync(candidate);
            if (watched)
            {
                primary = candidate;
                primaryName = name;
                break;
            }
            if (candidate == apps[0]) primaryName = name;
        }

        var key = $"{primary.Key} {request.Pane}";
        if (declined.TryGetValue(key, out var last) && DateTimeOffset.UtcNow - last < QuietAfterNo)
            return "ignored";

        if (request.Pane == Pane.Network)
        {
            var blocked = await controller.RefreshAndCheckLocalNetworkBlockedAsync([primary], primary);
            if (!blocked)
            {
                await controller.NoteAsync($"{primaryName} asked for local network, which isn't blocked");
                return "ignored";
            }
        }
        else if (request.Pane == Pane.Internet)
        {
            var limited = await controller.RefreshAndCheckInternetLimitedAsync([primary], primary);
            if (!limited)
            {
                await controller.NoteAsync($"{primaryName} asked for the whole internet, which Revoke isn't limiting");
                return "ignored";
            }
        }

        var who = isClaimed
            ? $"{primaryName} (from the link — Revoke couldn't check who sent it)"
            : primaryName;
        var duration = Settings.Describe(request.Minutes);
        var header = request.Pane switch
        {
            Pane.Network => Helper.IsRunning
                ? $"{who} wants local network for {duration}"
                : $"{who} wants local network",
            Pane.Internet => Helper.IsRunning
                ? $"{who} wants the whole internet for {duration}"
                : $"{who} wants the whole internet",
            _ => $"{who} wants {what}",
        };
        var body = request.Pane switch
        {
            Pane.Network => Helper.IsRunning
                ? $"Revoke will stop blocking the local network for {primaryName} for {duration}, then block it again."
                : $"Revoke will stop blocking the local network for {primaryName}.",
            Pane.Internet => Helper.IsRunning
                ? $"Revoke will stop limiting the internet for {primaryName} for {duration}, then keep it to its model's hosts again."
                : $"Revoke will stop limiting the internet for {primaryName}.",
            _ => $"Yes opens Windows Settings so you can allow {what} for {primaryName}.",
        };

        if (isClaimed)
            body += $" The link named {primaryName}, but Revoke could not verify which app sent it.";

        var allow = await PromptWindow.AskAccessAsync(header, request.Reason, body);
        if (!allow)
        {
            declined[key] = DateTimeOffset.UtcNow;
            await controller.NoteAsync($"Turned down {primaryName} asking for {what}");
            return "no";
        }

        if (request.Pane == Pane.Network)
        {
            var result = await controller.AllowLocalNetworkTemporarilyAsync([primary], request.Minutes, primaryName);
            if (result is null || result.IsError) return "ignored";
        }
        else if (request.Pane == Pane.Internet)
        {
            var result = await controller.AllowInternetTemporarilyAsync([primary], request.Minutes, primaryName);
            if (result is null || result.IsError) return "ignored";
        }
        else
            await controller.OpenPrivacySettingsAsync(request.Pane, primaryName);
        return "yes";
    }

    /// <summary>Sends a request from <c>Revoke --request</c> to the running Revoke and waits for its answer.</summary>
    public static int SendFromCli(string url, bool printResult)
    {
        if (AccessRequest.Parse(url) is null)
        {
            Console.Error.WriteLine("Revoke: that isn't a request. Try: Revoke --request \"revoke://request?access=local-network&minutes=15&reason=Why\"");
            return 2;
        }
        try
        {
            using var pipe = new NamedPipeClientStream(".", AccessRequest.PipeName, PipeDirection.InOut);
            pipe.Connect(1500);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            writer.WriteLine(url);
            var answer = reader.ReadLineAsync().WaitAsync(TimeSpan.FromMinutes(10)).GetAwaiter().GetResult() ?? "ignored";
            if (printResult) Console.WriteLine(answer);
            return answer == "yes" ? 0 : 1;
        }
        catch (TimeoutException)
        {
            Console.Error.WriteLine("Revoke: nobody answered.");
            return 2;
        }
        catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Revoke: Revoke isn't running, so there's nobody to ask.");
            return 2;
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(nint pipe, out uint processId);
}
