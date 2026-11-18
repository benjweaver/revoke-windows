using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

if (args is ["hold"])
{
    using var gate = new ManualResetEventSlim();
    gate.Wait();
    return 0;
}

if (args is ["tcp", var host, var portText] && int.TryParse(portText, out var port) && port is > 0 and <= 65535)
{
    try
    {
        var addresses = await Dns.GetHostAddressesAsync(host);
        foreach (var address in addresses.Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token);
                Console.WriteLine($"connected {address}:{port}");
                return 0;
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException)
            {
                Console.WriteLine($"blocked {address}:{port}: {e.GetType().Name}");
            }
        }
        return 1;
    }
    catch (Exception e) when (e is SocketException or OperationCanceledException)
    {
        Console.WriteLine($"DNS failed: {e.GetType().Name}");
        return 2;
    }
}

if (args is ["request", var revoke, var url])
{
    using var child = Process.Start(new ProcessStartInfo(revoke)
    {
        UseShellExecute = false,
        ArgumentList = { "--request", url },
        RedirectStandardOutput = true,
        RedirectStandardError = true,
    });
    if (child is null) return 2;
    var output = await child.StandardOutput.ReadToEndAsync();
    var error = await child.StandardError.ReadToEndAsync();
    await child.WaitForExitAsync();
    Console.Write(output);
    Console.Error.Write(error);
    return child.ExitCode;
}

if (args is ["protocol", var protocolUrl])
{
    using var child = Process.Start(new ProcessStartInfo(protocolUrl) { UseShellExecute = true });
    return child is null ? 2 : 0;
}

Console.Error.WriteLine("Usage: RevokeVmProbe hold | tcp <host> <port> | request <Revoke.exe> <url> | protocol <url>");
return 2;
