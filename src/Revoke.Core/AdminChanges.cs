using System.ComponentModel;
using System.Management;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;

namespace Revoke.Core;

/// <summary>
/// Makes admin changes through Windows' own interfaces: the Service Control Manager,
/// the firewall's management provider (to switch rules on and off and delete them by
/// their exact ID), the Windows Firewall COM API (to create rules), and the registry.
/// Runs as SYSTEM in the helper service, or as admin in the helper program after a UAC
/// prompt.
/// </summary>
public static partial class AdminChanges
{
    const string FirewallNamespace = @"\\.\root\StandardCimv2";

    /// <summary>Makes every change, carrying on past failures. Returns the failures.</summary>
    public static List<string> Apply(IEnumerable<ElevatedOp> ops)
    {
        var failures = new List<string>();
        foreach (var op in ops)
        {
            try
            {
                Apply(op);
            }
            catch (Exception e) when (e is ManagementException or COMException or Win32Exception or InvalidOperationException
                or UnauthorizedAccessException or IOException or System.ServiceProcess.TimeoutException or ArgumentException)
            {
                failures.Add($"{Elevated.Describe(op)}: {e.Message.Trim()}");
            }
        }
        return failures;
    }

    static void Apply(ElevatedOp op)
    {
        switch (op)
        {
            case ElevatedOp.StopService s:
                using (var service = new ServiceController(s.Name))
                {
                    if (service.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending) break;
                    service.Stop(stopDependentServices: true);
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
                break;

            case ElevatedOp.SetServiceStart s:
                SetStartType(s.Name, s.Start);
                break;

            case ElevatedOp.SetRuleEnabled r:
                using (var rule = new ManagementObject(new ManagementPath($"{FirewallNamespace}:MSFT_NetFirewallRule.InstanceID=\"{Escape(r.Id)}\"")))
                {
                    rule.Get();
                    rule.InvokeMethod(r.Enabled ? "Enable" : "Disable", null);
                }
                break;

            case ElevatedOp.BlockLocalNetwork b:
                AddBlocks(b);
                break;

            case ElevatedOp.RemoveBlocks r:
                RemoveBlocks(Firewall.DescriptionPrefix + r.ClientKey);
                break;

            case ElevatedOp.SetMachineStartup m:
                using (var key = Registry.LocalMachine.CreateSubKey(Startup.ApprovedKey(m.Wow64)))
                    key.SetValue(m.Name, Startup.Approval(m.Enabled), RegistryValueKind.Binary);
                break;

            default:
                throw new ArgumentException("Not a change Revoke makes.");
        }
    }

    /// <summary>Escapes a value for a WMI object path.</summary>
    static string Escape(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"");

    /// <summary>One outbound block rule per protocol, through the Windows Firewall COM API.</summary>
    static void AddBlocks(ElevatedOp.BlockLocalNetwork block)
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        dynamic policy = Activator.CreateInstance(policyType)!;
        foreach (var protocol in new[] { 6, 17 }) // TCP, UDP
        {
            dynamic rule = Activator.CreateInstance(ruleType)!;
            rule.Name = $"Revoke: keep {block.Label} off the local network";
            rule.Description = Firewall.DescriptionPrefix + block.ClientKey;
            rule.Grouping = Firewall.Group;
            rule.ApplicationName = block.Program;
            rule.Protocol = protocol; // before ports, which only apply to TCP and UDP
            rule.RemotePorts = Firewall.Ports;
            rule.RemoteAddresses = string.Join(',', Firewall.LocalAddresses);
            rule.Direction = 2; // NET_FW_RULE_DIR_OUT
            rule.Action = 0; // NET_FW_ACTION_BLOCK
            rule.Profiles = 0x7FFFFFFF; // NET_FW_PROFILE2_ALL
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }
    }

    /// <summary>Deletes every firewall rule Revoke added, as when removing the helper.
    /// Returns why it couldn't, or null.</summary>
    public static string? RemoveAllRules()
    {
        try
        {
            RemoveBlocks(null);
            return null;
        }
        catch (Exception e) when (e is ManagementException or COMException or UnauthorizedAccessException)
        {
            return $"Remove Revoke's firewall rules: {e.Message.Trim()}";
        }
    }

    /// <summary>Deletes Revoke's rules with this description, or all of them, each by its own ID.</summary>
    static void RemoveBlocks(string? description)
    {
        using var searcher = new ManagementObjectSearcher(new ManagementScope(FirewallNamespace),
            new ObjectQuery($"SELECT * FROM MSFT_NetFirewallRule WHERE RuleGroup = '{Firewall.Group}'"));
        foreach (ManagementObject rule in searcher.Get())
        {
            using (rule)
            {
                if (description is null || rule["Description"] as string == description) rule.Delete();
            }
        }
    }

    /// <summary>
    /// Sets how a service starts. A packaged app's service (Claude's, ChatGPT's) refuses the
    /// service API to everyone but Windows' package installer, so for those the start value
    /// goes straight into the service's registry key, which administrators may write; the
    /// service manager reads it at the next restart.
    /// </summary>
    static void SetStartType(string name, int start)
    {
        try
        {
            SetStartTypeThroughServiceManager(name, start);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 5) // ERROR_ACCESS_DENIED
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}", writable: true)
                ?? throw new InvalidOperationException($"{name} isn't installed.");
            if (key.GetValue("Type") is not int type || (type & 0x200) == 0) throw; // only packaged services
            key.SetValue("Start", start, RegistryValueKind.DWord);
        }
    }

    static void SetStartTypeThroughServiceManager(string name, int start)
    {
        var manager = OpenSCManagerW(null, null, 0x1); // SC_MANAGER_CONNECT
        if (manager == 0) throw new Win32Exception();
        try
        {
            var service = OpenServiceW(manager, name, 0x2); // SERVICE_CHANGE_CONFIG
            if (service == 0) throw new Win32Exception();
            try
            {
                const uint NoChange = 0xFFFFFFFF;
                if (!ChangeServiceConfigW(service, NoChange, (uint)start, NoChange, null, null, 0, null, null, null, null))
                    throw new Win32Exception();
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    internal static partial nint OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    internal static partial nint OpenServiceW(nint manager, string name, uint access);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ChangeServiceConfigW(nint service, uint type, uint start, uint errorControl, string? binaryPath,
        string? loadOrderGroup, nint tagId, string? dependencies, string? account, string? password, string? displayName);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseServiceHandle(nint handle);
}
