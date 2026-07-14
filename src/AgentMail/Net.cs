using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace AgentMail;

/// <summary>Local network address discovery for advertising all the ways a node can be reached.</summary>
static class Net
{
    /// <summary>
    /// This host's usable LAN IPv4 addresses: RFC1918, on an interface that has a default gateway
    /// (so host-only virtual switches like WSL/Hyper-V, which have no gateway, are excluded), and
    /// not the Tailscale CGNAT range (100.64.0.0/10 — that's covered by the MagicDNS endpoint).
    /// </summary>
    public static IEnumerable<string> LanIPv4()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var props = ni.GetIPProperties();
            bool hasGateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
            if (!hasGateway) continue; // skip host-only virtual switches
            foreach (var ua in props.UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                string ip = ua.Address.ToString();
                if (IsPrivate(ip) && !IsTailscale(ip)) yield return ip;
            }
        }
    }

    private static bool IsTailscale(string ip)
    {
        // 100.64.0.0/10 => 100.64.0.0 .. 100.127.255.255
        var p = ip.Split('.');
        return p.Length == 4 && p[0] == "100" && int.TryParse(p[1], out int b) && b >= 64 && b <= 127;
    }

    private static bool IsPrivate(string ip)
    {
        var p = ip.Split('.');
        if (p.Length != 4 || !int.TryParse(p[0], out int a) || !int.TryParse(p[1], out int b)) return false;
        return a == 10
            || (a == 192 && b == 168)
            || (a == 172 && b >= 16 && b <= 31);
    }
}
