#include "help.h"

#include "addr.h"
#include "tunnel.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool eth_name_port(const char *name, int *port)
{
    const char *p;
    uint32_t v;

    if (strncmp(name, "eth", 3) != 0)
        return false;
    p = name + 3;
    if (!*p)
        return false;
    for (const char *q = p; *q; q++) {
        if (*q < '0' || *q > '9')
            return false;
    }
    if (tr_parse_u32(p, 0, 255, &v))
        return false;
    *port = (int)v;
    return true;
}

static bool parse_dotted_vlan(const char *name, char *parent, size_t plen,
                              int *vid)
{
    const char *dot = strrchr(name, '.');
    uint32_t v;

    if (!dot || dot == name || !dot[1])
        return false;
    size_t n = (size_t)(dot - name);
    if (n >= plen)
        return false;
    memcpy(parent, name, n);
    parent[n] = '\0';
    if (tr_parse_u32(dot + 1, 1, 4094, &v))
        return false;
    *vid = (int)v;
    return true;
}

static void print_prefixes(FILE *f, const struct tr_iface *iface,
                           const char *indent)
{
    for (int i = 0; i < iface->naddrs; i++) {
        char a[96];
        tr_prefix_ntop(&iface->addrs[i], a, sizeof(a));
        fprintf(f, "%s%s\n", indent, a);
    }
    if (iface->ipv6_autoconf)
        fprintf(f, "%sipv6 autoconf\n", indent);
}

static void print_eth_summary(FILE *f, const struct tr_config *cfg)
{
    fprintf(f, "Ethernet interfaces:\n");
    int count = 0;
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present || iface->kind != TR_IF_ETHERNET)
            continue;
        count++;
        fprintf(f, "  %-16s ifindex %-2d DPDK port %d  mtu %u",
                iface->name, iface->slot, iface->port_id, iface->mtu);
        if (iface->naddrs || iface->ipv6_autoconf)
            fprintf(f, "  (has L3)");
        fprintf(f, "\n");
        for (int v = 0; v < TR_MAX_IFACES; v++) {
            const struct tr_iface *vlan = &cfg->ifaces[v];
            if (vlan->present && vlan->kind == TR_IF_VLAN &&
                vlan->parent == iface->slot)
                fprintf(f, "    VLAN %-10s mtu %u\n", vlan->name, vlan->mtu);
        }
    }
    if (!count)
        fprintf(f, "  (none; eth<N> is created automatically when a port "
                   "is available)\n");
}

static void print_free_ports(FILE *f, const struct tr_config *cfg, int nports)
{
    bool used[256] = {false};
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (iface->present && iface->kind == TR_IF_ETHERNET &&
            iface->port_id >= 0 && iface->port_id < 256)
            used[iface->port_id] = true;
    }
    fprintf(f, "DPDK ports: %d", nports);
    bool first = true;
    for (int p = 0; p < nports; p++) {
        if (used[p])
            continue;
        fprintf(f, "%s%d", first ? " (free: " : ", ", p);
        first = false;
    }
    fprintf(f, "%s\n", first ? "" : ")");
}

static void general_help(FILE *f, bool config_mode)
{
    fprintf(f, "dpdk-tunnel-router command help\n\n");
    fprintf(f, "  ?                          context help at the current prompt\n");
    fprintf(f, "  Up / Down                  command history\n");
    fprintf(f, "  Left / Right / Home / End  move the cursor\n");
    fprintf(f, "  Backspace / Delete         edit\n");
    fprintf(f, "  Ctrl-L                     clear screen\n");
    fprintf(f, "  Ctrl-C                     cancel current line\n");
    fprintf(f, "  Ctrl-D                     EOF / leave CLI\n");
    fprintf(f, "  set ?                      configuration paths\n");
    fprintf(f, "  set interfaces ?           interface types\n");
    fprintf(f, "  set interfaces ethernet eth1 ?\n");
    fprintf(f, "  set interfaces tunnel tun0 ?\n");
    fprintf(f, "  set interfaces bridge br0 ?\n");
    fprintf(f, "  set protocols static route ?\n");
    fprintf(f, "  show ?                     operational show topics\n");
    fprintf(f, "  tcpdump ?                  packet capture help\n");
    fprintf(f, "  delete ?                   deletion forms\n\n");
    if (!config_mode) {
        fprintf(f, "Read mode:\n");
        fprintf(f, "  show ...                   display running state\n");
        fprintf(f, "  configure                  enter configuration mode\n");
        fprintf(f, "  tcpdump start|stop|status  pcap capture\n");
        fprintf(f, "  exit | quit                leave the CLI\n\n");
        fprintf(f, "Configuration changes require configuration mode.\n");
        fprintf(f, "Use 'configure', then 'set ...' / 'delete ...' and "
                   "'save'.\n");
    } else {
        fprintf(f, "Configuration mode:\n");
        fprintf(f, "  set ...                    edit the candidate\n");
        fprintf(f, "  delete ... | del ...       remove candidate objects\n");
        fprintf(f, "  show configuration         show candidate\n");
        fprintf(f, "  show running-config        show active configuration\n");
        fprintf(f, "  save | commit              apply and persist candidate\n");
        fprintf(f, "  discard | rollback         discard candidate changes\n");
        fprintf(f, "  read | exit | end          return to read mode\n\n");
        fprintf(f, "Unsaved changes cannot be left with exit/read.\n");
    }
}

static void set_overview(FILE *f, const struct tr_config *cfg)
{
    fprintf(f, "set commands:\n\n");
    fprintf(f, "  set interfaces ethernet <name> [port <id>] [mtu <mtu>]\n");
    fprintf(f, "      [address <prefix>|address ipv6 autoconf]\n");
    fprintf(f, "      [vlan-id <1..4094> [address <prefix>|mtu <mtu>]]\n");
    fprintf(f, "  set interfaces tunnel <name> remote <IPv4|IPv6>\n");
    fprintf(f, "  set interfaces tunnel <name> local-address <IPv4|IPv6>\n");
    fprintf(f, "  set interfaces tunnel <name> local-interface <IF name>\n");
    fprintf(f, "  set interfaces tunnel <name> mtu <68..9000>\n");
    fprintf(f, "  set interfaces tunnel <name> encapsulation <name>\n");
    fprintf(f, "  set interfaces tunnel <name> tcp-mss <auto|none|N>\n");
    fprintf(f, "  set interfaces tunnel <name> address <prefix|ipv6 autoconf>\n");
    fprintf(f, "  set interfaces bridge <name> children <IF name>\n");
    fprintf(f, "  set interfaces bridge <name> mtu <68..9000>\n");
    fprintf(f, "  set protocols static route <prefix> via <same-family "
               "next-hop>\n\n");
    fprintf(f, "Context help examples:\n");
    fprintf(f, "  set interfaces ?\n");
    fprintf(f, "  set interfaces ethernet eth1 ?\n");
    fprintf(f, "  set interfaces tunnel tun0 ?\n\n");

    fprintf(f, "Current objects:\n");
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present)
            continue;
        const char *kind = iface->kind == TR_IF_ETHERNET ? "ethernet"
                          : iface->kind == TR_IF_VLAN   ? "vlan"
                          : iface->kind == TR_IF_TUNNEL ? "tunnel"
                                                        : "bridge";
        fprintf(f, "  %-8s %s\n", kind, iface->name);
    }
}

static void ethernet_overview(FILE *f, const struct tr_config *cfg, int nports)
{
    fprintf(f, "Ethernet / VLAN interfaces\n\n");
    print_eth_summary(f, cfg);
    print_free_ports(f, cfg, nports);
    fprintf(f,
            "\nSyntax:\n"
            "  set interfaces ethernet <name> [port <id>] [mtu <68..9000>]\n"
            "  set interfaces ethernet <name> address <IPv4|IPv6 prefix>\n"
            "  set interfaces ethernet <name> address ipv6 autoconf\n"
            "  set interfaces ethernet <name> vlan-id <1..4094> "
            "address <prefix>\n"
            "  set interfaces ethernet <name> vlan-id <1..4094> mtu <mtu>\n"
            "\n"
            "eth<N> is automatically mapped to DPDK port N when the port is\n"
            "available.  For a custom name, bind the port explicitly:\n"
            "  set interfaces ethernet wan0 port 1\n"
            "\n"
            "A VLAN command creates a child interface named <name>.<vid>.\n"
            "You can address the child directly as <name>.<vid>:\n"
            "  set interfaces ethernet eth0.10 address 192.168.10.1/24\n"
            "  set interfaces ethernet eth0.10 address ipv6 autoconf\n"
            "Examples:\n"
            "  set interfaces ethernet eth0 address 192.0.2.1/24\n"
            "  set interfaces ethernet eth0 address 2001:db8:1::1/64\n"
            "  set interfaces ethernet eth0 mtu 9000\n"
            "  set interfaces ethernet eth0 vlan-id 10 address "
            "192.168.10.1/24\n");
}

static void ethernet_interface_help(FILE *f, const struct tr_config *cfg,
                                    int nports, const char *name,
                                    const char *field)
{
    const struct tr_iface *iface = tr_config_find_const(cfg, name);
    char parent_name[TR_IFNAME_LEN] = "";
    int dotted_vid = 0;
    bool dotted = false;
    int inferred = -1;
    bool can_infer = eth_name_port(name, &inferred);

    if (!iface && parse_dotted_vlan(name, parent_name, sizeof(parent_name),
                                    &dotted_vid))
        dotted = true;
    bool is_vlan = iface && iface->kind == TR_IF_VLAN;
    bool vlan_like = is_vlan || dotted;

    if (iface && iface->kind != TR_IF_ETHERNET && !is_vlan) {
        fprintf(f, "Interface %s is not an Ethernet/VLAN interface.\n", name);
        return;
    }

    if (is_vlan) {
        char mac[18];
        tr_format_mac(iface->mac, mac);
        const struct tr_iface *parent =
            tr_config_find_slot_const(cfg, iface->parent);
        fprintf(f, "VLAN %s (current configuration)\n", iface->name);
        fprintf(f, "  ifindex: %d\n", iface->slot);
        fprintf(f, "  parent: %s\n",
                parent ? parent->name : "(missing)");
        fprintf(f, "  VLAN ID: %d\n", iface->vlan_id);
        fprintf(f, "  MTU: %u\n", iface->mtu);
        fprintf(f, "  MAC: %s\n", mac);
        fprintf(f, "  addresses:\n");
        if (!iface->naddrs && !iface->ipv6_autoconf)
            fprintf(f, "    (none)\n");
        print_prefixes(f, iface, "    ");
        if (iface->bridge >= 0)
            fprintf(f, "  bridge member: %s\n",
                    cfg->ifaces[iface->bridge].name);
    } else if (iface) {
        char mac[18];
        tr_format_mac(iface->mac, mac);
        fprintf(f, "Ethernet %s (current configuration)\n", iface->name);
        fprintf(f, "  ifindex: %d\n", iface->slot);
        fprintf(f, "  DPDK port: %d\n", iface->port_id);
        fprintf(f, "  MTU: %u\n", iface->mtu);
        fprintf(f, "  MAC: %s\n", mac);
        fprintf(f, "  addresses:\n");
        if (!iface->naddrs && !iface->ipv6_autoconf)
            fprintf(f, "    (none)\n");
        print_prefixes(f, iface, "    ");
        if (iface->bridge >= 0)
            fprintf(f, "  bridge member: %s\n",
                    cfg->ifaces[iface->bridge].name);
        bool vlan_header = false;
        for (int i = 0; i < TR_MAX_IFACES; i++) {
            const struct tr_iface *v = &cfg->ifaces[i];
            if (v->present && v->kind == TR_IF_VLAN &&
                v->parent == iface->slot) {
                if (!vlan_header) {
                    fprintf(f, "  VLAN children:\n");
                    vlan_header = true;
                }
                fprintf(f, "    %-16s mtu %u\n", v->name, v->mtu);
            }
        }
    } else if (dotted) {
        const struct tr_iface *parent =
            tr_config_find_const(cfg, parent_name);
        fprintf(f, "VLAN %s is not configured yet.\n", name);
        fprintf(f, "  parent: %s\n", parent_name);
        fprintf(f, "  VLAN ID: %d\n", dotted_vid);
        if (!parent)
            fprintf(f, "  Parent Ethernet '%s' does not exist; create it "
                       "first.\n", parent_name);
        else if (parent->kind != TR_IF_ETHERNET)
            fprintf(f, "  Parent '%s' is not an Ethernet interface.\n",
                    parent_name);
        else
            fprintf(f,
                    "  A command such as the following creates this VLAN:\n"
                    "  set interfaces ethernet %s address 192.0.2.1/24\n"
                    "  set interfaces ethernet %s address ipv6 autoconf\n",
                    name, name);
    } else {
        fprintf(f, "Ethernet %s is not configured yet.\n", name);
        if (can_infer && inferred < nports)
            fprintf(f,
                    "  %s maps automatically to DPDK port %d.  A command "
                    "such as\n"
                    "  'set interfaces ethernet %s address ...' creates it.\n",
                    name, inferred, name);
        else
            fprintf(f,
                    "  No automatic port mapping for this name.  Create it "
                    "with:\n"
                    "  set interfaces ethernet %s port <0..%d>\n",
                    name, nports > 0 ? nports - 1 : 0);
    }

    if (field && strcmp(field, "address") == 0) {
        fprintf(f,
                "\naddress property:\n"
                "  set interfaces ethernet %s address <IPv4 prefix>\n"
                "  set interfaces ethernet %s address <IPv6 prefix>\n"
                "  set interfaces ethernet %s address ipv6 autoconf\n\n"
                "  - CIDR is required for a useful connected route; a bare\n"
                "    address is treated as /32 or /128.\n"
                "  - Host bits are preserved in the interface address; the\n"
                "    connected FIB route is canonicalized.\n"
                "  - The command can be repeated for multiple addresses.\n"
                "  - ipv6 autoconf installs a SLAAC address from received\n"
                "    Router Advertisements and a default route via the RA\n"
                "    source.  This works on VLAN children too.\n\n"
                "Examples:\n"
                "  set interfaces ethernet %s address 192.0.2.1/24\n"
                "  set interfaces ethernet %s address 2001:db8:1::1/64\n"
                "  set interfaces ethernet %s address ipv6 autoconf\n",
                name, name, name, name, name, name);
        return;
    }
    if (field && strcmp(field, "mtu") == 0) {
        fprintf(f,
                "\nmtu property:\n"
                "  set interfaces ethernet %s mtu <68..9000>\n\n"
                "  - Default: 1500.\n"
                "  - This is the IP MTU; the Ethernet frame limit is MTU+14\n"
                "    (MTU+18 for a VLAN-tagged child).\n"
                "  - The DPDK port is initialized for up to 9600 byte frames;\n"
                "    the configured MTU is enforced in software.\n"
                "  - A tunnel underlay fragment size is based on the egress\n"
                "    interface MTU.\n",
                name);
        return;
    }
    if (field && strcmp(field, "port") == 0) {
        if (vlan_like) {
            fprintf(f,
                    "\nport property is not valid on a VLAN child.\n"
                    "  Configure the parent Ethernet instead:\n"
                    "  set interfaces ethernet %s port <id>\n",
                    dotted ? parent_name : "(parent)");
            return;
        }
        fprintf(f,
                "\nport property:\n"
                "  set interfaces ethernet %s port <0..%d>\n\n"
                "  - Binds the logical interface to a DPDK port.\n"
                "  - eth<N> is normally assigned automatically to port N.\n"
                "  - One DPDK port can be bound to only one Ethernet "
                "interface.\n"
                "  - Use 'show interfaces' / 'show status' to see ports.\n",
                name, nports > 0 ? nports - 1 : 0);
        return;
    }
    if (field && strcmp(field, "vlan-id") == 0) {
        if (vlan_like) {
            fprintf(f,
                    "\nvlan-id is not valid on a VLAN child.\n"
                    "  This interface is already a VLAN.  Address it directly:\n"
                    "  set interfaces ethernet %s address ipv6 autoconf\n",
                    name);
            return;
        }
        fprintf(f,
                "\nvlan-id property:\n"
                "  set interfaces ethernet %s vlan-id <1..4094> "
                "address <prefix|ipv6 autoconf>\n"
                "  set interfaces ethernet %s vlan-id <1..4094> mtu <mtu>\n\n"
                "  - Creates a child interface named %s.<vid>.\n"
                "  - The tag is terminated at the parent; L3/ARP/NDP runs on\n"
                "    the child with an untagged logical frame.\n"
                "  - VLAN children support static IPv4/IPv6 addresses and\n"
                "    address ipv6 autoconf (tagged RA/SLAAC).\n"
                "  - A VLAN child can also be a bridge member.\n"
                "  - VLAN IDs are local to the parent interface.\n"
                "  - The child can be addressed directly as "
                "<parent>.<vid>, e.g.\n"
                "    set interfaces ethernet eth0.10 address ipv6 autoconf\n\n"
                "Examples:\n"
                "  set interfaces ethernet %s vlan-id 10 address "
                "192.168.10.1/24\n"
                "  set interfaces ethernet %s vlan-id 10 address "
                "ipv6 autoconf\n"
                "  set interfaces ethernet %s.10 address ipv6 autoconf\n"
                "  set interfaces ethernet %s vlan-id 20 mtu 1500\n",
                name, name, name, name, name, name, name);
        return;
    }

    if (vlan_like) {
        fprintf(f,
                "\nValid properties for VLAN %s:\n"
                "  address <IPv4 prefix | IPv6 prefix | ipv6 autoconf>\n"
                "      Static L3 address or SLAAC/RA address on this VLAN.\n"
                "      Tagged RAs install a SLAAC address and a default route.\n"
                "  mtu <68..9000>\n"
                "      IP MTU (default 1500).  Enforced in software.\n\n"
                "Examples:\n"
                "  set interfaces ethernet %s address 192.168.10.1/24\n"
                "  set interfaces ethernet %s address 2001:db8:10::1/64\n"
                "  set interfaces ethernet %s address ipv6 autoconf\n"
                "  set interfaces ethernet %s mtu 1500\n",
                name, name, name, name, name);
        return;
    }

    fprintf(f,
            "\nValid properties for ethernet %s:\n"
            "  port <0..%d>\n"
            "      Bind to a DPDK port.  eth<N> is automatic; custom names\n"
            "      need this once.  A port can be used by only one interface.\n"
            "  address <IPv4 prefix | IPv6 prefix | ipv6 autoconf>\n"
            "      Add an L3 address.  Can be repeated.  ipv6 autoconf uses\n"
            "      RA/SLAAC.  Host bits are preserved.\n"
            "  mtu <68..9000>\n"
            "      IP MTU (default 1500).  Enforced in software.\n"
            "  vlan-id <1..4094> [address <prefix|ipv6 autoconf> | mtu <mtu>]\n"
            "      Create/configure child %s.<vid> with tag termination.\n"
            "  <name>.<vid> can also be used directly, e.g.\n"
            "      set interfaces ethernet eth0.10 address ipv6 autoconf\n\n"
            "Examples:\n"
            "  set interfaces ethernet %s address 192.0.2.1/24\n"
            "  set interfaces ethernet %s address 2001:db8:1::1/64\n"
            "  set interfaces ethernet %s address ipv6 autoconf\n"
            "  set interfaces ethernet %s vlan-id 10 address ipv6 autoconf\n"
            "  set interfaces ethernet %s mtu 9000\n",
            name, nports > 0 ? nports - 1 : 0, name, name, name, name, name,
            name);
}

static void tunnel_overview(FILE *f, const struct tr_config *cfg)
{
    fprintf(f, "Tunnel interfaces:\n");
    int count = 0;
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *iface = &cfg->ifaces[i];
        if (!iface->present || iface->kind != TR_IF_TUNNEL)
            continue;
        count++;
        char remote[96] = "-", local[96] = "-";
        if (iface->tunnel.remote.family)
            tr_ip_ntop(&iface->tunnel.remote, remote, sizeof(remote));
        if (iface->tunnel.local.family)
            tr_ip_ntop(&iface->tunnel.local, local, sizeof(local));
        fprintf(f, "  %-16s encap %-10s remote %s local %s mtu %u\n",
                iface->name, iface->tunnel.driver, remote, local, iface->mtu);
    }
    if (!count)
        fprintf(f, "  (none)\n");
    fprintf(f,
            "\nSyntax:\n"
            "  set interfaces tunnel <name> remote <IPv4|IPv6>\n"
            "  set interfaces tunnel <name> local-address <IPv4|IPv6>\n"
            "  set interfaces tunnel <name> local-interface <IF name>\n"
            "  set interfaces tunnel <name> mtu <68..9000>\n"
            "  set interfaces tunnel <name> encapsulation <name>\n"
            "  set interfaces tunnel <name> tcp-mss <auto|none|N>\n"
            "  set interfaces tunnel <name> address <prefix|"
            "ipv6 autoconf>\n\n"
            "Available encapsulations:\n");
    for (int i = 0; i < tr_tunnel_driver_count(); i++) {
        const struct tr_tnl_driver *d = tr_tunnel_driver_at(i);
        fprintf(f, "  %-16s %s%s\n", d->name,
                d->ipv6_only ? "IPv6 outer only" : "IPv4/IPv6 outer",
                d->builtin ? " (builtin)" : " (plugin)");
    }
    fprintf(f,
            "\nExamples:\n"
            "  set interfaces tunnel tun0 encapsulation etherip6\n"
            "  set interfaces tunnel tun0 remote 2001:db8:1::2\n"
            "  set interfaces tunnel tun0 local-address 2001:db8:1::1\n"
            "  set interfaces tunnel tun0 local-interface eth0\n"
            "  set interfaces tunnel tun0 mtu 9000\n"
            "  set interfaces tunnel tun0 tcp-mss auto\n"
            "  set interfaces tunnel tun0 address 10.0.0.1/30\n");
}

static void tunnel_interface_help(FILE *f, const struct tr_config *cfg,
                                  const char *name, const char *field)
{
    (void)field;
    const struct tr_iface *iface = tr_config_find_const(cfg, name);
    if (iface && iface->kind == TR_IF_TUNNEL) {
        char remote[96] = "-", local[96] = "-";
        if (iface->tunnel.remote.family)
            tr_ip_ntop(&iface->tunnel.remote, remote, sizeof(remote));
        if (iface->tunnel.local.family)
            tr_ip_ntop(&iface->tunnel.local, local, sizeof(local));
        fprintf(f, "Tunnel %s (current configuration)\n", iface->name);
        fprintf(f, "  ifindex: %d\n", iface->slot);
        fprintf(f, "  encapsulation: %s\n", iface->tunnel.driver);
        fprintf(f, "  remote: %s\n", remote);
        fprintf(f, "  local-address: %s\n", local);
        fprintf(f, "  local-interface: %s\n",
                iface->tunnel.local_if[0] ? iface->tunnel.local_if : "(FIB)");
        fprintf(f, "  mtu: %u\n", iface->mtu);
        fprintf(f, "  tcp-mss: ");
        if (iface->tunnel.tcp_mss < 0)
            fprintf(f, "none\n");
        else if (iface->tunnel.tcp_mss == 0)
            fprintf(f, "auto\n");
        else
            fprintf(f, "%d\n", iface->tunnel.tcp_mss);
        fprintf(f, "  addresses:\n");
        if (!iface->naddrs && !iface->ipv6_autoconf)
            fprintf(f, "    (none)\n");
        print_prefixes(f, iface, "    ");
        if (iface->bridge >= 0)
            fprintf(f, "  bridge member: %s\n",
                    cfg->ifaces[iface->bridge].name);
        fprintf(f, "\n");
    } else {
        fprintf(f,
                "Tunnel %s is not configured yet; the first set command "
                "creates it.\n\n",
                name);
    }
    fprintf(f,
            "Tunnel properties\n\n"
            "  remote <IPv4|IPv6>\n"
            "      Peer/outer destination.  Required for the tunnel to be up.\n"
            "  local-address <IPv4|IPv6>\n"
            "      Outer source address.  Must match remote family.  If\n"
            "      omitted, a source on local-interface is selected.\n"
            "  local-interface <IF name>\n"
            "      Pin the outer egress to Ethernet/VLAN.  Also used to\n"
            "      validate received outer packets.  Without it the FIB\n"
            "      route to remote selects the underlay.\n"
            "  mtu <68..9000>\n"
            "      Inner IP MTU.  Outer fragmentation handles underlay MTU\n"
            "      smaller than this value.  Default 1500.\n"
            "  encapsulation <name>\n"
            "      Tunnel driver.  Available:\n");
    for (int i = 0; i < tr_tunnel_driver_count(); i++) {
        const struct tr_tnl_driver *d = tr_tunnel_driver_at(i);
        fprintf(f, "        %-16s %s\n", d->name,
                d->ipv6_only ? "IPv6 outer only" : "IPv4/IPv6 outer");
    }
    fprintf(f,
            "      etherip6 = EtherIP/RFC3378 over IPv6\n"
            "      etherip  = EtherIP/RFC3378 over IPv4 or IPv6 (default)\n"
            "  tcp-mss <auto|none|N>\n"
            "      auto: clamp TCP MSS to underlay MTU minus outer/inner\n"
            "      headers; none: disable; N: fixed 64..8960.\n"
            "  address <prefix|ipv6 autoconf>\n"
            "      Inner L3 address (overlay).  Can be repeated.\n\n"
            "The interface is created by the first set command.  remote and\n"
            "either local-address or local-interface are required for it to\n"
            "become operational.\n\n"
            "Examples for %s:\n"
            "  set interfaces tunnel %s encapsulation etherip6\n"
            "  set interfaces tunnel %s remote 2001:db8:1::2\n"
            "  set interfaces tunnel %s local-address 2001:db8:1::1\n"
            "  set interfaces tunnel %s local-interface eth0\n"
            "  set interfaces tunnel %s mtu 9000\n"
            "  set interfaces tunnel %s tcp-mss auto\n"
            "  set interfaces tunnel %s address 10.0.0.1/30\n",
            name, name, name, name, name, name, name, name);
}

static void bridge_overview(FILE *f, const struct tr_config *cfg)
{
    fprintf(f, "Bridge interfaces:\n");
    for (int i = 0; i < TR_MAX_IFACES; i++) {
        const struct tr_iface *br = &cfg->ifaces[i];
        if (!br->present || br->kind != TR_IF_BRIDGE)
            continue;
        fprintf(f, "  %-16s mtu %u children:", br->name, br->mtu);
        for (int c = 0; c < br->nchildren; c++) {
            const struct tr_iface *child =
                tr_config_find_slot_const(cfg, br->children[c]);
            if (child)
                fprintf(f, " %s", child->name);
        }
        fprintf(f, "\n");
    }
    fprintf(f,
            "\nSyntax:\n"
            "  set interfaces bridge <name> children <IF name>\n"
            "  set interfaces bridge <name> mtu <68..9000>\n\n"
            "  - L2 bridge: MAC learning, flooding, ageing.\n"
            "  - Children can be Ethernet, VLAN, or tunnel interfaces.\n"
            "  - A child cannot have an L3 address or be a bridge.\n"
            "  - Nested bridges are not supported.\n"
            "  - MTU limits forwarded L2 frames (MTU+14 / +18 tagged).\n\n"
            "Examples:\n"
            "  set interfaces bridge br0 children eth0\n"
            "  set interfaces bridge br0 children tun0\n"
            "  set interfaces bridge br0 mtu 1500\n");
}

static void route_help(FILE *f)
{
    fprintf(f,
            "Static routes\n\n"
            "Syntax:\n"
            "  set protocols static route <prefix> via <next-hop>\n"
            "  delete protocols static route <prefix>\n\n"
            "  <prefix>   IPv4 or IPv6 CIDR (e.g. 0.0.0.0/0, 10.0.0.0/8,\n"
            "             ::/0, 2001:db8:ffff::/48)\n"
            "  <next-hop> must be the same address family; it is resolved\n"
            "             recursively against the FIB.  A next-hop must be\n"
            "             reachable through a connected or more-specific\n"
            "             route.  Unresolvable routes stay in the FIB but are\n"
            "             not usable until the next hop resolves.\n\n"
            "Examples:\n"
            "  set protocols static route 0.0.0.0/0 via 192.0.2.254\n"
            "  set protocols static route 10.0.0.0/8 via 192.0.2.1\n"
            "  set protocols static route 2001:db8:ffff::/48 via "
            "2001:db8:1::2\n\n"
            "Connected routes are generated automatically from interface\n"
            "addresses; do not add them as static routes.\n");
}

static void show_help(FILE *f)
{
    fprintf(f,
            "show commands\n\n"
            "  show configuration         running configuration (read mode)\n"
            "  show running-config        running configuration\n"
            "  show interfaces [name]     logical interfaces, addresses, MAC,\n"
            "                             VLAN children, runtime IPv6\n"
            "  show routes                FIB (connected/static/SLAAC)\n"
            "  show neighbors             ARP/NDP cache\n"
            "  show bridge                learned MAC table\n"
            "  show statistics            per-interface counters\n"
            "  show tunnels               tunnel state and parameters\n"
            "  show drivers               registered tunnel drivers\n"
            "  show status                DPDK ports, workers, drivers\n"
            "  show version               version information\n\n"
            "In configuration mode:\n"
            "  show configuration         candidate configuration\n"
            "  show interfaces            candidate interfaces\n"
            "  show running-config        active configuration\n"
            "  Operational tables (routes/neighbors/statistics) describe\n"
            "  the running data plane.\n");
}

static void tcpdump_help(FILE *f)
{
    fprintf(f,
            "tcpdump / packet capture\n\n"
            "Syntax:\n"
            "  tcpdump start [interface <name>|any] -w <file>\n"
            "                [-d rx|tx|both] [-s <64..16384>] [-c <count>]\n"
            "                [filter <expression>]\n"
            "  tcpdump -i <name|any> -w <file> ...   (start omitted)\n"
            "  tcpdump stop\n"
            "  tcpdump status\n\n"
            "  -w FILE      output pcap path (required)\n"
            "  -i IF        interface name, or any (default any)\n"
            "  -d DIR       rx, tx, or both (default both)\n"
            "  -s SNAPLEN   capture length 64..16384 (default 16384)\n"
            "  -c COUNT     stop after COUNT packets; 0 = unlimited\n"
            "  filter EXPR  simple AND filter, must be last\n\n"
            "Filter terms (AND; 'and' may be omitted):\n"
            "  ip | ip6 | arp\n"
            "  tcp | udp | icmp | icmp6\n"
            "  host ADDR | src host ADDR | dst host ADDR\n"
            "  port N | src port N | dst port N\n"
            "  vlan ID\n"
            "  ether host MAC\n"
            "  'or' is not supported.\n\n"
            "Capture points:\n"
            "  physical RX (VLAN tag included), physical TX after outer\n"
            "  encapsulation/fragmentation, VLAN child RX/TX untagged, tunnel\n"
            "  inner RX after decap, tunnel inner TX before encap.\n"
            "  'any' captures all taps; a tunnel can therefore show both\n"
            "  outer and inner packets.\n\n"
            "Examples:\n"
            "  tcpdump -i eth0 -w /tmp/eth0.pcap -c 100\n"
            "  tcpdump -i tun0 -w /tmp/tun0.pcap -d both\n"
            "  tcpdump -i any -w /tmp/tcp443.pcap filter \"tcp port 443\"\n"
            "  tcpdump status\n"
            "  tcpdump stop\n");
}

static void delete_help(FILE *f)
{
    fprintf(f,
            "delete commands\n\n"
            "  delete interfaces ethernet <name>\n"
            "  delete interfaces ethernet <name> vlan-id <1..4094>\n"
            "  delete interfaces ethernet <name> address <prefix>\n"
            "  delete interfaces tunnel <name>\n"
            "  delete interfaces tunnel <name> address <prefix>\n"
            "  delete interfaces bridge <name>\n"
            "  delete interfaces bridge <name> children <IF name>\n"
            "  delete protocols static route <prefix>\n\n"
            "Deleting an interface also removes its addresses, VLAN children,\n"
            "and bridge membership.  A deleted eth<N> can be recreated by a\n"
            "later 'set interfaces ethernet ethN ...' when port N is free.\n");
}

static void mode_command_help(FILE *f, const char *cmd)
{
    if (strcmp(cmd, "save") == 0 || strcmp(cmd, "commit") == 0)
        fprintf(f,
                "save / commit\n\n"
                "Applies the candidate configuration to the data plane and\n"
                "atomically writes the running configuration file.\n"
                "If validation or file write fails, the running state is\n"
                "rolled back and the candidate remains dirty.\n"
                "Available only in configuration mode.\n");
    else if (strcmp(cmd, "discard") == 0 || strcmp(cmd, "rollback") == 0)
        fprintf(f,
                "discard / rollback\n\n"
                "Replaces the candidate with the current running "
                "configuration.\n"
                "Available only in configuration mode.\n");
    else if (strcmp(cmd, "configure") == 0 || strcmp(cmd, "config") == 0)
        fprintf(f,
                "configure\n\n"
                "Enters configuration mode and copies the running config\n"
                "into a per-session candidate.  Exit with 'read', 'exit', or\n"
                "'end'; unsaved changes are refused.\n");
    else if (strcmp(cmd, "read") == 0 || strcmp(cmd, "end") == 0 ||
             strcmp(cmd, "exit") == 0)
        fprintf(f,
                "read / end / exit\n\n"
                "Leaves configuration mode.  If the candidate has unsaved\n"
                "changes, use 'save' or 'discard' first; otherwise the exit\n"
                "is refused.\n");
}

int tr_help_command(const struct tr_config *cfg, int nports, bool config_mode,
                    int argc, char **argv, char **out)
{
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f)
        return -1;

    const char *a0 = argc > 0 ? argv[0] : NULL;
    if (!a0) {
        general_help(f, config_mode);
    } else if (strcmp(a0, "set") == 0) {
        if (argc == 1) {
            set_overview(f, cfg);
        } else if (strcmp(argv[1], "interfaces") == 0) {
            if (argc == 2) {
                fprintf(f,
                        "set interfaces <type> ...\n\n"
                        "  ethernet <name>  physical/logical Ethernet, "
                        "VLAN, L3\n"
                        "  tunnel <name>    point-to-point L2 tunnel\n"
                        "  bridge <name>    L2 bridge\n\n"
                        "Context help:\n"
                        "  set interfaces ethernet eth1 ?\n"
                        "  set interfaces tunnel tun0 ?\n"
                        "  set interfaces bridge br0 ?\n");
            } else if (strcmp(argv[2], "ethernet") == 0) {
                if (argc == 3)
                    ethernet_overview(f, cfg, nports);
                else
                    ethernet_interface_help(f, cfg, nports, argv[3],
                                            argc >= 5 ? argv[4] : NULL);
            } else if (strcmp(argv[2], "tunnel") == 0) {
                if (argc == 3)
                    tunnel_overview(f, cfg);
                else
                    tunnel_interface_help(f, cfg, argv[3],
                                          argc >= 5 ? argv[4] : NULL);
            } else if (strcmp(argv[2], "bridge") == 0) {
                bridge_overview(f, cfg);
            } else {
                set_overview(f, cfg);
            }
        } else if (strcmp(argv[1], "protocols") == 0) {
            route_help(f);
        } else {
            set_overview(f, cfg);
        }
    } else if (strcmp(a0, "delete") == 0 || strcmp(a0, "del") == 0) {
        delete_help(f);
    } else if (strcmp(a0, "show") == 0) {
        show_help(f);
    } else if (strcmp(a0, "tcpdump") == 0 || strcmp(a0, "capture") == 0) {
        tcpdump_help(f);
    } else if (strcmp(a0, "save") == 0 || strcmp(a0, "commit") == 0 ||
               strcmp(a0, "discard") == 0 || strcmp(a0, "rollback") == 0 ||
               strcmp(a0, "configure") == 0 || strcmp(a0, "config") == 0 ||
               strcmp(a0, "read") == 0 || strcmp(a0, "end") == 0 ||
               strcmp(a0, "exit") == 0) {
        mode_command_help(f, a0);
    } else {
        fprintf(f, "No detailed help for '%s'.\n\n", a0);
        general_help(f, config_mode);
    }
    fclose(f);
    *out = buf;
    return 0;
}
