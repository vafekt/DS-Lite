#!/usr/bin/env python3
"""
DS-Lite lab interactive menus — a command-palette front-end for run.sh.

Draws a filterable, arrow-key picker and prints the chosen token(s) to stdout,
so run.sh keeps doing the heavy lifting (spawning terminals, wiring namespaces)
and only the *selection UI* lives here. Capture the result with $(...):

    action=$(ds_menu.py main "isp")
    aid=$(ds_menu.py attacks "isp")
    val=$(printf 'fast\tfast\nmedium\tmedium\n' | ds_menu.py choose "intensity")

Modes (argv[1]):
  main       -> attack | watch | shell | restore | settings | quit
  attacks    -> an attack id (T1..T15)            [reads attack_corpus.txt]
  choose     -> a token, items read from stdin (token<TAB>label[<TAB>tag])
  placement  -> b4-1 | b4-2 | isp | internet | mgmt | none
  devices    -> space-separated namespaces (multi-select with space)

argv[2] = attacker-placement hint (shown in header).
Exit code 0 with a token on stdout = selection; exit 1 with empty stdout = cancelled (Esc).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))            # repo root
CORPUS = os.path.join(os.path.dirname(HERE), "attack_corpus.txt")

MAIN = [
    ("attack",   "1. Attack",   "pick an attack - runs it in one terminal, saves + compares to reference"),
    ("defenses", "2. Defenses", "turn a control on/off, then re-run the attack it closes"),
    ("watch",    "3. Watch",    "open Wireshark / a live monitor on any device"),
    ("shell",    "4. Shell",    "open a terminal on any device (or all)"),
    ("restore",  "5. Restore lab", "reset to a clean baseline (no restart, no Ctrl-C)"),
    ("settings", "6. Settings", "attacker placement / connectivity test"),
    ("quit",     "0. Quit",     "stop the lab and tear everything down"),
]

# Each verified defense, the attack(s) it closes, and a one-line description.
# The id is the article_defenses.sh toggle name. Kept in sync with the corpus.
DEFENSES = [
    ("TRABELSI",      "TRABELSI  (closes T1)",        "half-open early eviction; co-resident keeps service"),
    ("NAT_LOG",       "NAT_LOG  (closes T2)",         "per-binding attribution log for the shared IPv4"),
    ("SAVI",          "SAVI  (closes T3, T5, T6)",    "per-port carrier source binding; drops outer spoof"),
    ("ESP_AEAD",      "ESP_AEAD  (closes T4)",        "AES-GCM ESP on the softwire; no cleartext"),
    ("FEISTEL_IPID",  "FEISTEL_IPID  (closes T6)",    "Feistel IP-ID randomization at each B4"),
    ("PCP_QUOTA",     "PCP_QUOTA  (closes T7)",       "per-subscriber PCP mapping cap"),
    ("PCP_OWNERSHIP", "PCP_OWNERSHIP  (closes T8, T10)", "THIRD_PARTY/PEER bound to requester prefix"),
    ("PCP_AUTH",      "PCP_AUTH  (closes T9)",        "authenticated ANNOUNCE; forged epoch reset ignored"),
    ("DNS_0X20",      "DNS_0X20  (closes T11)",       "0x20 case randomization at the B4 resolver"),
    ("DHCPV6_AUTH",   "DHCPV6_AUTH  (closes T12, T13)", "Ed25519-signed DHCPv6; rogue ADVERTISE rejected"),
    ("SNMP_USM",      "SNMP_USM  (closes T14, T15)",  "SNMPv3 USM + engineID pin; v2c default denied"),
    ("__alloff__",    "Turn ALL defenses OFF",        "restore the vulnerable attack baseline"),
]

SETTINGS = [
    ("placement", "Set attacker placement", "where the attacker sits"),
    ("conntest",  "Run connectivity test",  "verify the lab is healthy"),
]

# Live monitors, one per attack surface of the paper's taxonomy (A1 NAT/CGN,
# A2 tunnel, A3 fragmentation, B1 PCP, B2 DNS, B3 DHCPv6, C1 SNMP) plus the
# subscriber-impact view. run.sh maps each token to a netns + live command.
MONITORS = [
    ("nat",      "AFTR NAT / conntrack table",         "A1 CGN"),
    ("softwire", "AFTR softwire (IPv4-in-IPv6)",        "A2 tunnel"),
    ("frag",     "AFTR fragment / reassembly counters", "A3 frag"),
    ("pcp",      "AFTR PCP control activity",           "B1 PCP"),
    ("dns",      "Resolver DNS queries / replies",      "B2 DNS"),
    ("dhcp",     "B4 DHCPv6 messages",                  "B3 DHCPv6"),
    ("snmp",     "AFTR SNMP (OAM) activity",            "C1 SNMP"),
    ("victim",   "Subscriber connectivity (victim)",    "impact"),
]

# Canonical 3-position model (paper submission/dimensions.tex): P1 customer LAN,
# P2 on-path IPv6 carrier, P3 operator OAM. An attack can be feasible from more
# than one position; to stage a multi-position / colluding attack, place the
# primary console here and open extra device shells (Shell menu) as accomplices.
# "internet" is kept for free exploration only: an external WAN host reaches just
# recon, so no corpus attack launches purely from there (no P4).
PLACEMENTS = [
    ("b4-1",     "B4-1 subscriber LAN",    "P1  customer LAN  (10.0.1.0/24)"),
    ("b4-2",     "B4-2 subscriber LAN",    "P1  2nd customer LAN  (10.0.2.0/24)"),
    ("isp",      "ISP / carrier segment",  "P2  on-path carrier  (2001:db8:cafe::/64)"),
    ("mgmt",     "OAM management network", "P3  operator OAM  (10.99.0.0/24)"),
    ("internet", "Public Internet / WAN",  "external, recon-only (no P4)  (198.51.100.0/24)"),
    ("none",     "No attacker", ""),
]

DEVICES = [
    ("dhcpv6server", "DHCPv6-Server", ""), ("dns-server", "DNS-Server", "::2"),
    ("b4-1", "B4-1", ""), ("b4-2", "B4-2", ""), ("aftr", "AFTR", ""),
    ("client1", "Client1", ""), ("client2", "Client2", ""),
    ("server-router", "Server-Router", ""), ("server", "Server", ""),
    ("attacker", "Attacker", ""), ("mgmt", "Mgmt-Station", "10.99.0.10"),
]


def load_attacks():
    rows = []
    try:
        with open(CORPUS) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) >= 4:
                    aid, group, name, vantage = parts[0], parts[1], parts[2], parts[3]
                    rows.append((aid, f"{aid:<4} {name}", f"{vantage} / {group.split(' ',1)[0]}"))
    except FileNotFoundError:
        pass
    return rows


def pick(items, title, header="", multi=False, filterable=True):
    """items: list of (token, label, tag). Returns token, list[token] if multi, or None."""
    from prompt_toolkit import Application
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout, HSplit, Window
    from prompt_toolkit.layout.controls import FormattedTextControl, BufferControl
    from prompt_toolkit.layout.dimension import D
    from prompt_toolkit.styles import Style

    state = {"cur": 0, "checked": set(), "filtered": list(range(len(items)))}
    search = Buffer()

    def refilter(_=None):
        q = search.text.lower()
        state["filtered"] = [i for i, (tok, lab, tag) in enumerate(items)
                             if q in lab.lower() or q in tag.lower() or q in tok.lower()]
        if state["cur"] >= len(state["filtered"]):
            state["cur"] = max(0, len(state["filtered"]) - 1)
    search.on_text_changed += refilter

    # Snug, content-fitted columns so every row aligns flush regardless of menu.
    # Layout per row: [sp][cursor 2][checkbox 0|4][label LABELW][gap 2][tag]
    # All glyphs are 7-bit ASCII so the alignment is identical on every terminal.
    LABEL_CAP = 56

    def _geometry():
        labels = [it[1] for it in items] or [""]
        tags = [it[2] for it in items] or [""]
        label_w = min(max(len(l) for l in labels), LABEL_CAP)
        box_w = 4 if multi else 0
        tag_w = max(len(t) for t in tags)
        # 1 left margin + cursor(2) + checkbox + label + 2 gap + tag
        rule_w = 1 + 2 + box_w + label_w + (2 + tag_w if tag_w else 0)
        return label_w, min(rule_w, 100)

    def render():
        label_w, rule_w = _geometry()
        out = []
        if header:
            out.append(("class:hdr", f" {header}\n"))
        out.append(("class:title", f" {title}\n"))
        if filterable:
            out.append(("class:dim", " search: "))
            out.append(("class:search", search.text or " "))
            out.append(("", "\n"))
        out.append(("class:dim", " " + "-" * rule_w + "\n"))
        view = state["filtered"]
        # window of up to 14 rows around the cursor
        top = max(0, min(state["cur"] - 6, max(0, len(view) - 14)))
        for row, idx in enumerate(view[top:top + 14], start=top):
            tok, lab, tag = items[idx]
            cursor = row == state["cur"]
            arrow = "> " if cursor else "  "
            box = (("[x] " if idx in state["checked"] else "[ ] ") if multi else "")
            disp = lab if len(lab) <= label_w else lab[:label_w - 3] + "..."
            if tag:
                line = f" {arrow}{box}{disp:<{label_w}}  {tag}"
            else:
                line = f" {arrow}{box}{disp}"
            out.append(("class:sel" if cursor else "", line + "\n"))
        if not view:
            out.append(("class:dim", "   (no match)\n"))
        out.append(("class:dim", " " + "-" * rule_w + "\n"))
        hint = "[Up/Dn] move   [Enter] select   [Esc] back"
        if multi:
            hint = "[Up/Dn] move   [Space] toggle   [^A] all   [Enter] confirm   [Esc] back"
        out.append(("class:dim", " " + hint))
        return out

    kb = KeyBindings()

    @kb.add("up")
    def _(e):
        state["cur"] = max(0, state["cur"] - 1)

    @kb.add("down")
    def _(e):
        state["cur"] = min(len(state["filtered"]) - 1, state["cur"] + 1)

    @kb.add("c-c")
    @kb.add("escape")
    def _(e):
        e.app.exit(result=None)

    if multi:
        @kb.add("space")
        def _(e):
            if state["filtered"]:
                idx = state["filtered"][state["cur"]]
                state["checked"] ^= {idx}

        # Select-all toggle. Ctrl-A is used (not a letter) so it never collides
        # with type-to-filter. It toggles the *currently filtered* set: if every
        # filtered row is already checked, clear them; otherwise check them all.
        @kb.add("c-a")
        def _(e):
            fset = set(state["filtered"])
            if fset and fset <= state["checked"]:
                state["checked"] -= fset
            else:
                state["checked"] |= fset

        @kb.add("enter")
        def _(e):
            e.app.exit(result=[items[i][0] for i in sorted(state["checked"])])
    else:
        @kb.add("enter")
        def _(e):
            if state["filtered"]:
                e.app.exit(result=items[state["filtered"][state["cur"]]][0])
            else:
                e.app.exit(result=None)

    body = Window(FormattedTextControl(render), always_hide_cursor=True)
    search_win = Window(BufferControl(buffer=search), height=0)  # captures typing
    # Focus the search window from frame 0 (focused_element) so the first
    # keystrokes are never dropped while the app is still starting up.
    layout = (Layout(HSplit([body, search_win]), focused_element=search_win)
              if filterable else Layout(body))

    style = Style.from_dict({
        "title": "bold",
        "hdr": "fg:#888888",
        "sel": "reverse",
        "dim": "fg:#888888",
        "search": "fg:#00afff bold",
    })
    # Render the UI on /dev/tty so the chosen token can still go to stdout when
    # run.sh captures it with $(...).  Fall back to the default streams (e.g. a
    # pty test) if /dev/tty is unavailable.
    # full_screen=True renders in the alternate screen and updates in place, so
    # the menu does not stack/reprint on terminals that do not answer cursor-
    # position requests (CPR); on exit the previous screen is restored, so
    # run.sh's result output is not clobbered.
    app_kwargs = dict(layout=layout, key_bindings=kb, style=style,
                      full_screen=True, mouse_support=False)
    try:
        from prompt_toolkit.input.defaults import create_input
        from prompt_toolkit.output.defaults import create_output
        app_kwargs["input"] = create_input(open("/dev/tty"))
        app_kwargs["output"] = create_output(stdout=open("/dev/tty", "w"))
    except Exception:
        pass
    app = Application(**app_kwargs)
    if filterable:
        app.layout.focus(search_win)
    return app.run()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "main"
    place = sys.argv[2] if len(sys.argv) > 2 else "none"
    active = sys.argv[3] if len(sys.argv) > 3 else ""

    if mode == "--list":   # non-interactive sanity check
        for tok, lab, tag in load_attacks():
            print(f"{tok}\t{lab}\t{tag}")
        return 0

    if mode == "choose":   # dynamic picker: items read from stdin
        # each line: "token" or "token<TAB>label" or "token<TAB>label<TAB>tag"
        title = sys.argv[2] if len(sys.argv) > 2 else "Choose"
        items = []
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t")
            tok = parts[0]
            lab = parts[1] if len(parts) > 1 else tok
            tag = parts[2] if len(parts) > 2 else ""
            items.append((tok, lab, tag))
        if not items:
            return 1
        r = pick(items, title + "  (type to filter)")
        if r is None:
            return 1
        print(r)
        return 0

    header = f"DS-Lite Lab    attacker: {place or 'none'}"
    if mode == "main":
        r = pick(MAIN, "What do you want to do?", header=header)
    elif mode == "attacks":
        r = pick(load_attacks(), "Attack - pick one (type to filter)", header=header)
    elif mode == "watch":
        # One place for both live monitors and a Wireshark capture.
        items = list(MONITORS) + [("wireshark", "Wireshark capture", "pick device + interface")]
        r = pick(items, "Watch - pick what to observe (type to filter)", header=header)
    elif mode == "defenses":
        r = pick(DEFENSES, "Defenses - pick a control to toggle (type to filter)", header=header)
    elif mode == "onoff":
        r = pick([("on", "Turn ON", "enable this control"),
                  ("off", "Turn OFF", "disable this control")],
                 sys.argv[2] if len(sys.argv) > 2 else "On or off?", header=header)
    elif mode == "monitors":
        r = pick(MONITORS, "Live monitor - pick a surface", header=header)
    elif mode == "settings":
        r = pick(SETTINGS, "Settings", header=header)
    elif mode == "placement":
        r = pick(PLACEMENTS, "Set attacker placement", header=header)
    elif mode in ("devices", "shell"):
        # "shell" adds an All-devices entry (the old workbench) on top.
        items = list(DEVICES)
        if mode == "shell":
            items = [("__all__", "All devices (workbench)", "every shell + cheatsheet")] + items
        r = pick(items, "Shell - pick device(s)", header=header, multi=True)
        if isinstance(r, list):
            print(" ".join(r)); return 0
    else:
        sys.stderr.write(f"unknown mode: {mode}\n"); return 2

    if r is None:
        return 1
    print(r)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        sys.exit(1)   # cancelled — exit quietly, no traceback
