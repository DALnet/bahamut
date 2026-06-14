"""ircd.conf template generator for test servers."""

import os

# Core modules (auto-loaded from dpath/modules/core/)
CORE_MODULES = [
    "m_privmsg", "m_away", "m_wallops", "m_who", "m_gossip",
    "m_legacy_bridge",
]

# All extra modules we want loaded for full-feature testing
ALL_EXTRA_MODULES = [
    "m_account_notify",
    "m_account_tag",
    "m_away_notify",
    "m_batch",
    "m_bot_mode",
    "m_chathistory",
    "m_chghost",
    "m_echo_message",
    "m_extended_join",
    "m_gossip_eventlog",
    "m_invite_notify",
    "m_labeled_response",
    "m_monitor",
    "m_msgid",
    "m_server_time",
    "m_session",
    "m_setname",
    "m_starttls",
    "m_tagmsg",
    "m_tls_tag",
    "m_userhost_in_names",
    "m_webirc",
]

CONFIG_TEMPLATE = """\
global {{
    name    {server_name};
    info    "{server_info}";
}};

options {{
    network_name    TestNet;
    allow_split_ops;
    show_links;
}};

ssl {{
    certificate ircd.crt;
    key         ircd.key;
}};

{port_blocks}

class {{
    name     users;
    pingfreq 90;
    maxsendq 100000;
    maxusers 1000;
}};

class {{
    name     opers;
    pingfreq 90;
    maxsendq 500000;
}};

allow {{
    host  *@*;
    flags CFT;
    class users;
}};

oper {{
    name   admin;
    passwd secret;
    host   *@*;
    access OAaRD;
    class  opers;
}};

{server_class_block}

{gossip_block}

{gopeer_blocks}

{connect_blocks}

modules {{
    path {module_path};
{autoload_lines}
}};
"""


def _port_block(port, flags="ni"):
    if flags:
        return f'port {{ port {port}; bind 127.0.0.1; flags {flags}; }};'
    return f'port {{ port {port}; bind 127.0.0.1; }};'


def _setup_module_dirs(tmpdir, build_dir):
    """Create modules/core and modules/extra directories in tmpdir with symlinks.

    Meson builds all modules into a flat build/modules/ directory with 'lib'
    prefix (e.g. libm_privmsg.so). The server expects:
      - dpath/modules/core/*.so  (scanned by load_module_dir, any name works)
      - module_path/m_foo.so     (autoload uses module_path/<name>.so)

    We create per-file symlinks with the expected names.
    """
    build_modules = os.path.join(build_dir, "modules")
    core_dir = os.path.join(tmpdir, "modules", "core")
    extra_dir = os.path.join(tmpdir, "modules", "extra")
    os.makedirs(core_dir, exist_ok=True)
    os.makedirs(extra_dir, exist_ok=True)

    # Symlink core modules into modules/core/
    # load_module_dir scans *.so — any filename ending in .so works
    for mod in CORE_MODULES:
        src = os.path.join(build_modules, f"lib{mod}.so")
        dst = os.path.join(core_dir, f"{mod}.so")
        if os.path.exists(src) and not os.path.exists(dst):
            os.symlink(src, dst)

    # Symlink extra modules into modules/extra/
    # autoload calls load_module(name) → module_path/<name>.so
    for mod in ALL_EXTRA_MODULES:
        src = os.path.join(build_modules, f"lib{mod}.so")
        dst = os.path.join(extra_dir, f"{mod}.so")
        if os.path.exists(src) and not os.path.exists(dst):
            os.symlink(src, dst)

    return extra_dir


def generate_config(
    tmpdir,
    build_dir,
    server_name="irc.test",
    server_info="Test Server",
    irc_port=6667,
    ws_port=None,
    ssl_port=None,
    extra_modules=None,
    gopeer_configs=None,
    server_id=None,
    connect_configs=None,
):
    """Generate an ircd.conf in tmpdir and set up module symlinks.

    Args:
        tmpdir: Directory to write ircd.conf into (becomes dpath)
        build_dir: Path to the meson build directory (contains modules/)
        server_name: Server name for global block
        server_info: Server description
        irc_port: Main IRC port number
        ws_port: WebSocket port number (optional)
        ssl_port: SSL port number (optional)
        extra_modules: List of extra module names to autoload (default: all)
        gopeer_configs: List of dicts with keys: host, port, name, server_id
        server_id: This server's ID for gossip

    Returns:
        Path to the generated ircd.conf
    """
    if extra_modules is None:
        extra_modules = ALL_EXTRA_MODULES

    # Build port blocks
    port_blocks = [_port_block(irc_port, "ni")]
    if ws_port is not None:
        port_blocks.append(_port_block(ws_port, "Wni"))
    if ssl_port is not None:
        port_blocks.append(_port_block(ssl_port, "Sni"))

    # Build autoload lines
    autoload_lines = "\n".join(f"    autoload {m};" for m in extra_modules)

    # Build gossip/gopeer blocks
    gossip_block = ""
    gopeer_blocks_str = ""

    if gopeer_configs:
        gossip_block = "gossip {\n    fanout      3;\n    sync_window 30;\n};"
        gopeer_parts = []
        for gp in gopeer_configs:
            tls_line = "\n    tls;" if gp.get("tls") else ""
            gopeer_parts.append(
                f"gopeer {{\n"
                f"    host      {gp['host']};\n"
                f"    port      {gp['port']};\n"
                f"    name      {gp['name']};\n"
                f"    server_id {gp['server_id']};{tls_line}\n"
                f"}};"
            )
        gopeer_blocks_str = "\n\n".join(gopeer_parts)

    # Build connect{} blocks (TS5 server links)
    server_class_block = ""
    connect_blocks_str = ""

    if connect_configs:
        server_class_block = (
            "class {\n"
            "    name     servers;\n"
            "    pingfreq 120;\n"
            "    connfreq 5;\n"
            "    maxsendq 1000000;\n"
            "    maxlinks 10;\n"
            "};"
        )
        connect_parts = []
        for cc in connect_configs:
            flags_line = f"\n    flags       {cc['flags']};" if cc.get("flags") else ""
            port_line = f"\n    port        {cc['port']};" if cc.get("port") else ""
            connect_parts.append(
                f"connect {{\n"
                f"    name        {cc['name']};\n"
                f"    host        {cc['host']};"
                f"{port_line}\n"
                f"    apasswd     {cc['apasswd']};\n"
                f"    cpasswd     {cc['cpasswd']};"
                f"{flags_line}\n"
                f"    class       servers;\n"
                f"}};"
            )
        connect_blocks_str = "\n\n".join(connect_parts)

    # Set up module directories with proper symlinks
    extra_dir = _setup_module_dirs(tmpdir, build_dir)

    config_content = CONFIG_TEMPLATE.format(
        server_name=server_name,
        server_info=server_info,
        port_blocks="\n".join(port_blocks),
        module_path=extra_dir,
        autoload_lines=autoload_lines,
        server_class_block=server_class_block,
        gossip_block=gossip_block,
        gopeer_blocks=gopeer_blocks_str,
        connect_blocks=connect_blocks_str,
    )

    conf_path = os.path.join(tmpdir, "ircd.conf")
    with open(conf_path, "w") as f:
        f.write(config_content)

    return conf_path


# ---------------------------------------------------------------------------
# Old (master-branch) bahamut config — no modules, no gossip, no ssl block
# ---------------------------------------------------------------------------

OLD_CONFIG_TEMPLATE = """\
global {{
    name    {server_name};
    info    "{server_info}";
}};

options {{
    network_name    TestNet;
    allow_split_ops;
    show_links;
}};

{port_blocks}

class {{
    name     users;
    pingfreq 90;
    maxsendq 100000;
    maxusers 1000;
}};

class {{
    name     opers;
    pingfreq 90;
    maxsendq 500000;
}};

class {{
    name     servers;
    pingfreq 120;
    connfreq 5;
    maxsendq 1000000;
    maxlinks 10;
}};

allow {{
    host  *@*;
    class users;
}};

{connect_blocks}
"""


def generate_old_config(
    tmpdir,
    server_name="irc.test",
    server_info="Test Server",
    irc_port=6667,
    connect_configs=None,
):
    """Generate an ircd.conf for old (master-branch) bahamut.

    Old bahamut has no modules, no gossip, no ssl {} block.
    TLS certs are read from the working directory by compile-time paths.
    """
    port_blocks = [_port_block(irc_port, "")]

    connect_parts = []
    for cc in (connect_configs or []):
        flags_line = f"\n    flags       {cc['flags']};" if cc.get("flags") else ""
        port_line = f"\n    port        {cc['port']};" if cc.get("port") else ""
        connect_parts.append(
            f"connect {{\n"
            f"    name        {cc['name']};\n"
            f"    host        {cc['host']};"
            f"{port_line}\n"
            f"    apasswd     {cc['apasswd']};\n"
            f"    cpasswd     {cc['cpasswd']};"
            f"{flags_line}\n"
            f"    class       servers;\n"
            f"}};"
        )

    config_content = OLD_CONFIG_TEMPLATE.format(
        server_name=server_name,
        server_info=server_info,
        port_blocks="\n".join(port_blocks),
        connect_blocks="\n\n".join(connect_parts),
    )

    conf_path = os.path.join(tmpdir, "ircd.conf")
    with open(conf_path, "w") as f:
        f.write(config_content)

    return conf_path
