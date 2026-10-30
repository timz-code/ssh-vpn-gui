from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk, Pango  # noqa: E402

from .cascade import CASCADE_KINDS, CASCADE_LABELS, socks5_proxy
from .paths import SUDOERS_RULE, SYSTEM_HELPER, SYSTEM_ROUTING_FILE
from .ssh_tunnel import tunnel_daemon_started_at
from .system import CASCADE_HELPER_TIMEOUT_SECONDS, is_fail_closed, load_tunnel_state
from .tunnel_watch import TunnelSnapshot, evaluate_tunnel_health, inspect_tunnel


APP_ID = "dev.cursor.SshVpnGui"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ssh-vpn-gui"
CONFIG_FILE = CONFIG_DIR / "config.json"
WATCH_INTERVAL_MS = 4000
WALL_SLEEP_GAP_SECONDS = 25
DEAD_STREAK_LIMIT = 2
MAX_AUTO_RECONNECTS = 8
SLOW_RECONNECT_INTERVAL_MS = 60_000
BLOCKED_STATUS = (
    "Tunnel is down. Non-direct traffic is blocked. "
    "Connect to retry, or Exit and Restore to return to the system routes."
)
# In CASCADE_KINDS order.
CASCADE_CHOICES = ("None", "OpenVPN (.ovpn file)", "Tor", "SOCKS5 proxy")
CASCADE_HINTS = {
    "none": "Tunnel traffic leaves the server from its own address.",
    "ovpn": "Tunnel traffic leaves through your OpenVPN provider.",
    "tor": "TCP and DNS go through Tor. Other UDP and ping are blocked.",
    "socks5": "TCP and DNS go through the proxy. Other UDP and ping are blocked.",
}
SOCKS5_FIELDS = ("name", "host", "port", "user", "password")


def connected_button_label(elapsed_seconds: float) -> str:
    """`Connected 1:02:05`, or `Connected 2d 3:04:05` after a day."""
    total = max(0, int(elapsed_seconds))
    days, rest = divmod(total, 24 * 60 * 60)
    hours, rest = divmod(rest, 60 * 60)
    minutes, seconds = divmod(rest, 60)
    clock = f"{hours}:{minutes:02d}:{seconds:02d}"
    if days:
        return f"Connected {days}d {clock}"
    return f"Connected {clock}"


def connection_started_at(recorded: float | None, *, now: float) -> float:
    """Uptime origin for a tunnel found already running.

    `recorded` is the daemon pid file's mtime. A missing, zero or future
    value means the real start is unknown, so counting begins at `now`.
    """
    if recorded is None or recorded <= 0 or recorded > now:
        return now
    return recorded


def next_reconnect_delay_ms(attempts: int) -> int | None:
    """Delay before the next auto-reconnect. None means try immediately."""
    if attempts < MAX_AUTO_RECONNECTS:
        return None
    return SLOW_RECONNECT_INTERVAL_MS


def wall_clock_implies_sleep(elapsed_seconds: float) -> bool:
    return elapsed_seconds > WALL_SLEEP_GAP_SECONDS


def disconnect_args_for_reap(
    *, server: str, login: str, password: str, routing: bool = True
) -> tuple[list[str], str | None]:
    args = ["disconnect", "--fail-closed"]
    if not routing:
        args.append("--no-routing")
    if server and login and password:
        args.extend(["--server", server, "--login", login])
        return args, password
    args.append("--local-only")
    if server:
        args.extend(["--server", server])
    return args, None


def network_is_available() -> bool | None:
    try:
        monitor = Gio.NetworkMonitor.get_default()
        if not monitor.get_network_available():
            return False
        return monitor.get_connectivity() != Gio.NetworkConnectivity.LOCAL
    except Exception:
        return None


class RoutingEditorWindow(Gtk.Window):
    def __init__(self, parent: "SshVpnWindow") -> None:
        super().__init__(title="Edit Routing Rules", transient_for=parent, modal=True)
        self.parent_window = parent
        self.set_default_size(720, 520)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda _button: self.close())
        self.save_button = Gtk.Button(label="Save")
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", self._on_save_clicked)

        header = Gtk.HeaderBar()
        header.pack_start(cancel_button)
        header.pack_end(self.save_button)
        self.set_titlebar(header)

        self.text_view = Gtk.TextView()
        self.text_view.set_monospace(True)
        self.text_view.set_wrap_mode(Gtk.WrapMode.NONE)
        self.text_view.set_top_margin(12)
        self.text_view.set_bottom_margin(12)
        self.text_view.set_left_margin(12)
        self.text_view.set_right_margin(12)

        self.message = Gtk.Label()
        self.message.set_xalign(0)
        self.message.set_wrap(True)
        self.message.add_css_class("dim-label")

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)
        scroller.set_hexpand(True)
        scroller.set_child(self.text_view)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.append(scroller)
        content.append(self.message)
        self.set_child(content)

        try:
            text = SYSTEM_ROUTING_FILE.read_text(encoding="utf-8")
        except OSError as exc:
            text = ""
            self.message.set_text(f"Unable to read routing rules: {exc}")
            self.save_button.set_sensitive(False)
        self.text_view.get_buffer().set_text(text)

    def _on_save_clicked(self, _button: Gtk.Button) -> None:
        buffer = self.text_view.get_buffer()
        content = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)
        self.save_button.set_sensitive(False)
        self.text_view.set_editable(False)
        self.message.set_text("Validating and saving routing rules...")

        def worker() -> None:
            result = run_helper(["save-routing"], password=None, content=content)
            GLib.idle_add(self._handle_save_result, result)

        threading.Thread(target=worker, daemon=True).start()

    def _handle_save_result(self, result: dict) -> bool:
        if result.get("ok"):
            self.close()
            self.parent_window._on_routing_rules_saved()
        else:
            self.message.set_text(result.get("error", "Unable to save routing rules"))
            self.save_button.set_sensitive(True)
            self.text_view.set_editable(True)
        return False


class ServerEditorWindow(Gtk.Window):
    def __init__(self, parent: "SshVpnWindow") -> None:
        super().__init__(title="Add server", transient_for=parent, modal=True)
        self.parent_window = parent
        self.set_default_size(460, 340)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda _button: self.close())
        self.save_button = Gtk.Button(label="Save")
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", self._on_save_clicked)

        header = Gtk.HeaderBar()
        header.pack_start(cancel_button)
        header.pack_end(self.save_button)
        self.set_titlebar(header)

        _host_row, self.host_entry = _entry_row("Server")
        self.host_entry.set_placeholder_text("203.0.113.10")
        _notice_row, self.notice_entry = _entry_row("Notice")
        self.notice_entry.set_placeholder_text("Vultr")
        _login_row, self.login_entry = _entry_row("Login")
        self.login_entry.set_text("root")
        _password_row, self.password_entry = _entry_row("Password", password=True)

        self.message = Gtk.Label(label="The same login on the same host replaces the saved password.")
        self.message.set_xalign(0)
        self.message.set_wrap(True)
        self.message.add_css_class("dim-label")

        group = Adw.PreferencesGroup()
        group.add(_host_row)
        group.add(_notice_row)
        group.add(_login_row)
        group.add(_password_row)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)
        content.append(group)
        content.append(self.message)
        self.set_child(content)
        self.host_entry.grab_focus()

    def _on_save_clicked(self, _button: Gtk.Button) -> None:
        error = self.parent_window.add_server(
            self.host_entry.get_text(),
            self.login_entry.get_text(),
            self.password_entry.get_text(),
            self.notice_entry.get_text(),
        )
        if error:
            self.message.set_text(error)
            return
        self.close()


class Socks5EditorWindow(Gtk.Window):
    def __init__(self, parent: "SshVpnWindow") -> None:
        super().__init__(title="Add SOCKS5 proxy", transient_for=parent, modal=True)
        self.parent_window = parent
        self._saved = False
        self.set_default_size(460, 410)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda _button: self.close())
        self.save_button = Gtk.Button(label="Save")
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", self._on_save_clicked)

        header = Gtk.HeaderBar()
        header.pack_start(cancel_button)
        header.pack_end(self.save_button)
        self.set_titlebar(header)

        name_row, self.name_entry = _entry_row("Name")
        self.name_entry.set_placeholder_text("Optional, shown in the list")
        host_row, self.host_entry = _entry_row("Address")
        self.host_entry.set_placeholder_text("192.168.1.20 or proxy.example.com")
        port_row, self.port_entry = _entry_row("Port")
        self.port_entry.set_placeholder_text("1080")
        self.port_entry.set_input_purpose(Gtk.InputPurpose.DIGITS)
        user_row, self.user_entry = _entry_row("Login")
        self.user_entry.set_placeholder_text("Optional")
        password_row, self.password_entry = _entry_row("Password", password=True)
        self.password_entry.set_placeholder_text("Optional")

        self.message = Gtk.Label(
            label=(
                "The VPN server connects to this proxy, so it must be reachable from the server. "
                "Saving the same address, port and login again replaces the saved name and password."
            )
        )
        self.message.set_xalign(0)
        self.message.set_wrap(True)
        self.message.add_css_class("dim-label")

        group = Adw.PreferencesGroup()
        group.add(name_row)
        group.add(host_row)
        group.add(port_row)
        group.add(user_row)
        group.add(password_row)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)
        content.append(group)
        content.append(self.message)
        self.set_child(content)
        self.connect("close-request", self._on_close_request)
        self.name_entry.grab_focus()

    def _on_save_clicked(self, _button: Gtk.Button) -> None:
        error = self.parent_window.add_socks5(
            self.host_entry.get_text(),
            self.port_entry.get_text(),
            self.user_entry.get_text(),
            self.password_entry.get_text(),
            self.name_entry.get_text(),
        )
        if error:
            self.message.set_text(error)
            return
        self._saved = True
        self.close()

    def _on_close_request(self, _window: Gtk.Window) -> bool:
        if not self._saved:
            self.parent_window.socks5_editor_cancelled()
        return False


class OvpnEditorWindow(Gtk.Window):
    def __init__(self, parent: "SshVpnWindow") -> None:
        super().__init__(title="Add OpenVPN profile", transient_for=parent, modal=True)
        self.parent_window = parent
        self._saved = False
        self._path = ""
        self._dialog: Gtk.FileChooserNative | None = None
        self.set_default_size(460, 280)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda _button: self.close())
        self.save_button = Gtk.Button(label="Save")
        self.save_button.add_css_class("suggested-action")
        self.save_button.connect("clicked", self._on_save_clicked)

        header = Gtk.HeaderBar()
        header.pack_start(cancel_button)
        header.pack_end(self.save_button)
        self.set_titlebar(header)

        name_row, self.name_entry = _entry_row("Name")
        self.name_entry.set_placeholder_text("Optional, shown in the list")
        choose_button = Gtk.Button(label="Choose…")
        choose_button.set_valign(Gtk.Align.CENTER)
        choose_button.connect("clicked", self._on_choose_clicked)
        self.file_row = Adw.ActionRow(title="File", subtitle="No file chosen")
        # A path is not Pango markup.
        self.file_row.set_use_markup(False)
        self.file_row.add_suffix(choose_button)
        self.file_row.set_activatable_widget(choose_button)

        self.message = Gtk.Label(
            label=(
                "The profile must be self-contained, with certificates and keys inline. "
                "Adding the same file again replaces its saved name."
            )
        )
        self.message.set_xalign(0)
        self.message.set_wrap(True)
        self.message.add_css_class("dim-label")

        group = Adw.PreferencesGroup()
        group.add(name_row)
        group.add(self.file_row)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)
        content.append(group)
        content.append(self.message)
        self.set_child(content)
        self.connect("close-request", self._on_close_request)
        self.name_entry.grab_focus()

    def _on_choose_clicked(self, _button: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative(
            title="Select an OpenVPN configuration",
            transient_for=self,
            modal=True,
            action=Gtk.FileChooserAction.OPEN,
            accept_label="_Open",
            cancel_label="_Cancel",
        )
        ovpn_filter = Gtk.FileFilter()
        ovpn_filter.set_name("OpenVPN config (*.ovpn, *.conf)")
        ovpn_filter.add_pattern("*.ovpn")
        ovpn_filter.add_pattern("*.conf")
        dialog.add_filter(ovpn_filter)
        dialog.connect("response", self._on_dialog_response)
        self._dialog = dialog
        dialog.show()

    def _on_dialog_response(self, dialog: Gtk.FileChooserNative, response: int) -> None:
        self._dialog = None
        chosen = dialog.get_file() if response == Gtk.ResponseType.ACCEPT else None
        path = chosen.get_path() if chosen is not None else None
        if path:
            self._path = path
            self.file_row.set_subtitle(path)

    def _on_save_clicked(self, _button: Gtk.Button) -> None:
        error = self.parent_window.add_ovpn(self._path, self.name_entry.get_text())
        if error:
            self.message.set_text(error)
            return
        self._saved = True
        self.close()

    def _on_close_request(self, _window: Gtk.Window) -> bool:
        if not self._saved:
            self.parent_window.ovpn_editor_cancelled()
        return False


class SshVpnWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application) -> None:
        super().__init__(application=application, title="SSH VPN")
        self.set_default_size(680, 540)
        self.connected = False
        self.busy = False
        self._fail_closed = False
        self._exiting = False
        self._exit_after_restore = False
        self._suppress_toggle = False
        self._pending_routing: bool | None = None
        self._suppress_cascade_change = False
        # (requested, previous) second hop while cascade-on/off runs.
        self._pending_cascade: tuple[str, str] | None = None
        # Second hop to go back to if the OpenVPN or SOCKS5 editor opened by a
        # dropdown choice is closed without saving.
        self._cascade_fallback: str | None = None
        self._watch_source: int | None = None
        self._watch_in_flight = False
        self._dead_streak = 0
        self._last_wall = time.time()
        self._reaping = False
        self._pending_reconnect = False
        self._auto_reconnects = 0
        self._auto_connect_in_flight = False
        self._slow_reconnect_source: int | None = None
        self._resume_probe_active = False
        self._peer_watch_usable = False
        self._sleep_subscription = 0
        self._login1_connection: Gio.DBusConnection | None = None
        # Wall-clock moment the current tunnel came up. None while disconnected.
        self._connected_since: float | None = None
        self._uptime_source: int | None = None

        saved_config = load_saved_config()
        self.servers: list[dict[str, str]] = saved_config["servers"]
        # The server the running tunnel belongs to. Choosing another one in
        # the list while connected switches the tunnel over to it.
        self._active_server: dict[str, str] | None = None
        self._connecting_server: dict[str, str] | None = None
        self.server_row = ChoiceRow(
            "Server",
            empty_text="No servers yet",
            add_tooltip="Add server",
            remove_tooltip="Remove server",
            on_selected=self._on_server_selected,
            on_add=self._on_add_server_clicked,
            on_remove=self._on_remove_server_clicked,
        )

        self.routing_switch = Gtk.CheckButton()
        self.routing_switch.set_valign(Gtk.Align.CENTER)
        self.routing_switch.set_active(saved_config["routing"])
        self.routing_switch.connect("toggled", self._on_routing_toggled)
        routing_row = Adw.ActionRow(title="Routing rules", subtitle="Checked: use routing.cfg. Unchecked: send all traffic through tunnel.")
        routing_row.add_suffix(self.routing_switch)
        routing_row.set_activatable_widget(self.routing_switch)

        self.tls_switch = Gtk.CheckButton()
        self.tls_switch.set_valign(Gtk.Align.CENTER)
        self.tls_switch.set_active(saved_config["tls"])
        self.tls_switch.connect("toggled", self._on_tls_toggled)
        tls_row = Adw.ActionRow(
            title="Hide tunnel as TLS",
            subtitle="Send the tunnel as TLS data transfer. The server needs an open port, usually 443.",
        )
        tls_row.add_suffix(self.tls_switch)
        tls_row.set_activatable_widget(self.tls_switch)

        self.cascade_mode: str = saved_config["cascade_mode"]
        self.cascade_dropdown = Gtk.DropDown.new(Gtk.StringList.new(list(CASCADE_CHOICES)), None)
        self.cascade_dropdown.set_factory(_full_text_factory())
        self.cascade_dropdown.set_valign(Gtk.Align.CENTER)
        self.cascade_dropdown.set_selected(CASCADE_KINDS.index(self.cascade_mode))
        self.cascade_dropdown.connect("notify::selected", self._on_cascade_selected)
        self.cascade_row = Adw.ActionRow(title="Second hop")
        self.cascade_row.add_suffix(self.cascade_dropdown)

        self.ovpn_files: list[dict[str, str]] = saved_config["ovpn_files"]
        self.ovpn_row = ChoiceRow(
            "OpenVPN config",
            empty_text="No .ovpn files yet",
            add_tooltip="Add .ovpn file",
            remove_tooltip="Remove .ovpn file from the list",
            on_selected=self._on_ovpn_selected,
            on_add=self._open_ovpn_editor,
            on_remove=self._on_remove_ovpn_clicked,
        )
        self.socks5_proxies: list[dict[str, str]] = saved_config["socks5_proxies"]
        self.socks5_row = ChoiceRow(
            "SOCKS5 proxy",
            empty_text="No proxies yet",
            add_tooltip="Add SOCKS5 proxy",
            remove_tooltip="Remove SOCKS5 proxy",
            on_selected=self._on_socks5_selected,
            on_add=self._open_socks5_editor,
            on_remove=self._on_remove_socks5_clicked,
        )
        self._refresh_server_list(select=saved_config["selected"])
        self._refresh_ovpn_list(select=saved_config["ovpn_selected"])
        self._refresh_socks5_list(select=saved_config["socks5_selected"])
        self._update_cascade_rows()

        self.connect_button = Gtk.Button(label="Connect")
        self.connect_button.add_css_class("suggested-action")
        self.connect_button.connect("clicked", self._on_connect_clicked)
        # The uptime on this button ticks every second. Tabular figures keep
        # "1" and "0" the same width, so the button does not jump sideways.
        connect_label = self.connect_button.get_child()
        if isinstance(connect_label, Gtk.Label):
            figures = Pango.AttrList()
            figures.insert(Pango.attr_font_features_new("tnum"))
            connect_label.set_attributes(figures)

        self.disconnect_button = Gtk.Button(label="Disconnect")
        self.disconnect_button.connect("clicked", self._on_disconnect_clicked)
        self.disconnect_button.set_sensitive(False)

        self.exit_restore_button = Gtk.Button(label="Exit and Restore")
        self.exit_restore_button.add_css_class("destructive-action")
        self.exit_restore_button.connect("clicked", self._on_exit_restore_clicked)
        self.exit_restore_button.set_visible(False)

        self.update_geo_button = Gtk.Button(label="Update Routing Data")
        self.update_geo_button.connect("clicked", self._on_update_geo_clicked)

        self.edit_routing_button = Gtk.Button(label="Edit Routing Rules")
        self.edit_routing_button.connect("clicked", lambda _button: self.open_routing_editor())

        routing_button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        routing_button_box.append(self.update_geo_button)
        routing_button_box.append(self.edit_routing_button)

        self.diagnose_button = Gtk.Button(label="Diagnose")
        self.diagnose_button.connect("clicked", self._on_diagnose_clicked)

        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        button_box.set_margin_top(12)
        button_box.set_hexpand(True)
        button_box.append(self.connect_button)
        button_box.append(self.disconnect_button)
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        button_box.append(spacer)
        button_box.append(self.exit_restore_button)

        self.status = Gtk.Label(label="Ready")
        self.status.set_wrap(True)
        self.status.set_xalign(0)
        self.status.set_yalign(0)
        self.status.set_selectable(True)
        self.status.set_margin_top(8)
        self.status.set_margin_bottom(8)
        self.status.set_margin_start(8)
        self.status.set_margin_end(8)
        self.status.add_css_class("dim-label")

        self.status_scroller = Gtk.ScrolledWindow()
        self.status_scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.status_scroller.set_size_request(-1, 168)
        self.status_scroller.set_vexpand(True)
        self.status_scroller.add_css_class("card")
        self.status_scroller.set_child(self.status)

        group = Adw.PreferencesGroup(title="Connection")
        group.add(self.server_row.row)
        group.add(routing_row)
        group.add(tls_row)
        group.add(self.cascade_row)
        group.add(self.ovpn_row.row)
        group.add(self.socks5_row.row)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(24)
        content.set_margin_end(24)
        content.append(group)
        content.append(button_box)
        content.append(routing_button_box)
        content.append(self.diagnose_button)
        content.append(Gtk.Separator())
        content.append(self.status_scroller)

        header = Adw.HeaderBar()
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        # Adw.ApplicationWindow lays its content out at the content's minimum
        # width and clips what does not fit. Narrower than this, wrapped row
        # subtitles push the bottom of the status card out of the window.
        root.set_size_request(600, -1)
        root.append(header)
        root.append(content)
        self.set_content(root)
        self._set_busy(False)
        self._subscribe_sleep_signal()
        self.connect("close-request", self._on_close_request)
        GLib.idle_add(self._sync_existing_tunnel)

    def open_routing_editor(self) -> None:
        RoutingEditorWindow(self).present()

    def _on_routing_rules_saved(self) -> None:
        if self.connected and self.routing_switch.get_active() and not self.busy:
            server, _login, _password = self._tunnel_credentials()
            args = ["routing-on", "--server", server]
            self._run_helper(args, password=None, busy_text="Applying updated routing rules...")
        else:
            self._set_status("Routing rules saved. They will be used on the next connection.")

    def _on_connect_clicked(self, _button: Gtk.Button | None) -> None:
        if _button is not None:
            self._auto_reconnects = 0
            self._auto_connect_in_flight = False
            self._cancel_slow_reconnect()
        server = self._selected_server()
        if server is None or not server["login"] or not server["password"]:
            self._set_status("Add a server with a login and password, then choose it.")
            return

        try:
            cascade_args = self._cascade_args(self.cascade_mode)
        except ValueError as exc:
            self._set_status(str(exc))
            return

        self._save_config()
        args = self._connect_args(server)
        args.extend(cascade_args)
        self._connecting_server = dict(server)
        self._run_helper(
            args,
            password=server["password"],
            socks5_password=self._socks5_password(self.cascade_mode),
            busy_text="Connecting...",
        )

    def _switch_server(self) -> None:
        """Move the running tunnel to the server just chosen in the list."""
        previous = self._active_server
        target = self._selected_server()
        if target is None or previous is None or _same_server(target, previous):
            self._save_config()
            return
        if not target["login"] or not target["password"]:
            self._show_active_server()
            self._set_status(
                f"{server_label(target)} has no saved password. Disconnect, then add it again with +."
            )
            return
        try:
            cascade_args = self._cascade_args(self.cascade_mode)
        except ValueError as exc:
            self._show_active_server()
            self._set_status(str(exc))
            return

        self._save_config()
        self._auto_reconnects = 0
        self._auto_connect_in_flight = False
        self._cancel_slow_reconnect()
        args = self._connect_args(target)
        args.extend(cascade_args)
        args.extend(["--previous-server", previous["host"], "--previous-login", previous["login"]])
        self._connecting_server = dict(target)
        self._run_helper(
            args,
            password=target["password"],
            previous_password=previous["password"],
            socks5_password=self._socks5_password(self.cascade_mode),
            busy_text=f"Switching from {server_label(previous)} to {server_label(target)}...",
            action="switch",
        )

    def _on_disconnect_clicked(self, _button: Gtk.Button) -> None:
        self._pending_reconnect = False
        self._auto_connect_in_flight = False
        self._cancel_slow_reconnect()
        args = ["disconnect"]
        server, login, password = self._tunnel_credentials()
        if server and login and password:
            self._save_config()
            args.extend(["--server", server, "--login", login])
        self._run_helper(args, password=password, busy_text="Disconnecting...")

    def _on_exit_restore_clicked(self, _button: Gtk.Button | None) -> None:
        self._pending_reconnect = False
        self._auto_connect_in_flight = False
        self._cancel_slow_reconnect()
        self._exiting = True
        if self.busy:
            self._exit_after_restore = True
            self._set_status("Will restore system routing and exit when the current action finishes.")
            return
        self._start_exit_restore()

    def _start_exit_restore(self) -> None:
        args = ["disconnect"]
        server, login, password = self._tunnel_credentials()
        if server and login and password:
            args.extend(["--server", server, "--login", login])
        else:
            args.append("--local-only")
            if server:
                args.extend(["--server", server])
            password = None
        self._run_helper(
            args,
            password=password,
            busy_text="Restoring system routing, then exiting...",
            action="exit-restore",
        )

    def _on_close_request(self, *_args) -> bool:
        if self._fail_closed and not self._exiting:
            self._on_exit_restore_clicked(None)
            return True
        if not self._exiting:
            self._stop_uptime_timer()
        return bool(self._exiting)

    def _on_update_geo_clicked(self, _button: Gtk.Button) -> None:
        self._run_helper(["update-geo"], password=None, busy_text="Updating routing data...")

    def _on_diagnose_clicked(self, _button: Gtk.Button) -> None:
        args = ["diagnose"]
        server, _login, _password = self._tunnel_credentials()
        if server:
            args.extend(["--server", server])
        self._run_helper(args, password=None, busy_text="Running diagnostics...")

    def _on_routing_toggled(self, _button: Gtk.CheckButton) -> None:
        if self._suppress_toggle:
            return
        state = self.routing_switch.get_active()
        if not self.connected:
            self._save_config()
            return
        server, _login, _password = self._tunnel_credentials()
        args = ["routing-on" if state else "routing-off"]
        if server:
            args.extend(["--server", server])
        self._pending_routing = not state
        self._run_helper(args, password=None, busy_text="Updating routing...")

    def _on_cascade_selected(self, _dropdown: Gtk.DropDown, _pspec: GLib.ParamSpec) -> None:
        if self._suppress_cascade_change:
            return
        kind = self._selected_cascade()
        previous = self.cascade_mode
        self._update_cascade_rows()
        if kind == previous:
            return
        if kind == "ovpn" and not self.ovpn_files:
            self._cascade_fallback = previous
            self._set_status("Add the .ovpn file for the OpenVPN second hop.")
            self._open_ovpn_editor()
            return
        if kind == "socks5" and not self.socks5_proxies:
            self._cascade_fallback = previous
            self._set_status("Add the SOCKS5 proxy for the second hop.")
            self._open_socks5_editor()
            return
        self._select_cascade(kind, previous=previous)

    def _select_cascade(self, kind: str, *, previous: str, replacing: bool = False) -> None:
        if self.busy:
            self._set_cascade_dropdown(previous)
            self._set_status("Wait for the current action to finish, then choose the second hop again.")
            return
        if self.connected:
            self._apply_cascade(kind, previous=previous, replacing=replacing)
            return
        self.cascade_mode = kind
        self._save_config()
        if kind == "none":
            self._set_status("No second hop. Traffic will leave the server from its own address.")
        else:
            self._set_status(f"Second hop: {self._cascade_title(kind)}. It starts with the next connection.")

    def _apply_cascade(self, kind: str, *, previous: str, replacing: bool = False) -> None:
        server, login, password = self._tunnel_credentials()
        if not server or not login or not password:
            self._set_cascade_dropdown(previous)
            self._set_status("Choose a saved server.")
            return
        try:
            cascade_args = self._cascade_args(kind)
        except ValueError as exc:
            self._set_cascade_dropdown(previous)
            self._set_status(str(exc))
            return

        if kind == "none":
            args = ["cascade-off", "--server", server, "--login", login]
            busy_text = "Stopping the second hop on the server..."
        else:
            args = ["cascade-on", "--server", server, "--login", login, *cascade_args]
            item = self._cascade_item(kind)
            if replacing and item:
                busy_text = f"Switching {CASCADE_LABELS[kind]} on the server to {item}..."
            else:
                busy_text = f"Starting {self._cascade_title(kind)} on the server..."
        self._pending_cascade = (kind, previous)
        self._run_helper(
            args,
            password=password,
            socks5_password=self._socks5_password(kind),
            busy_text=busy_text,
        )

    def _cascade_args(self, kind: str) -> list[str]:
        """Helper arguments for a second hop. The ValueError message is for the user."""
        if kind == "ovpn":
            path = self._selected_ovpn()
            if not path:
                raise ValueError("Add a .ovpn file for the OpenVPN second hop, or set Second hop to None.")
            if not Path(path).is_file():
                raise ValueError(f"{path} no longer exists. Choose another .ovpn file, or set Second hop to None.")
            return ["--cascade", "ovpn", "--ovpn-file", path]
        if kind == "tor":
            return ["--cascade", "tor"]
        if kind == "socks5":
            saved = self._selected_socks5()
            if saved is None:
                raise ValueError("Add a SOCKS5 proxy, or set Second hop to None.")
            proxy = socks5_proxy(saved["host"], saved["port"], saved["user"], saved["password"])
            args = ["--cascade", "socks5", f"--socks5-server={proxy.host}:{proxy.port}"]
            if proxy.user:
                args.append(f"--socks5-user={proxy.user}")
            return args
        return []

    def _socks5_password(self, kind: str) -> str | None:
        if kind != "socks5":
            return None
        saved = self._selected_socks5()
        return saved["password"] if saved is not None else ""

    def _cascade_item(self, kind: str) -> str:
        """The chosen .ovpn file or proxy, as its list shows it."""
        if kind == "ovpn":
            return self.ovpn_row.selected_label()
        if kind == "socks5":
            return self.socks5_row.selected_label()
        return ""

    def _cascade_title(self, kind: str) -> str:
        item = self._cascade_item(kind)
        return f"{CASCADE_LABELS[kind]} ({item})" if item else CASCADE_LABELS[kind]

    def _selected_ovpn(self) -> str:
        index = self.ovpn_row.selected()
        return self.ovpn_files[index]["path"] if index is not None and index < len(self.ovpn_files) else ""

    def _selected_socks5(self) -> dict[str, str] | None:
        index = self.socks5_row.selected()
        return self.socks5_proxies[index] if index is not None and index < len(self.socks5_proxies) else None

    def _refresh_ovpn_list(self, *, select: int) -> None:
        self.ovpn_row.set_items(ovpn_labels(self.ovpn_files), select=select)
        self._update_hop_tooltips()
        self._update_list_controls()

    def _refresh_socks5_list(self, *, select: int) -> None:
        self.socks5_row.set_items(socks5_labels(self.socks5_proxies), select=select)
        self._update_hop_tooltips()
        self._update_list_controls()

    def _update_hop_tooltips(self) -> None:
        # The lists may show names instead of files and addresses.
        self.ovpn_row.dropdown.set_tooltip_text(self._selected_ovpn() or None)
        proxy = self._selected_socks5()
        self.socks5_row.dropdown.set_tooltip_text(socks5_address(proxy) if proxy is not None else None)

    def _on_ovpn_selected(self) -> None:
        self._switch_hop_entry("ovpn", self.ovpn_row)
        self._update_hop_tooltips()

    def _on_socks5_selected(self) -> None:
        self._switch_hop_entry("socks5", self.socks5_row)
        self._update_hop_tooltips()

    def _switch_hop_entry(self, kind: str, row: ChoiceRow) -> None:
        """A new choice in a second-hop list restarts that hop if it is running."""
        if self.connected and self.cascade_mode == kind:
            try:
                self._cascade_args(kind)
            except ValueError as exc:
                # The running hop keeps the previous entry.
                row.revert()
                self._set_status(str(exc))
                return
            self._save_config()
            self._select_cascade(kind, previous=kind, replacing=True)
        else:
            self._save_config()

    def _on_remove_ovpn_clicked(self) -> None:
        index = self.ovpn_row.selected()
        if index is None or index >= len(self.ovpn_files):
            return
        removed = self.ovpn_row.selected_label()
        self.ovpn_files, next_index = remove_item(self.ovpn_files, index)
        self._refresh_ovpn_list(select=next_index)
        self._save_config()
        self._set_status(f"Removed {removed} from the list. The file itself is kept.")

    def _on_remove_socks5_clicked(self) -> None:
        index = self.socks5_row.selected()
        if index is None or index >= len(self.socks5_proxies):
            return
        removed = self.socks5_row.selected_label()
        self.socks5_proxies, next_index = remove_item(self.socks5_proxies, index)
        self._refresh_socks5_list(select=next_index)
        self._save_config()
        self._set_status(f"Removed SOCKS5 proxy {removed}.")

    def _open_socks5_editor(self) -> None:
        Socks5EditorWindow(self).present()

    def _open_ovpn_editor(self) -> None:
        OvpnEditorWindow(self).present()

    def add_socks5(self, host: str, port: str, user: str, password: str, name: str = "") -> str | None:
        try:
            proxy = socks5_proxy(host, port, user, password)
        except ValueError as exc:
            return str(exc)
        saved = {
            "name": _clean_name(name),
            "host": proxy.host,
            "port": str(proxy.port),
            "user": proxy.user,
            "password": proxy.password,
        }
        before = self._selected_socks5()
        self.socks5_proxies, index = upsert_socks5(self.socks5_proxies, saved)
        self._refresh_socks5_list(select=index)
        self._save_config()
        changed = before is None or {**before, "name": ""} != {**saved, "name": ""}
        self._hop_entry_added(
            "socks5", f"Saved SOCKS5 proxy {self.socks5_row.selected_label()}.", changed=changed
        )
        return None

    def add_ovpn(self, path: str, name: str = "") -> str | None:
        if not path:
            return "Choose the .ovpn file."
        if not Path(path).is_file():
            return f"{path} no longer exists."
        before = self._selected_ovpn()
        self.ovpn_files, index = upsert_ovpn(self.ovpn_files, {"name": _clean_name(name), "path": path})
        self._refresh_ovpn_list(select=index)
        self._save_config()
        self._hop_entry_added(
            "ovpn", f"Saved OpenVPN profile {self.ovpn_row.selected_label()}.", changed=path != before
        )
        return None

    def _hop_entry_added(self, kind: str, message: str, *, changed: bool) -> None:
        """Start the hop with a saved entry. A new name alone (not changed) does not restart it."""
        fallback, self._cascade_fallback = self._cascade_fallback, None
        if fallback is not None:
            self._select_cascade(kind, previous=fallback)
        elif changed and self.connected and self.cascade_mode == kind:
            self._select_cascade(kind, previous=kind, replacing=True)
        else:
            self._set_status(message)

    def socks5_editor_cancelled(self) -> None:
        fallback, self._cascade_fallback = self._cascade_fallback, None
        if fallback is not None:
            self._set_cascade_dropdown(fallback)
            self._set_status("SOCKS5 proxy not set. The second hop is unchanged.")

    def ovpn_editor_cancelled(self) -> None:
        fallback, self._cascade_fallback = self._cascade_fallback, None
        if fallback is not None:
            self._set_cascade_dropdown(fallback)
            self._set_status("No .ovpn file added. The second hop is unchanged.")

    def _selected_cascade(self) -> str:
        index = self.cascade_dropdown.get_selected()
        if index == Gtk.INVALID_LIST_POSITION or index >= len(CASCADE_KINDS):
            return "none"
        return CASCADE_KINDS[index]

    def _set_cascade_dropdown(self, kind: str) -> None:
        self._suppress_cascade_change = True
        try:
            self.cascade_dropdown.set_selected(CASCADE_KINDS.index(kind))
        finally:
            self._suppress_cascade_change = False
        self._update_cascade_rows()

    def _update_cascade_rows(self) -> None:
        kind = self._selected_cascade()
        self.cascade_row.set_subtitle(CASCADE_HINTS[kind])
        self.ovpn_row.row.set_visible(kind == "ovpn")
        self.socks5_row.row.set_visible(kind == "socks5")

    def _connect_args(self, server: dict[str, str]) -> list[str]:
        args = ["connect", "--server", server["host"], "--login", server["login"]]
        if not self.routing_switch.get_active():
            args.append("--no-routing")
        if self.tls_switch.get_active():
            args.append("--tls")
        return args

    def _on_tls_toggled(self, _button: Gtk.CheckButton) -> None:
        self._save_config()
        if self.connected and not self.busy:
            self._reconnect_for_tls()

    def _reconnect_for_tls(self) -> None:
        """Rebuild the running tunnel so the checkbox takes effect now."""
        server = self._active_server or self._selected_server()
        if server is None or not server["login"] or not server["password"]:
            self._set_status("Add a server with a login and password, then choose it.")
            return
        try:
            cascade_args = self._cascade_args(self.cascade_mode)
        except ValueError as exc:
            self._set_status(str(exc))
            return
        self._auto_reconnects = 0
        self._auto_connect_in_flight = False
        self._cancel_slow_reconnect()
        args = self._connect_args(server)
        args.extend(cascade_args)
        args.extend(["--previous-server", server["host"], "--previous-login", server["login"]])
        self._connecting_server = dict(server)
        hiding = self.tls_switch.get_active()
        self._run_helper(
            args,
            password=server["password"],
            previous_password=server["password"],
            socks5_password=self._socks5_password(self.cascade_mode),
            busy_text="Hiding the tunnel as TLS..." if hiding else "Turning TLS hiding off...",
            action="switch",
        )

    def _save_config(self) -> None:
        save_config(
            servers=self.servers,
            selected=self.server_row.selected() or 0,
            routing=self.routing_switch.get_active(),
            tls=self.tls_switch.get_active(),
            cascade_mode=self.cascade_mode,
            ovpn_files=self.ovpn_files,
            ovpn_selected=self.ovpn_row.selected() or 0,
            socks5_proxies=self.socks5_proxies,
            socks5_selected=self.socks5_row.selected() or 0,
        )

    def _selected_server(self) -> dict[str, str] | None:
        index = self.server_row.selected()
        return self.servers[index] if index is not None and index < len(self.servers) else None

    def _credentials(self) -> tuple[str, str, str]:
        server = self._selected_server()
        if server is None:
            return "", "", ""
        return server["host"], server["login"], server["password"]

    def _tunnel_credentials(self) -> tuple[str, str, str]:
        """The server the running tunnel belongs to, else the chosen one."""
        if self.connected and self._active_server is not None:
            server = self._active_server
            return server["host"], server["login"], server["password"]
        return self._credentials()

    def _active_server_index(self) -> int | None:
        if self._active_server is None:
            return None
        for index, server in enumerate(self.servers):
            if _same_server(server, self._active_server):
                return index
        return None

    def _show_active_server(self) -> None:
        index = self._active_server_index()
        if index is not None:
            self.server_row.select(index)
        self._save_config()

    def _adopt_tunnel_server(self) -> None:
        """Point the list at the server whose tunnel is running."""
        binding = load_tunnel_state()
        host = binding.server if binding is not None else ""
        chosen = self._active_server or self._selected_server()
        if host:
            for server in (self._active_server, self._selected_server(), *self.servers):
                if server is not None and server["host"] == host:
                    chosen = server
                    break
        self._active_server = dict(chosen) if chosen is not None else None
        self._show_active_server()

    def _refresh_server_list(self, *, select: int) -> None:
        self.server_row.set_items([server_label(server) for server in self.servers], select=select)
        self._update_list_controls()

    def _on_server_selected(self) -> None:
        if self.connected and not self.busy:
            self._switch_server()
        else:
            self._save_config()

    def _on_add_server_clicked(self) -> None:
        ServerEditorWindow(self).present()

    def add_server(self, host: str, login: str, password: str, notice: str = "") -> str | None:
        try:
            self.servers, index = upsert_server(self.servers, host, login, password, notice)
        except ValueError as exc:
            return str(exc)
        self._refresh_server_list(select=index)
        self._save_config()
        self._set_status(f"Saved {server_label(self.servers[index])}.")
        return None

    def _on_remove_server_clicked(self) -> None:
        index = self.server_row.selected()
        if index is None or index >= len(self.servers):
            return
        removed = server_label(self.servers[index])
        self.servers, next_index = remove_item(self.servers, index)
        self._refresh_server_list(select=next_index)
        self._save_config()
        self._set_status(f"Removed {removed}.")

    def _set_switch_active(self, switch: Gtk.CheckButton, active: bool) -> None:
        self._suppress_toggle = True
        try:
            switch.set_active(active)
        finally:
            self._suppress_toggle = False

    def _run_helper(
        self,
        args: list[str],
        *,
        password: str | None,
        busy_text: str,
        action: str | None = None,
        socks5_password: str | None = None,
        previous_password: str | None = None,
    ) -> None:
        self._set_busy(True)
        self._set_status(busy_text)
        command_name = action or args[0]

        def worker() -> None:
            result = run_helper(
                args,
                password=password,
                socks5_password=socks5_password,
                previous_password=previous_password,
                on_progress=lambda message: GLib.idle_add(self._set_status, message),
            )
            # Whether a failed switch got as far as closing the old tunnel.
            snapshot = inspect_tunnel() if command_name == "switch" and not result.get("ok") else None
            GLib.idle_add(self._handle_helper_result, command_name, result, snapshot)

        threading.Thread(target=worker, daemon=True).start()

    def _handle_helper_result(
        self, command: str, result: dict, snapshot: TunnelSnapshot | None = None
    ) -> bool:
        if command == "reap":
            return self._handle_reap_result(result)
        switching = command == "switch"
        if switching:
            command = "connect"
        if switching and not result.get("ok") and snapshot is not None and snapshot.process_up:
            previous = self._active_server
            self._connecting_server = None
            self._adopt_tunnel_server()
            current = self._active_server
            if current is None:
                note = "The tunnel is still up."
            elif previous is not None and _same_server(current, previous):
                note = f"Still connected to {server_label(current)}."
            else:
                note = f"Connected to {server_label(current)}."
            self._set_status(f"{result.get('error', 'Unknown helper error')}\n{note}")
        elif result.get("ok"):
            if command == "connect":
                self.connected = True
                # Count from this moment, not from the daemon's pid file: the
                # button only appears once the helper finishes, and a second
                # hop can take minutes after the tunnel itself is up.
                self._connected_since = time.time()
                self._active_server, self._connecting_server = self._connecting_server, None
                self._fail_closed = False
                self._auto_reconnects = 0
                self._auto_connect_in_flight = False
                self._cancel_slow_reconnect()
                self._dead_streak = 0
                self._peer_watch_usable = False
                self._start_watch()
            elif command == "disconnect":
                self.connected = False
                self._active_server = None
                self._fail_closed = False
                self._pending_reconnect = False
                self._auto_connect_in_flight = False
                self._cancel_slow_reconnect()
                self._stop_watch()
            elif command == "exit-restore":
                self.connected = False
                self._fail_closed = False
                self._stop_watch()
                self._set_busy(False)
                application = self.get_application()
                if application is not None:
                    application.quit()
                else:
                    self.destroy()
                return False
            if command in {"cascade-on", "cascade-off"} and self._pending_cascade is not None:
                self.cascade_mode = self._pending_cascade[0]
            if command in {"routing-on", "routing-off", "cascade-on", "cascade-off"}:
                self._save_config()
            self._pending_routing = None
            self._pending_cascade = None
            messages = result.get("messages") or []
            self._set_status("Done." if not messages else "\n".join(messages[-5:]))
        else:
            if command == "connect":
                self.connected = False
                self._active_server = self._connecting_server = None
                self._stop_watch()
                if is_fail_closed():
                    self._fail_closed = True
            elif command == "exit-restore":
                self._exiting = False
                self._exit_after_restore = False
            if self._pending_routing is not None:
                self._set_switch_active(self.routing_switch, self._pending_routing)
                self._pending_routing = None
                self._save_config()
            if self._pending_cascade is not None:
                _requested, previous = self._pending_cascade
                # A failed start leaves no second hop on the server: the
                # remote script or the helper's check stops it.
                self.cascade_mode = "none" if command == "cascade-on" else previous
                self._set_cascade_dropdown(self.cascade_mode)
                self._pending_cascade = None
                self._save_config()
            self._set_status(result.get("error", "Unknown helper error"))
        self._set_busy(False)
        if self._exit_after_restore and not self.busy:
            self._exit_after_restore = False
            self._start_exit_restore()
            return False
        if (
            command == "connect"
            and not result.get("ok")
            and self._fail_closed
            and not self._exiting
        ):
            if self._auto_connect_in_flight:
                self._auto_reconnect()
            else:
                self._schedule_slow_reconnect(result.get("error"))
        return False

    def _handle_reap_result(self, result: dict) -> bool:
        self._reaping = False
        self.connected = False
        self._active_server = None
        self._fail_closed = True
        self._stop_watch()
        reconnect = self._pending_reconnect
        self._pending_reconnect = False
        if self._exit_after_restore:
            self._set_busy(False)
            self._exit_after_restore = False
            self._start_exit_restore()
            return False
        if result.get("ok") and reconnect:
            self._set_busy(False)
            self._auto_reconnect()
            return False
        if result.get("ok"):
            self._set_status(BLOCKED_STATUS)
        else:
            self._set_status(result.get("error", "Unable to clean up the dead tunnel"))
        self._set_busy(False)
        return False

    def _sync_existing_tunnel(self) -> bool:
        threading.Thread(target=self._sync_existing_tunnel_worker, daemon=True).start()
        return False

    def _sync_existing_tunnel_worker(self) -> None:
        snapshot = inspect_tunnel()
        GLib.idle_add(self._apply_startup_snapshot, snapshot)

    def _apply_startup_snapshot(self, snapshot: TunnelSnapshot) -> bool:
        if self.busy or self.connected:
            return False
        if snapshot.process_up:
            self.connected = True
            self._connected_since = connection_started_at(tunnel_daemon_started_at(), now=time.time())
            self._adopt_tunnel_server()
            self._peer_watch_usable = snapshot.peer_reachable
            self._start_watch()
            self._set_status("Existing SSH tunnel is still up.")
            self._set_busy(False)
        elif snapshot.leftover:
            self._reap_dead_tunnel(
                snapshot,
                reconnect=False,
                reason="A previous tunnel is no longer healthy.",
            )
        elif is_fail_closed():
            self._fail_closed = True
            self._set_status(BLOCKED_STATUS)
            self._set_busy(False)
        return False

    def _subscribe_sleep_signal(self) -> None:
        try:
            connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            self._sleep_subscription = connection.signal_subscribe(
                "org.freedesktop.login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                "/org/freedesktop/login1",
                None,
                Gio.DBusSignalFlags.NONE,
                self._on_prepare_for_sleep,
            )
            self._login1_connection = connection
        except Exception:
            self._sleep_subscription = 0
            self._login1_connection = None

    def _on_prepare_for_sleep(
        self,
        _connection: Gio.DBusConnection,
        _sender: str | None,
        _object_path: str,
        _interface: str,
        _signal: str,
        parameters: GLib.Variant,
    ) -> None:
        going_to_sleep = bool(parameters.unpack()[0])
        if going_to_sleep:
            return
        self._auto_reconnects = 0
        self._cancel_slow_reconnect()
        GLib.idle_add(self._on_system_resumed)

    def _on_system_resumed(self) -> bool:
        if not self.connected or self.busy or self._reaping or self._resume_probe_active:
            return False
        self._resume_probe_active = True
        self._set_status("Computer woke up. Checking the tunnel...")
        threading.Thread(target=self._resume_probe_worker, daemon=True).start()
        return False

    def _resume_probe_worker(self) -> None:
        snapshot = inspect_tunnel()
        network: bool | None = None
        for attempt in range(8):
            if attempt:
                time.sleep(1.5)
            snapshot = inspect_tunnel()
            if snapshot.alive:
                break
            network = network_is_available()
            if network is False:
                continue
            if attempt >= 2:
                break
        GLib.idle_add(self._finish_resume_probe, snapshot, network)

    def _finish_resume_probe(self, snapshot: TunnelSnapshot, network: bool | None) -> bool:
        self._resume_probe_active = False
        if not self.connected or self.busy or self._reaping:
            return False
        if self._snapshot_is_healthy(snapshot, require_peer=True):
            self._dead_streak = 0
            self._set_status("Tunnel is still up after wake.")
            return False
        if network is False:
            self._set_status("Computer woke up. Waiting for the network before checking the tunnel...")
            return False
        self._reap_dead_tunnel(
            snapshot,
            reconnect=True,
            reason="Tunnel died after the computer woke from sleep.",
        )
        return False

    def _start_watch(self) -> None:
        if self._watch_source is not None:
            return
        self._dead_streak = 0
        self._last_wall = time.time()
        self._watch_source = GLib.timeout_add(WATCH_INTERVAL_MS, self._on_watch_tick)

    def _stop_watch(self) -> None:
        if self._watch_source is not None:
            GLib.source_remove(self._watch_source)
            self._watch_source = None
        self._dead_streak = 0
        self._watch_in_flight = False
        self._peer_watch_usable = False

    def _on_watch_tick(self) -> bool:
        now = time.time()
        elapsed = now - self._last_wall
        self._last_wall = now
        if wall_clock_implies_sleep(elapsed):
            self._auto_reconnects = 0
            self._cancel_slow_reconnect()
            self._on_system_resumed()
            return True
        if not self.connected or self.busy or self._reaping or self._resume_probe_active or self._watch_in_flight:
            return True
        self._watch_in_flight = True
        threading.Thread(target=self._watch_worker, daemon=True).start()
        return True

    def _watch_worker(self) -> None:
        snapshot = inspect_tunnel()
        GLib.idle_add(self._handle_watch_snapshot, snapshot)

    def _handle_watch_snapshot(self, snapshot: TunnelSnapshot) -> bool:
        self._watch_in_flight = False
        if not self.connected or self.busy or self._reaping or self._resume_probe_active:
            return False
        if self._snapshot_is_healthy(snapshot, require_peer=True):
            self._dead_streak = 0
            return False
        if network_is_available() is False:
            return False
        self._dead_streak += 1
        if self._dead_streak >= DEAD_STREAK_LIMIT:
            self._reap_dead_tunnel(
                snapshot,
                reconnect=True,
                reason="The SSH tunnel died.",
            )
        return False

    def _snapshot_is_healthy(self, snapshot: TunnelSnapshot, *, require_peer: bool) -> bool:
        healthy, self._peer_watch_usable = evaluate_tunnel_health(
            snapshot,
            require_peer=require_peer,
            peer_watch_usable=self._peer_watch_usable,
        )
        return healthy

    def _reap_dead_tunnel(self, snapshot: TunnelSnapshot, *, reconnect: bool, reason: str) -> None:
        if self.busy or self._reaping:
            return
        self._reaping = True
        self._pending_reconnect = reconnect
        server, login, password = self._tunnel_credentials()
        args, password = disconnect_args_for_reap(
            server=server,
            login=login,
            password=password,
            routing=self.routing_switch.get_active(),
        )
        remote = password is not None
        busy_text = (
            f"{reason} Cleaning leftover routes here and on the server ({snapshot.reason})..."
            if remote
            else f"{reason} Cleaning leftover routes ({snapshot.reason})..."
        )
        self._run_helper(args, password=password, busy_text=busy_text, action="reap")

    def _cancel_slow_reconnect(self) -> None:
        if self._slow_reconnect_source is not None:
            GLib.source_remove(self._slow_reconnect_source)
            self._slow_reconnect_source = None

    def _schedule_slow_reconnect(self, error: str | None = None) -> None:
        """Retry in a minute. `error` is why a connect the user asked for failed."""
        if self._exiting or self._exit_after_restore or self.connected:
            return
        self._fail_closed = True
        self._cancel_slow_reconnect()
        self._slow_reconnect_source = GLib.timeout_add(
            SLOW_RECONNECT_INTERVAL_MS, self._on_slow_reconnect_tick
        )
        if error:
            self._set_status(f"{error}\nNon-direct traffic is blocked. Next try in 1 minute.")
        else:
            self._set_status(
                f"Tunnel died after {self._auto_reconnects} reconnect attempts. "
                "Non-direct traffic is blocked. Next try in 1 minute."
            )
        self._set_busy(False)

    def _on_slow_reconnect_tick(self) -> bool:
        self._slow_reconnect_source = None
        if self._exiting or self._exit_after_restore or self.connected or self.busy:
            return False
        self._auto_connect_in_flight = True
        self._auto_reconnects += 1
        self._set_status(f"Tunnel still down. Reconnect {self._auto_reconnects}...")
        self._on_connect_clicked(None)
        return False

    def _auto_reconnect(self) -> None:
        if self._exiting or self._exit_after_restore:
            return
        delay = next_reconnect_delay_ms(self._auto_reconnects)
        if delay is not None:
            self._schedule_slow_reconnect()
            return
        self._auto_connect_in_flight = True
        self._auto_reconnects += 1
        self._set_status(
            f"Tunnel died. Reconnect {self._auto_reconnects}/{MAX_AUTO_RECONNECTS}..."
        )
        self._on_connect_clicked(None)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        available = not busy
        self.connect_button.set_sensitive(available and not self.connected)
        self.disconnect_button.set_sensitive(available and self.connected)
        if self.connected:
            if self._connected_since is None:
                self._connected_since = time.time()
            self.set_title("SSH VPN CONNECTED")
            self.connect_button.set_label(connected_button_label(time.time() - self._connected_since))
            self._start_uptime_timer()
            self.connect_button.remove_css_class("suggested-action")
            self.disconnect_button.add_css_class("destructive-action")
        else:
            self._connected_since = None
            self._stop_uptime_timer()
            self.set_title("SSH VPN")
            self.connect_button.set_label("Connect")
            self.connect_button.add_css_class("suggested-action")
            self.disconnect_button.remove_css_class("destructive-action")
        self.update_geo_button.set_sensitive(available)
        self.edit_routing_button.set_sensitive(available)
        self.diagnose_button.set_sensitive(available)
        self.routing_switch.set_sensitive(available)
        self.tls_switch.set_sensitive(available)
        self.cascade_dropdown.set_sensitive(available)
        self._update_list_controls()
        self._update_exit_restore_button()

    def _start_uptime_timer(self) -> None:
        if self._uptime_source is None:
            self._uptime_source = GLib.timeout_add_seconds(1, self._on_uptime_tick)

    def _stop_uptime_timer(self) -> None:
        source = self._uptime_source
        self._uptime_source = None
        if source is not None:
            GLib.source_remove(source)

    def _on_uptime_tick(self) -> bool:
        if not self.connected or self._connected_since is None:
            self._uptime_source = None
            return False
        self.connect_button.set_label(connected_button_label(time.time() - self._connected_since))
        return True

    def _update_list_controls(self) -> None:
        available = not self.busy
        managing = available and not self.connected
        # Choosing another entry while connected switches to it. What the
        # tunnel or its second hop is using cannot be removed.
        self.server_row.set_controls(choose=available, add=managing, remove=managing)
        self.ovpn_row.set_controls(choose=available, add=available, remove=managing)
        self.socks5_row.set_controls(choose=available, add=available, remove=managing)

    def _update_exit_restore_button(self) -> None:
        self.exit_restore_button.set_visible(self._fail_closed)
        self.exit_restore_button.set_sensitive(self._fail_closed)
        if self._fail_closed and not self.connected:
            self.set_title("SSH VPN — blocked")

    def _set_status(self, text: str) -> None:
        self.status.set_text(text)
        GLib.idle_add(self._scroll_status_to_bottom)

    def _scroll_status_to_bottom(self) -> bool:
        adjustment = self.status_scroller.get_vadjustment()
        adjustment.set_value(max(0, adjustment.get_upper() - adjustment.get_page_size()))
        return False


def run_helper(
    args: list[str],
    *,
    password: str | None,
    content: str | None = None,
    on_progress=None,
    socks5_password: str | None = None,
    previous_password: str | None = None,
) -> dict:
    command = [*_privileged_helper_command(), *args, "--routing-file", str(SYSTEM_ROUTING_FILE)]
    input_text = None
    secrets = {
        name: value
        for name, value in (("socks5_password", socks5_password), ("previous_password", previous_password))
        if value is not None
    }
    if (password or secrets) and content is not None:
        return {"ok": False, "error": "Cannot send a password and routing content together"}
    if secrets:
        command.append("--secrets-stdin")
        input_text = json.dumps({"password": password or "", **secrets})
    elif password:
        command.append("--password-stdin")
        input_text = password
    elif content is not None:
        command.append("--content-stdin")
        input_text = content

    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        return {"ok": False, "error": f"Missing executable: {exc.filename}"}

    stderr_chunks: list[str] = []
    stdout_chunks: list[str] = []

    def read_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            stderr_chunks.append(line)
            prefix = "SSH_VPN_GUI_PROGRESS "
            if on_progress is not None and line.startswith(prefix):
                on_progress(line[len(prefix) :].rstrip("\n"))

    def read_stdout() -> None:
        assert proc.stdout is not None
        stdout_chunks.append(proc.stdout.read())

    err_thread = threading.Thread(target=read_stderr, daemon=True)
    out_thread = threading.Thread(target=read_stdout, daemon=True)
    err_thread.start()
    out_thread.start()
    if proc.stdin is not None:
        if input_text is not None:
            proc.stdin.write(input_text)
        proc.stdin.close()
    try:
        proc.wait(timeout=_helper_timeout(args))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return {"ok": False, "error": "Helper timed out. Check SSH, DNS-over-TLS, or GitHub access for routing data."}
    out_thread.join(timeout=1)
    err_thread.join(timeout=1)

    output = (stdout_chunks[0] if stdout_chunks else "").strip()
    stderr = "".join(stderr_chunks).strip()
    try:
        payload = json.loads(output) if output else {}
    except json.JSONDecodeError:
        payload = {"ok": False, "error": output or stderr or "Helper returned invalid output"}
    if proc.returncode != 0:
        if not payload.get("ok", False):
            payload.setdefault("error", stderr or output or f"Helper exited with {proc.returncode}")
        else:
            payload = {"ok": False, "error": stderr or f"Helper exited with {proc.returncode}"}
    return payload


def _helper_timeout(args: list[str]) -> int:
    command = args[0] if args else ""
    if command == "update-geo":
        return 180
    if command == "diagnose":
        return 30
    if command == "status":
        return 10
    if command == "disconnect" and "--local-only" in args:
        return 20
    timeout = 90
    if command == "cascade-on" or (
        command == "connect" and ("--cascade" in args or "--ovpn-file" in args or "--tls" in args)
    ):
        timeout = CASCADE_HELPER_TIMEOUT_SECONDS
    if "--previous-server" in args:
        # Closing the old tunnel includes an SSH cleanup on the old server.
        timeout += 30
    return timeout


def _entry_row(title: str, *, password: bool = False) -> tuple[Adw.ActionRow, Gtk.Entry]:
    entry = Gtk.Entry()
    entry.set_hexpand(True)
    entry.set_valign(Gtk.Align.CENTER)
    if password:
        entry.set_visibility(False)
        entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)

    row = Adw.ActionRow(title=title)
    row.add_suffix(entry)
    row.set_activatable_widget(entry)
    return row, entry


class ChoiceRow:
    """A row with a dropdown of saved entries and + / - buttons."""

    def __init__(
        self,
        title: str,
        *,
        empty_text: str,
        add_tooltip: str,
        remove_tooltip: str,
        on_selected: Callable[[], None],
        on_add: Callable[[], None],
        on_remove: Callable[[], None],
    ) -> None:
        self._empty_text = empty_text
        self._on_selected = on_selected
        self._suppress = False
        self._current: int | None = None
        self._previous: int | None = None
        self.model = Gtk.StringList()
        self.dropdown = Gtk.DropDown.new(self.model, None)
        self.dropdown.set_factory(_full_text_factory())
        self.dropdown.set_valign(Gtk.Align.CENTER)
        self.dropdown.connect("notify::selected", self._on_selected_changed)
        self.add_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text=add_tooltip)
        self.add_button.set_valign(Gtk.Align.CENTER)
        self.add_button.connect("clicked", lambda _button: on_add())
        self.remove_button = Gtk.Button(icon_name="list-remove-symbolic", tooltip_text=remove_tooltip)
        self.remove_button.set_valign(Gtk.Align.CENTER)
        self.remove_button.connect("clicked", lambda _button: on_remove())
        # Not AdwComboRow: it ellipsizes the value and turns insensitive
        # when the list is empty, which would also disable "+".
        self.row = Adw.ActionRow(title=title)
        self.row.add_suffix(self.dropdown)
        self.row.add_suffix(self.add_button)
        self.row.add_suffix(self.remove_button)

    def set_items(self, labels: list[str], *, select: int) -> None:
        self._suppress = True
        try:
            self.model.splice(0, self.model.get_n_items(), labels)
            if labels:
                self.dropdown.set_selected(max(0, min(select, len(labels) - 1)))
        finally:
            self._suppress = False
        self._current = self._previous = self.selected()
        self.dropdown.set_visible(bool(labels))
        self.row.set_subtitle("" if labels else self._empty_text)

    def selected(self) -> int | None:
        index = self.dropdown.get_selected()
        if index == Gtk.INVALID_LIST_POSITION or index >= self.model.get_n_items():
            return None
        return int(index)

    def selected_label(self) -> str:
        index = self.selected()
        return self.model.get_string(index) if index is not None else ""

    def select(self, index: int) -> None:
        self._suppress = True
        try:
            self.dropdown.set_selected(index)
        finally:
            self._suppress = False
        self._current = self._previous = self.selected()

    def revert(self) -> None:
        """Go back to the entry chosen before the user's last choice."""
        if self._previous is not None:
            self.select(self._previous)

    def set_controls(self, *, choose: bool, add: bool, remove: bool) -> None:
        self.dropdown.set_sensitive(choose)
        self.add_button.set_sensitive(add)
        self.remove_button.set_sensitive(remove and self.model.get_n_items() > 0)

    def _on_selected_changed(self, _dropdown: Gtk.DropDown, _pspec: GLib.ParamSpec) -> None:
        # A selection set from inside this handler is announced again after
        # it returns, past the suppress flag.
        if self._suppress or self.selected() == self._current:
            return
        self._previous, self._current = self._current, self.selected()
        self._on_selected()


def _full_text_factory() -> Gtk.SignalListItemFactory:
    factory = Gtk.SignalListItemFactory()
    factory.connect("setup", _setup_full_text_item)
    factory.connect("bind", _bind_full_text_item)
    return factory


def _setup_full_text_item(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
    item.set_child(Gtk.Label(xalign=0))


def _bind_full_text_item(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
    string = item.get_item()
    item.get_child().set_text(string.get_string() if string is not None else "")


def server_label(server: dict[str, str]) -> str:
    notice = str(server.get("notice") or "").strip()
    if notice:
        return f"{server['host']} {notice}"
    return server["host"]


def _same_server(left: dict[str, str], right: dict[str, str]) -> bool:
    return left["host"] == right["host"] and left["login"] == right["login"]


def socks5_address(proxy: dict[str, str]) -> str:
    endpoint = f"{proxy['host']}:{proxy['port']}"
    return f"{proxy['user']}@{endpoint}" if proxy["user"] else endpoint


def socks5_labels(proxies: list[dict[str, str]]) -> list[str]:
    """Names, else addresses. A name given twice gets the address added."""
    bases = [proxy["name"] or socks5_address(proxy) for proxy in proxies]
    return [
        f"{base} ({socks5_address(proxy)})" if proxy["name"] and bases.count(base) > 1 else base
        for proxy, base in zip(proxies, bases)
    ]


def ovpn_labels(files: list[dict[str, str]]) -> list[str]:
    """Names, else file names. A label shared by two entries gets the folder added."""
    bases = [entry["name"] or Path(entry["path"]).name for entry in files]
    labels = []
    for entry, base in zip(files, bases):
        path = Path(entry["path"])
        if bases.count(base) == 1:
            labels.append(base)
        elif entry["name"]:
            labels.append(f"{base} ({Path(path.parent.name, path.name)})")
        else:
            labels.append(f"{base} ({path.parent.name or '/'})")
    return labels


def _clean_name(value: object) -> str:
    return " ".join(str(value or "").split())


def normalize_server(item: object) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    host = str(item.get("host") or item.get("server") or "").strip()
    if not host:
        return None
    login = str(item.get("login") or "root").strip() or "root"
    return {
        "host": host,
        "login": login,
        "password": str(item.get("password") or ""),
        "notice": str(item.get("notice") or "").strip(),
    }


def servers_from_saved(data: dict) -> tuple[list[dict[str, str]], int]:
    raw = data.get("servers")
    servers: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            server = normalize_server(item)
            if server is not None:
                servers.append(server)
    if not servers:
        legacy = normalize_server(data)
        if legacy is not None:
            servers.append(legacy)
    return servers, _saved_index(data.get("selected"), len(servers))


def ovpn_files_from_saved(data: dict) -> tuple[list[dict[str, str]], int]:
    raw = data.get("ovpn_files")
    if not isinstance(raw, list):
        # Configs from before 0.2.38 hold a single path.
        raw = [data.get("ovpn_path")]
    files: list[dict[str, str]] = []
    for item in raw:
        # Early 0.2.38 builds saved bare paths.
        entry = item if isinstance(item, dict) else {"path": item}
        path = entry.get("path")
        if isinstance(path, str) and path.strip():
            files, _index = upsert_ovpn(files, {"name": _clean_name(entry.get("name")), "path": path})
    return files, _saved_index(data.get("ovpn_selected"), len(files))


def socks5_proxies_from_saved(data: dict) -> tuple[list[dict[str, str]], int]:
    raw = data.get("socks5_proxies")
    if not isinstance(raw, list):
        # Early 0.2.38 builds kept a single proxy.
        raw = [data.get("socks5")]
    proxies: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        proxy = {key: str(item.get(key) or "") for key in SOCKS5_FIELDS}
        proxy["name"] = _clean_name(proxy["name"])
        if proxy["host"] and proxy["port"]:
            proxies, _index = upsert_socks5(proxies, proxy)
    return proxies, _saved_index(data.get("socks5_selected"), len(proxies))


def _saved_index(value: object, count: int) -> int:
    try:
        index = int(value)
    except (TypeError, ValueError):
        index = 0
    return max(0, min(index, count - 1)) if count else 0


def upsert_server(
    servers: list[dict[str, str]], host: str, login: str, password: str, notice: str = ""
) -> tuple[list[dict[str, str]], int]:
    cleaned_host = host.strip()
    cleaned_login = login.strip() or "root"
    cleaned_notice = notice.strip()
    if not cleaned_host:
        raise ValueError("Server address is required.")
    if not password:
        raise ValueError("Password is required.")
    updated = [dict(item) for item in servers]
    record = {
        "host": cleaned_host,
        "login": cleaned_login,
        "password": password,
        "notice": cleaned_notice,
    }
    for index, item in enumerate(updated):
        if item["host"] == cleaned_host and item["login"] == cleaned_login:
            updated[index] = record
            return updated, index
    updated.append(record)
    return updated, len(updated) - 1


def upsert_ovpn(
    files: list[dict[str, str]], entry: dict[str, str]
) -> tuple[list[dict[str, str]], int]:
    """The same file replaces the saved name."""
    updated = [dict(item) for item in files]
    for index, item in enumerate(updated):
        if item["path"] == entry["path"]:
            updated[index] = dict(entry)
            return updated, index
    updated.append(dict(entry))
    return updated, len(updated) - 1


def upsert_socks5(
    proxies: list[dict[str, str]], proxy: dict[str, str]
) -> tuple[list[dict[str, str]], int]:
    """The same address, port and login replace the saved name and password."""
    updated = [dict(item) for item in proxies]
    key = (proxy["host"], proxy["port"], proxy["user"])
    for index, item in enumerate(updated):
        if (item["host"], item["port"], item["user"]) == key:
            updated[index] = dict(proxy)
            return updated, index
    updated.append(dict(proxy))
    return updated, len(updated) - 1


def remove_item(items: list, index: int) -> tuple[list, int]:
    """Drop items[index]; return the list and the entry to select next."""
    updated = list(items)
    if 0 <= index < len(updated):
        del updated[index]
    if not updated:
        return [], 0
    return updated, min(index, len(updated) - 1)


def load_saved_config() -> dict:
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    servers, selected = servers_from_saved(data)
    ovpn_files, ovpn_selected = ovpn_files_from_saved(data)
    socks5_proxies, socks5_selected = socks5_proxies_from_saved(data)
    if data.get("cascade_mode") in CASCADE_KINDS:
        cascade_mode = data["cascade_mode"]
    elif "cascade" in data:
        # Before 0.2.38 the second hop was an on/off OpenVPN checkbox.
        cascade_mode = "ovpn" if data["cascade"] else "none"
    else:
        cascade_mode = "none"
    return {
        "servers": servers,
        "selected": selected,
        "routing": bool(data.get("routing", True)),
        "tls": bool(data.get("tls", False)),
        "cascade_mode": cascade_mode,
        "ovpn_files": ovpn_files,
        "ovpn_selected": ovpn_selected,
        "socks5_proxies": socks5_proxies,
        "socks5_selected": socks5_selected,
    }


def save_config(
    *,
    servers: list[dict[str, str]],
    selected: int = 0,
    routing: bool = True,
    tls: bool = False,
    cascade_mode: str = "none",
    ovpn_files: list[dict[str, str]] | None = None,
    ovpn_selected: int = 0,
    socks5_proxies: list[dict[str, str]] | None = None,
    socks5_selected: int = 0,
) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(
            {
                "servers": servers,
                "selected": selected,
                "routing": routing,
                "tls": tls,
                "cascade_mode": cascade_mode,
                "ovpn_files": ovpn_files or [],
                "ovpn_selected": ovpn_selected,
                "socks5_proxies": socks5_proxies or [],
                "socks5_selected": socks5_selected,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    CONFIG_FILE.chmod(0o600)


def _helper_command() -> list[str]:
    return [str(SYSTEM_HELPER)]


def _privileged_helper_command() -> list[str]:
    helper_command = _helper_command()
    if SUDOERS_RULE.exists() and shutil.which("sudo"):
        return ["sudo", "-n", *helper_command]
    return ["pkexec", *helper_command]


class SshVpnApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID)

    def do_activate(self) -> None:
        window = self.props.active_window
        if window is None:
            window = SshVpnWindow(self)
        window.present()


def main() -> int:
    app = SshVpnApplication()
    return app.run(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
