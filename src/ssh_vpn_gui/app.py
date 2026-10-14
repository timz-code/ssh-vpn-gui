from __future__ import annotations

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
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .paths import SUDOERS_RULE, SYSTEM_HELPER, SYSTEM_ROUTING_FILE
from .system import OVPN_HELPER_TIMEOUT_SECONDS, is_fail_closed
from .tunnel_watch import TunnelSnapshot, evaluate_tunnel_health, inspect_tunnel


APP_ID = "dev.cursor.SshVpnGui"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ssh-vpn-gui"
CONFIG_FILE = CONFIG_DIR / "config.json"
WATCH_INTERVAL_MS = 4000
WALL_SLEEP_GAP_SECONDS = 25
DEAD_STREAK_LIMIT = 2
MAX_AUTO_RECONNECTS = 8
SLOW_RECONNECT_INTERVAL_MS = 60_000


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
        self._pending_toggle: tuple[str, bool] | None = None
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

        saved_config = load_saved_config()
        self.servers: list[dict[str, str]] = list(saved_config.get("servers") or [])
        self._suppress_server_change = False
        self.server_model = Gtk.StringList()
        self.server_dropdown = Gtk.DropDown.new(self.server_model, None)
        self.server_dropdown.set_factory(_full_text_factory())
        self.server_dropdown.set_valign(Gtk.Align.CENTER)
        self.server_dropdown.connect("notify::selected", self._on_server_selected)
        self.add_server_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Add server")
        self.add_server_button.set_valign(Gtk.Align.CENTER)
        self.add_server_button.connect("clicked", self._on_add_server_clicked)
        self.remove_server_button = Gtk.Button(icon_name="list-remove-symbolic", tooltip_text="Remove server")
        self.remove_server_button.set_valign(Gtk.Align.CENTER)
        self.remove_server_button.connect("clicked", self._on_remove_server_clicked)
        # Not AdwComboRow: it ellipsizes the value and turns insensitive
        # when the list is empty, which would also disable "+".
        self.server_row = Adw.ActionRow(title="Server")
        self.server_row.add_suffix(self.server_dropdown)
        self.server_row.add_suffix(self.add_server_button)
        self.server_row.add_suffix(self.remove_server_button)
        self._refresh_server_list(select=int(saved_config.get("selected", 0) or 0))

        self.routing_switch = Gtk.CheckButton()
        self.routing_switch.set_valign(Gtk.Align.CENTER)
        self.routing_switch.set_active(bool(saved_config.get("routing", True)))
        self.routing_switch.connect("toggled", self._on_routing_toggled)
        routing_row = Adw.ActionRow(title="Routing rules", subtitle="Checked: use routing.cfg. Unchecked: send all traffic through tunnel.")
        routing_row.add_suffix(self.routing_switch)
        routing_row.set_activatable_widget(self.routing_switch)

        self.ovpn_path = saved_config.get("ovpn_path", "")
        self._ovpn_dialog = None
        self.cascade_switch = Gtk.CheckButton()
        self.cascade_switch.set_valign(Gtk.Align.CENTER)
        self.cascade_switch.set_active(bool(saved_config.get("cascade", False)))
        self.cascade_switch.connect("toggled", self._on_cascade_toggled)
        cascade_row = Adw.ActionRow(
            title="Use .ovpn file on remote server",
            subtitle="Run the chosen OpenVPN config on the server and route tunnel traffic through it (cascaded VPN).",
        )
        cascade_row.add_suffix(self.cascade_switch)
        cascade_row.set_activatable_widget(self.cascade_switch)

        self.ovpn_button = Gtk.Button(label="Choose .ovpn file")
        self.ovpn_button.set_valign(Gtk.Align.CENTER)
        self.ovpn_button.connect("clicked", self._on_choose_ovpn_clicked)
        self.ovpn_row = Adw.ActionRow(title="OpenVPN config")
        self.ovpn_row.add_suffix(self.ovpn_button)
        self._update_ovpn_subtitle()

        self.connect_button = Gtk.Button(label="Connect")
        self.connect_button.add_css_class("suggested-action")
        self.connect_button.connect("clicked", self._on_connect_clicked)

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
        group.add(self.server_row)
        group.add(routing_row)
        group.add(cascade_row)
        group.add(self.ovpn_row)

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
            server, _login, _password = self._credentials()
            args = ["routing-on", "--server", server]
            self._run_helper(args, password=None, busy_text="Applying updated routing rules...")
        else:
            self._set_status("Routing rules saved. They will be used on the next connection.")

    def _on_connect_clicked(self, _button: Gtk.Button | None) -> None:
        if _button is not None:
            self._auto_reconnects = 0
            self._auto_connect_in_flight = False
            self._cancel_slow_reconnect()
        server, login, password = self._credentials()
        if not server or not login or not password:
            self._set_status("Add a server with a login and password, then choose it.")
            return

        cascade = self.cascade_switch.get_active()
        if cascade and not self.ovpn_path:
            self._set_status("Choose a .ovpn file or turn off the cascaded VPN option.")
            return

        self._save_config()
        args = ["connect", "--server", server, "--login", login]
        if not self.routing_switch.get_active():
            args.append("--no-routing")
        if cascade:
            args.extend(["--ovpn-file", self.ovpn_path])
            busy_text = "Connecting..."
        else:
            busy_text = "Connecting..."
        self._run_helper(args, password=password, busy_text=busy_text)

    def _on_disconnect_clicked(self, _button: Gtk.Button) -> None:
        self._pending_reconnect = False
        self._auto_connect_in_flight = False
        self._cancel_slow_reconnect()
        args = ["disconnect"]
        server, login, password = self._credentials()
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
        server, login, password = self._credentials()
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
        return bool(self._exiting)

    def _on_update_geo_clicked(self, _button: Gtk.Button) -> None:
        self._run_helper(["update-geo"], password=None, busy_text="Updating routing data...")

    def _on_diagnose_clicked(self, _button: Gtk.Button) -> None:
        args = ["diagnose"]
        server, _login, _password = self._credentials()
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
        server, _login, _password = self._credentials()
        args = ["routing-on" if state else "routing-off"]
        if server:
            args.extend(["--server", server])
        self._pending_toggle = ("routing", not state)
        self._run_helper(args, password=None, busy_text="Updating routing...")

    def _on_cascade_toggled(self, _button: Gtk.CheckButton) -> None:
        self.ovpn_row.set_sensitive(not self.busy)
        if self._suppress_toggle:
            return

        enabled = self.cascade_switch.get_active()
        if enabled and not Path(self.ovpn_path).is_file():
            self._set_switch_active(self.cascade_switch, False)
            self._set_status("Choose a .ovpn file to use the cascaded VPN.")
            self._save_config()
            return

        if not self.connected:
            self._save_config()
            return

        self._apply_cascade(enabled)

    def _on_choose_ovpn_clicked(self, _button: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative(
            title="Select an OpenVPN configuration",
            transient_for=self,
            action=Gtk.FileChooserAction.OPEN,
            accept_label="_Open",
            cancel_label="_Cancel",
        )
        ovpn_filter = Gtk.FileFilter()
        ovpn_filter.set_name("OpenVPN config (*.ovpn, *.conf)")
        ovpn_filter.add_pattern("*.ovpn")
        ovpn_filter.add_pattern("*.conf")
        dialog.add_filter(ovpn_filter)
        dialog.connect("response", self._on_ovpn_dialog_response)
        self._ovpn_dialog = dialog
        dialog.show()

    def _on_ovpn_dialog_response(self, dialog: Gtk.FileChooserNative, response: int) -> None:
        if response == Gtk.ResponseType.ACCEPT:
            selected = dialog.get_file()
            if selected is not None:
                self.ovpn_path = selected.get_path() or ""
                self._update_ovpn_subtitle()
                self._save_config()
                if self.connected and self.cascade_switch.get_active():
                    self._apply_cascade(True, replacing=True)
        self._ovpn_dialog = None

    def _update_ovpn_subtitle(self) -> None:
        if self.ovpn_path:
            self.ovpn_row.set_subtitle(Path(self.ovpn_path).name)
        else:
            self.ovpn_row.set_subtitle("No file selected")
        self.ovpn_row.set_sensitive(not self.busy)

    def _save_config(self) -> None:
        selected = self._selected_index()
        save_config(
            servers=self.servers,
            selected=0 if selected is None else selected,
            routing=self.routing_switch.get_active(),
            cascade=self.cascade_switch.get_active(),
            ovpn_path=self.ovpn_path,
        )

    def _credentials(self) -> tuple[str, str, str]:
        index = self._selected_index()
        if index is None:
            return "", "", ""
        server = self.servers[index]
        return server["host"], server["login"], server["password"]

    def _selected_index(self) -> int | None:
        if not self.servers:
            return None
        index = self.server_dropdown.get_selected()
        if index == Gtk.INVALID_LIST_POSITION or index >= len(self.servers):
            return None
        return int(index)

    def _refresh_server_list(self, *, select: int) -> None:
        self._suppress_server_change = True
        try:
            self.server_model.splice(
                0,
                self.server_model.get_n_items(),
                [server_label(server) for server in self.servers],
            )
            if self.servers:
                self.server_dropdown.set_selected(max(0, min(select, len(self.servers) - 1)))
                self.server_dropdown.set_visible(True)
                self.server_row.set_subtitle("")
            else:
                self.server_dropdown.set_visible(False)
                self.server_row.set_subtitle("No servers yet")
        finally:
            self._suppress_server_change = False
        editable = not self.busy and not self.connected
        self.remove_server_button.set_sensitive(editable and bool(self.servers))

    def _on_server_selected(self, _dropdown: Gtk.DropDown, _pspec: GLib.ParamSpec) -> None:
        if self._suppress_server_change:
            return
        self._save_config()

    def _on_add_server_clicked(self, _button: Gtk.Button) -> None:
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

    def _on_remove_server_clicked(self, _button: Gtk.Button) -> None:
        index = self._selected_index()
        if index is None:
            return
        removed = server_label(self.servers[index])
        self.servers, next_index = remove_server(self.servers, index)
        self._refresh_server_list(select=next_index)
        self._save_config()
        self._set_status(f"Removed {removed}.")

    def _apply_cascade(self, enabled: bool, *, replacing: bool = False) -> None:
        server, login, password = self._credentials()
        if not server or not login or not password:
            self._set_switch_active(self.cascade_switch, not enabled)
            self._set_status("Choose a saved server.")
            return

        args = ["cascade-on" if enabled else "cascade-off", "--server", server, "--login", login]
        if enabled:
            if not Path(self.ovpn_path).is_file():
                self._set_switch_active(self.cascade_switch, False)
                self._set_status("The selected .ovpn file no longer exists.")
                self._save_config()
                return
            args.extend(["--ovpn-file", self.ovpn_path])

        self._pending_toggle = ("cascade", False if replacing else not enabled)
        if replacing:
            busy_text = "Replacing the remote OpenVPN configuration..."
        elif enabled:
            busy_text = "Starting cascade..."
        else:
            busy_text = "Stopping OpenVPN cascade on the remote server..."
        self._run_helper(args, password=password, busy_text=busy_text)

    def _set_switch_active(self, switch: Gtk.CheckButton, active: bool) -> None:
        self._suppress_toggle = True
        try:
            switch.set_active(active)
        finally:
            self._suppress_toggle = False
        self.ovpn_row.set_sensitive(not self.busy)

    def _run_helper(self, args: list[str], *, password: str | None, busy_text: str, action: str | None = None) -> None:
        self._set_busy(True)
        self._set_status(busy_text)
        command_name = action or args[0]

        def worker() -> None:
            result = run_helper(
                args,
                password=password,
                on_progress=lambda message: GLib.idle_add(self._set_status, message),
            )
            GLib.idle_add(self._handle_helper_result, command_name, result)

        threading.Thread(target=worker, daemon=True).start()

    def _handle_helper_result(self, command: str, result: dict) -> bool:
        if command == "reap":
            return self._handle_reap_result(result)
        if result.get("ok"):
            if command == "connect":
                self.connected = True
                self._fail_closed = False
                self._auto_reconnects = 0
                self._auto_connect_in_flight = False
                self._cancel_slow_reconnect()
                self._dead_streak = 0
                self._peer_watch_usable = False
                self._start_watch()
            elif command == "disconnect":
                self.connected = False
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
            if command in {"routing-on", "routing-off", "cascade-on", "cascade-off"}:
                self._save_config()
            self._pending_toggle = None
            messages = result.get("messages") or []
            self._set_status("Done." if not messages else "\n".join(messages[-5:]))
        else:
            if command == "connect":
                self.connected = False
                self._stop_watch()
                if is_fail_closed():
                    self._fail_closed = True
            elif command == "exit-restore":
                self._exiting = False
                self._exit_after_restore = False
            if self._pending_toggle is not None:
                name, previous_state = self._pending_toggle
                switch = self.routing_switch if name == "routing" else self.cascade_switch
                self._set_switch_active(switch, previous_state)
                self._pending_toggle = None
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
                self._schedule_slow_reconnect()
        return False

    def _handle_reap_result(self, result: dict) -> bool:
        self._reaping = False
        self.connected = False
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
            messages = result.get("messages") or []
            detail = "\n".join(messages[-3:]) if messages else "Leftover tunnel state was removed."
            self._set_status(detail)
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
            self._peer_watch_usable = snapshot.peer_reachable
            self._start_watch()
            self._set_status("Existing SSH tunnel is still up.")
            self._set_busy(False)
        elif is_fail_closed():
            self._fail_closed = True
            self._set_status(
                "Tunnel is down. Non-direct traffic is blocked. "
                "Connect to retry, or Exit and Restore to return to the system routes."
            )
            self._set_busy(False)
        elif snapshot.leftover:
            self._reap_dead_tunnel(
                snapshot,
                reconnect=False,
                reason="A previous tunnel is no longer healthy.",
            )
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
        server, login, password = self._credentials()
        args, password = disconnect_args_for_reap(
            server=server,
            login=login,
            password=password,
            routing=self.routing_switch.get_active(),
        )
        remote = password is not None
        busy_text = (
            f"{reason} Cleaning leftover routes and remote OpenVPN ({snapshot.reason})..."
            if remote
            else f"{reason} Cleaning leftover routes ({snapshot.reason})..."
        )
        self._run_helper(args, password=password, busy_text=busy_text, action="reap")

    def _cancel_slow_reconnect(self) -> None:
        if self._slow_reconnect_source is not None:
            GLib.source_remove(self._slow_reconnect_source)
            self._slow_reconnect_source = None

    def _schedule_slow_reconnect(self) -> None:
        if self._exiting or self._exit_after_restore or self.connected:
            return
        self._fail_closed = True
        self._cancel_slow_reconnect()
        self._slow_reconnect_source = GLib.timeout_add(
            SLOW_RECONNECT_INTERVAL_MS, self._on_slow_reconnect_tick
        )
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
            self.set_title("SSH VPN CONNECTED")
            self.connect_button.set_label("Connected")
            self.connect_button.remove_css_class("suggested-action")
            self.disconnect_button.add_css_class("destructive-action")
        else:
            self.set_title("SSH VPN")
            self.connect_button.set_label("Connect")
            self.connect_button.add_css_class("suggested-action")
            self.disconnect_button.remove_css_class("destructive-action")
        self.update_geo_button.set_sensitive(available)
        self.edit_routing_button.set_sensitive(available)
        self.diagnose_button.set_sensitive(available)
        self.routing_switch.set_sensitive(available)
        self.cascade_switch.set_sensitive(available)
        self.ovpn_row.set_sensitive(available)
        credentials_editable = available and not self.connected
        self.server_dropdown.set_sensitive(credentials_editable)
        self.add_server_button.set_sensitive(credentials_editable)
        self.remove_server_button.set_sensitive(credentials_editable and bool(self.servers))
        self._update_exit_restore_button()

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
) -> dict:
    command = [*_privileged_helper_command(), *args, "--routing-file", str(SYSTEM_ROUTING_FILE)]
    input_text = None
    if password and content is not None:
        return {"ok": False, "error": "Cannot send a password and routing content together"}
    if password:
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
    if command == "cascade-on" or (command == "connect" and "--ovpn-file" in args):
        return OVPN_HELPER_TIMEOUT_SECONDS
    return 90


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
    selected = data.get("selected", 0)
    try:
        index = int(selected)
    except (TypeError, ValueError):
        index = 0
    if servers:
        index = max(0, min(index, len(servers) - 1))
    else:
        index = 0
    return servers, index


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


def remove_server(servers: list[dict[str, str]], index: int) -> tuple[list[dict[str, str]], int]:
    updated = [dict(item) for item in servers]
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
        return {"servers": [], "selected": 0}
    if not isinstance(data, dict):
        return {"servers": [], "selected": 0}
    servers, selected = servers_from_saved(data)
    result: dict = {"servers": servers, "selected": selected}
    if "ovpn_path" in data:
        result["ovpn_path"] = str(data["ovpn_path"])
    for key in ("routing", "cascade"):
        if key in data:
            result[key] = bool(data[key])
    return result


def save_config(
    *,
    servers: list[dict[str, str]],
    selected: int = 0,
    routing: bool = True,
    cascade: bool = False,
    ovpn_path: str = "",
) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(
            {
                "servers": servers,
                "selected": selected,
                "routing": routing,
                "cascade": cascade,
                "ovpn_path": ovpn_path,
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
