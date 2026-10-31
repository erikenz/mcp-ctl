//! Optional tray icon for a running service (`mcp-ctl up`).
//!
//! Enable it with `"tray": { "enabled": true }` in `~/.config/mcp-ctl/config.json`.
//! The icon shows the health of the backend MCP servers and its menu lists each
//! server plus `Restart service` and `Shut down`.
//!
//! When every server is running the icon is the desktop's own `network-server` icon,
//! so it matches the panel; when servers need attention the item switches to the
//! `NeedsAttention` status with a tinted alert icon and details in the tooltip/menu.
//!
//! Two implementations sit behind the same interface:
//!
//! * Linux publishes a freedesktop StatusNotifierItem on the session D-Bus from its own
//!   thread, so the supervisor keeps the main thread. Any SNI host works (KDE Plasma,
//!   waybar, Quickshell shells, GNOME with the AppIndicator extension, ...).
//! * macOS and Windows use the platform's own status item, which belongs to the thread
//!   that runs the application event loop: there [`TrayHandle::run`] takes over the main
//!   thread and the supervisor runs beside it.
//!
//! Publishing the icon is best-effort everywhere: when there is no desktop session, no
//! host, or no implementation for the platform, the service keeps running without an
//! icon and logs why.

use std::sync::Arc;
use std::sync::mpsc::Sender;

use crate::config::mcp_endpoint_url;
use crate::hub::{Hub, ServerStatus};

/// Something the user asked for through the tray menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// Restart the service: this process shuts down and a fresh detached copy starts.
    Restart,
    /// Shut the service down.
    Shutdown,
}

/// Facts about the running service that the tray displays.
#[derive(Debug, Clone)]
pub struct TrayInfo {
    pub pid: u32,
    /// The profile this service belongs to, so two icons can be told apart.
    pub profile: String,
    pub hub_port: u16,
    /// Set when the auth proxy is running in front of the hub.
    pub proxy_port: Option<u16>,
    /// Public URL clients connect to, when one is known.
    pub external_url: Option<String>,
}

/// What this tray icon calls itself: the tool, plus the profile when it is not the default.
pub fn title(info: &TrayInfo) -> String {
    if info.profile == crate::config::DEFAULT_PROFILE {
        "mcp-ctl".to_string()
    } else {
        format!("mcp-ctl ({})", info.profile)
    }
}

/// Aggregate health of the backend servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Every backend server is running.
    Up,
    /// At least one backend server exited.
    Degraded,
    /// No backend server is running.
    Down,
}

/// Aggregate view of a status snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub health: Health,
    pub running: usize,
    pub total: usize,
}

/// Collapse a per-server snapshot into the aggregate the icon and menu show.
pub fn summarize(statuses: &[ServerStatus]) -> Summary {
    let total = statuses.len();
    let running = statuses.iter().filter(|s| s.running).count();
    let health = if total == 0 || running == 0 {
        Health::Down
    } else if running < total {
        Health::Degraded
    } else {
        Health::Up
    };
    Summary {
        health,
        running,
        total,
    }
}

impl Summary {
    /// Short human-readable description, e.g. "all 2 servers up".
    pub fn describe(&self) -> String {
        match (self.health, self.total) {
            (Health::Up, 1) => "server up".to_string(),
            (Health::Up, total) => format!("all {total} servers up"),
            (Health::Degraded, _) => format!("{}/{} servers up", self.running, self.total),
            (Health::Down, 1) => "server down".to_string(),
            (Health::Down, total) => format!("all {total} servers down"),
        }
    }
}

impl Health {
    /// Adwaita green/yellow/red, used for the alert icon.
    pub fn color(self) -> [u8; 3] {
        match self {
            Health::Up => [0x2E, 0xC2, 0x7E],
            Health::Degraded => [0xF5, 0xC2, 0x11],
            Health::Down => [0xC0, 0x1C, 0x28],
        }
    }
}

/// Draw the alert icon shown when backends need attention: a stack of three server
/// bars, tinted with the current health colour.
///
/// Returns RGBA pixels, which is what the macOS and Windows tray icons take.
pub fn alert_glyph_rgba(size: u32, color: [u8; 3]) -> Vec<u8> {
    let mut pixels = vec![0u8; (size * size * 4) as usize];
    let size = size as i32;
    let margin = (size / 8).max(1);
    let bar_h = (size / 6).max(2);
    let gap = (size / 12).max(1);
    let top = (size - (3 * bar_h + 2 * gap)) / 2;

    for bar in 0..3 {
        let y0 = top + bar * (bar_h + gap);
        for y in y0..(y0 + bar_h).min(size) {
            for x in margin..(size - margin) {
                let at = ((y * size + x) * 4) as usize;
                pixels[at] = color[0];
                pixels[at + 1] = color[1];
                pixels[at + 2] = color[2];
                pixels[at + 3] = 0xFF;
            }
        }
    }
    pixels
}

/// The same glyph as ARGB32 pixels in network byte order, which is what a
/// StatusNotifierItem pixmap takes.
pub fn alert_glyph_argb(size: u32, color: [u8; 3]) -> Vec<u8> {
    let mut pixels = alert_glyph_rgba(size, color);
    for pixel in pixels.chunks_mut(4) {
        pixel.rotate_right(1);
    }
    pixels
}

/// One line per server, e.g. `github — running (12 tools)`, in the order the hub
/// reports them.
pub fn server_labels(statuses: &[ServerStatus]) -> Vec<String> {
    statuses
        .iter()
        .map(|status| {
            if status.running {
                format!("{} — running ({} tools)", status.name, status.tool_count)
            } else {
                format!("{} — exited", status.name)
            }
        })
        .collect()
}

/// The tooltip: what the service is doing, and the URLs a client can use.
pub fn tooltip(info: &TrayInfo, statuses: &[ServerStatus]) -> String {
    let summary = summarize(statuses);
    let mut text = format!(
        "{} — {} · PID {}",
        title(info),
        summary.describe(),
        info.pid
    );
    text.push_str(&format!("\nHub: http://127.0.0.1:{}/mcp", info.hub_port));
    if let Some(port) = info.proxy_port {
        text.push_str(&format!("\nAuth: http://127.0.0.1:{port}/mcp"));
    }
    if let Some(url) = &info.external_url {
        text.push_str(&format!("\nRemote: {}", mcp_endpoint_url(url)));
    }
    text
}

/// Server run states that differ between two snapshots: `(name, running now)`.
pub fn transitions<'a>(
    before: &'a [ServerStatus],
    after: &'a [ServerStatus],
) -> Vec<(&'a str, bool)> {
    after
        .iter()
        .filter_map(|now| {
            let was = before.iter().find(|b| b.name == now.name)?;
            (was.running != now.running).then_some((now.name.as_str(), now.running))
        })
        .collect()
}

/// Start the tray icon for a running hub.
///
/// Returns `None` when the icon cannot be published at all (no implementation for the
/// platform, no desktop session, no host for it). That is never fatal: the caller keeps
/// serving without a tray.
///
/// On macOS and Windows the icon is only created later, inside [`TrayHandle::run`],
/// because it has to be built on the thread that runs the event loop.
pub fn start(hub: Arc<Hub>, info: TrayInfo, actions: Sender<TrayAction>) -> Option<TrayHandle> {
    platform::start(hub, info, actions)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{
        Health, Hub, TrayAction, TrayInfo, alert_glyph_argb, server_labels, summarize, title,
        tooltip,
    };
    use crate::config::mcp_endpoint_url;
    use ksni::blocking::TrayMethods;
    use ksni::menu::{StandardItem, SubMenu};
    use ksni::{Category, Icon, MenuItem, OfflineReason, Status, ToolTip, Tray};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::Sender;
    use std::time::Duration;

    /// The desktop's own server icon, used while every backend runs.
    const ICON_NAME: &str = "network-server";

    /// Sizes of the alert icon offered to the host; it picks the closest one.
    const ICON_SIZES: [u32; 3] = [16, 22, 32];

    /// How often the tray re-reads server state.
    const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

    /// Granularity of the wait between refreshes, so shutdown stays responsive.
    const STOP_POLL: Duration = Duration::from_millis(100);

    /// Handle to the running tray icon.
    pub struct TrayHandle {
        stop: Arc<AtomicBool>,
    }

    impl TrayHandle {
        /// Ask the tray to remove the icon and stop refreshing.
        ///
        /// Never blocks: the icon lives on the session D-Bus, so a panel that stops
        /// answering must not be able to stall the service's shutdown.
        pub fn shutdown(&self) {
            self.stop.store(true, Ordering::SeqCst);
        }

        /// The icon is published from its own thread here, so the supervisor keeps the
        /// main thread.
        pub fn needs_main_thread(&self) -> bool {
            false
        }

        /// Nothing to drive: the icon refreshes itself from a thread of its own.
        pub fn run(self, _running: Arc<AtomicBool>) {}
    }

    pub fn start(hub: Arc<Hub>, info: TrayInfo, actions: Sender<TrayAction>) -> Option<TrayHandle> {
        let last = hub.statuses();
        let icon = TrayIcon {
            hub,
            info,
            actions,
            last,
        };
        // A service may start before the panel/shell is up, so treat a missing
        // watcher as "try again later" instead of giving up at startup.
        let handle = match icon.assume_sni_available(true).spawn() {
            Ok(handle) => handle,
            Err(e) => {
                errln!("Warning: tray icon unavailable ({e}); continuing without one.");
                return None;
            }
        };

        // Refresh from a dedicated thread: publishing the icon talks to the panel over
        // D-Bus, and a slow or wedged panel must never stall the hub's control loop.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let spawned = std::thread::Builder::new()
            .name("tray-refresh".to_string())
            .spawn(move || {
                while !stop_thread.load(Ordering::SeqCst) {
                    if handle.update(|tray| tray.refresh()).is_none() {
                        break; // The tray service is gone, nothing left to notify.
                    }
                    let mut waited = Duration::ZERO;
                    while waited < REFRESH_INTERVAL && !stop_thread.load(Ordering::SeqCst) {
                        std::thread::sleep(STOP_POLL);
                        waited += STOP_POLL;
                    }
                }
                // Best effort: when the process exits, the D-Bus name is dropped and the
                // host removes the icon on its own.
                let _ = handle.shutdown();
            });
        if let Err(error) = spawned {
            errln!(
                "Warning: the tray refresh thread could not start ({error}); continuing without a tray icon."
            );
            return None;
        }

        outln!("Tray icon enabled.");
        Some(TrayHandle { stop })
    }

    struct TrayIcon {
        hub: Arc<Hub>,
        info: TrayInfo,
        actions: Sender<TrayAction>,
        /// Previous snapshot, used to log backend servers dying exactly once.
        last: Vec<super::ServerStatus>,
    }

    impl TrayIcon {
        fn summary(&self) -> super::Summary {
            summarize(&self.hub.statuses())
        }

        /// Compare the current snapshot with the previous one and log what changed.
        /// A backend dying is otherwise invisible in the daemon log, since the hub
        /// keeps serving the remaining servers.
        fn refresh(&mut self) {
            let statuses = self.hub.statuses();
            for (name, running) in super::transitions(&self.last, &statuses) {
                if running {
                    outln!("MCP server '{name}' is running again.");
                } else {
                    errln!("Warning: MCP server '{name}' exited; its tools are no longer served.");
                }
            }
            self.last = statuses;
        }

        /// Disabled menu entry, used for the read-only status lines.
        fn info_item(label: String) -> MenuItem<Self> {
            StandardItem {
                label,
                enabled: false,
                ..Default::default()
            }
            .into()
        }
    }

    impl Tray for TrayIcon {
        /// The menu is the whole interface, so a left click opens it.
        const MENU_ON_ACTIVATE: bool = true;

        fn id(&self) -> String {
            "mcp-ctl".into()
        }

        fn title(&self) -> String {
            title(&self.info)
        }

        fn category(&self) -> Category {
            Category::ApplicationStatus
        }

        fn status(&self) -> Status {
            match self.summary().health {
                Health::Up => Status::Active,
                Health::Degraded | Health::Down => Status::NeedsAttention,
            }
        }

        /// The desktop's server icon. Hosts that render a pixmap prefer one when it is
        /// present, so the themed icon is only used while no pixmap is offered.
        fn icon_name(&self) -> String {
            ICON_NAME.into()
        }

        /// While the item is in `NeedsAttention`, hosts that support it show this tinted
        /// alert icon instead of the plain server icon.
        fn attention_icon_pixmap(&self) -> Vec<Icon> {
            let color = self.summary().health.color();
            ICON_SIZES
                .iter()
                .map(|&size| Icon {
                    width: size as i32,
                    height: size as i32,
                    data: alert_glyph_argb(size, color),
                })
                .collect()
        }

        fn tool_tip(&self) -> ToolTip {
            ToolTip {
                title: title(&self.info),
                description: tooltip(&self.info, &self.hub.statuses()),
                ..Default::default()
            }
        }

        fn menu(&self) -> Vec<MenuItem<Self>> {
            let statuses = self.hub.statuses();
            let summary = summarize(&statuses);

            let mut items = vec![
                Self::info_item(format!("{} — {}", title(&self.info), summary.describe())),
                Self::info_item(format!("hub: http://127.0.0.1:{}/mcp", self.info.hub_port)),
            ];
            if let Some(port) = self.info.proxy_port {
                items.push(Self::info_item(format!(
                    "auth: http://127.0.0.1:{port}/mcp"
                )));
            }
            if let Some(url) = &self.info.external_url {
                items.push(Self::info_item(format!(
                    "remote: {}",
                    mcp_endpoint_url(url)
                )));
            }

            let servers = server_labels(&statuses)
                .into_iter()
                .map(Self::info_item)
                .collect();
            items.push(
                SubMenu {
                    label: format!("Servers ({})", summary.describe()),
                    submenu: servers,
                    ..Default::default()
                }
                .into(),
            );

            items.push(MenuItem::Separator);
            items.push(
                StandardItem {
                    label: "Restart service".into(),
                    activate: Box::new(|tray: &mut Self| {
                        let _ = tray.actions.send(TrayAction::Restart);
                    }),
                    ..Default::default()
                }
                .into(),
            );
            items.push(
                StandardItem {
                    label: "Shut down".into(),
                    activate: Box::new(|tray: &mut Self| {
                        let _ = tray.actions.send(TrayAction::Shutdown);
                    }),
                    ..Default::default()
                }
                .into(),
            );
            items
        }

        fn watcher_online(&self) {
            outln!("tray: status notifier host is back; icon restored.");
        }

        fn watcher_offline(&self, reason: OfflineReason) -> bool {
            errln!(
                "Warning: tray icon is offline ({reason:?}). Enable a status notifier host \
                 (a panel tray) or set \"tray\": {{\"enabled\": false}}."
            );
            // Keep waiting: the host may come back (e.g. panel restart).
            true
        }
    }
}

/// macOS and Windows: the platform's own status item.
///
/// Both platforms hand the icon to the thread that runs the application event loop
/// (AppKit on macOS, the message pump on Windows), so [`TrayHandle::run`] takes over the
/// main thread and the supervisor runs beside it. The icon, its menu and its tooltip are
/// refreshed from inside that loop.
#[cfg(any(target_os = "macos", windows))]
mod platform {
    use super::{
        Health, Hub, ServerStatus, TrayAction, TrayInfo, alert_glyph_rgba, server_labels,
        summarize, tooltip, transitions,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::Sender;
    use std::time::{Duration, Instant};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
    use winit::application::ApplicationHandler;
    use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
    use winit::window::WindowId;

    /// How often the icon, its menu and the tooltip are refreshed.
    const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

    /// Size of the icon handed to the platform, which scales it for the panel.
    const ICON_SIZE: u32 = 32;

    /// The tray icon, owned by the thread that runs the event loop.
    pub struct TrayHandle {
        hub: Arc<Hub>,
        info: TrayInfo,
        actions: Sender<TrayAction>,
        /// Set by [`TrayHandle::run`], once the icon exists.
        icon: Option<TrayIcon>,
        status_items: Vec<MenuItem>,
        restart: Option<MenuItem>,
        shutdown: Option<MenuItem>,
        health: Health,
        last: Vec<ServerStatus>,
    }

    impl TrayHandle {
        /// Both platforms put the icon on the thread that owns the event loop.
        pub fn needs_main_thread(&self) -> bool {
            true
        }

        /// Nothing to remove: the icon goes away with the event loop.
        pub fn shutdown(&self) {}

        /// Build the icon and run the platform event loop until `running` goes false.
        ///
        /// Never returns while the service runs. A system that refuses to give us an
        /// event loop or an icon only costs the icon.
        pub fn run(mut self, running: Arc<AtomicBool>) {
            let event_loop = match EventLoop::new() {
                Ok(event_loop) => event_loop,
                Err(error) => {
                    errln!(
                        "Warning: the tray icon needs an event loop, which this system \
                         refused ({error}); continuing without one."
                    );
                    return;
                }
            };
            if let Err(error) = self.build() {
                errln!("Warning: tray icon unavailable ({error}); continuing without one.");
                return;
            }
            outln!("Tray icon enabled.");

            let mut app = App {
                tray: self,
                running,
            };
            if let Err(error) = event_loop.run_app(&mut app) {
                errln!("warning: the tray event loop stopped: {error}");
            }
        }

        fn build(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            let statuses = self.hub.statuses();
            let menu = Menu::new();
            for label in server_labels(&statuses) {
                let item = MenuItem::new(label, false, None);
                menu.append(&item)?;
                self.status_items.push(item);
            }
            menu.append(&PredefinedMenuItem::separator())?;
            let restart = MenuItem::new("Restart service", true, None);
            let shutdown = MenuItem::new("Shut down", true, None);
            menu.append(&restart)?;
            menu.append(&shutdown)?;

            let icon = TrayIconBuilder::new()
                .with_tooltip(tooltip(&self.info, &statuses))
                .with_menu(Box::new(menu))
                .with_icon(health_icon(Health::Up)?)
                .build()?;

            self.icon = Some(icon);
            self.restart = Some(restart);
            self.shutdown = Some(shutdown);
            self.health = summarize(&statuses).health;
            self.last = statuses;
            Ok(())
        }

        /// Refresh the menu labels, the tooltip and the icon, and report what changed.
        fn refresh(&mut self) {
            let statuses = self.hub.statuses();
            for (name, running) in transitions(&self.last, &statuses) {
                if running {
                    outln!("MCP server '{name}' is running again.");
                } else {
                    errln!("Warning: MCP server '{name}' exited; its tools are no longer served.");
                }
            }
            self.last = statuses.clone();

            for (item, label) in self.status_items.iter().zip(server_labels(&statuses)) {
                if item.text() != label {
                    item.set_text(label);
                }
            }

            if let Some(icon) = &self.icon {
                let _ = icon.set_tooltip(Some(tooltip(&self.info, &statuses)));
            }
            let health = summarize(&statuses).health;
            if health != self.health {
                self.health = health;
                if let Some(icon) = &self.icon
                    && let Ok(replacement) = health_icon(health)
                {
                    let _ = icon.set_icon(Some(replacement));
                }
            }
        }
    }

    /// The alert glyph tinted with the colour of a health state.
    fn health_icon(health: Health) -> Result<Icon, tray_icon::BadIcon> {
        Icon::from_rgba(
            alert_glyph_rgba(ICON_SIZE, health.color()),
            ICON_SIZE,
            ICON_SIZE,
        )
    }

    /// The event loop: it owns the tray and polls for menu clicks.
    struct App {
        tray: TrayHandle,
        running: Arc<AtomicBool>,
    }

    impl ApplicationHandler for App {
        fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

        fn window_event(
            &mut self,
            _event_loop: &ActiveEventLoop,
            _window_id: WindowId,
            _event: winit::event::WindowEvent,
        ) {
        }

        fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
            if !self.running.load(Ordering::SeqCst) {
                event_loop.exit();
                return;
            }

            while let Ok(event) = MenuEvent::receiver().try_recv() {
                let restart = self.tray.restart.as_ref().map(MenuItem::id) == Some(&event.id);
                let shutdown = self.tray.shutdown.as_ref().map(MenuItem::id) == Some(&event.id);
                if restart {
                    let _ = self.tray.actions.send(TrayAction::Restart);
                } else if shutdown {
                    let _ = self.tray.actions.send(TrayAction::Shutdown);
                }
            }

            self.tray.refresh();
            // Wake up for the next refresh even when nothing else happens.
            event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + REFRESH_INTERVAL));
        }
    }

    pub fn start(hub: Arc<Hub>, info: TrayInfo, actions: Sender<TrayAction>) -> Option<TrayHandle> {
        Some(TrayHandle {
            hub,
            info,
            actions,
            icon: None,
            status_items: Vec::new(),
            restart: None,
            shutdown: None,
            health: Health::Up,
            last: Vec::new(),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::{Hub, TrayAction, TrayInfo};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::Sender;

    /// Placeholder for platforms without an implementation yet.
    pub struct TrayHandle;

    impl TrayHandle {
        pub fn shutdown(&self) {}

        pub fn needs_main_thread(&self) -> bool {
            false
        }

        pub fn run(self, _running: Arc<AtomicBool>) {}
    }

    pub fn start(
        _hub: Arc<Hub>,
        _info: TrayInfo,
        _actions: Sender<TrayAction>,
    ) -> Option<TrayHandle> {
        errln!(
            "Warning: the tray icon is not implemented on this platform yet; \
             ignoring \"tray\": {{\"enabled\": true}}."
        );
        None
    }
}

pub use platform::TrayHandle;

#[cfg(test)]
mod tests {
    use super::*;

    fn status(name: &str, running: bool) -> ServerStatus {
        ServerStatus {
            name: name.to_string(),
            tool_count: 1,
            running,
        }
    }

    #[test]
    fn summarize_reports_all_up() {
        let summary = summarize(&[status("a", true), status("b", true)]);
        assert_eq!(summary.health, Health::Up);
        assert_eq!(summary.running, 2);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.describe(), "all 2 servers up");
    }

    #[test]
    fn summarize_reports_degraded() {
        let summary = summarize(&[status("a", true), status("b", false)]);
        assert_eq!(summary.health, Health::Degraded);
        assert_eq!(summary.describe(), "1/2 servers up");
    }

    #[test]
    fn summarize_reports_down() {
        let summary = summarize(&[status("a", false)]);
        assert_eq!(summary.health, Health::Down);
        assert_eq!(summary.describe(), "server down");
    }

    #[test]
    fn summarize_handles_no_servers() {
        let summary = summarize(&[]);
        assert_eq!(summary.health, Health::Down);
        assert_eq!(summary.total, 0);
    }

    #[test]
    fn transitions_reports_servers_going_down_and_up() {
        let before = [status("a", true), status("b", true), status("c", false)];
        let after = [status("a", true), status("b", false), status("c", true)];
        assert_eq!(
            transitions(&before, &after),
            vec![("b", false), ("c", true)]
        );
        assert!(transitions(&before, &before).is_empty());
    }

    #[test]
    fn alert_glyph_is_argb_pixels() {
        let pixels = alert_glyph_argb(16, [0x2E, 0xC2, 0x7E]);
        assert_eq!(pixels.len(), 16 * 16 * 4);

        // Corners stay transparent, the middle bar carries the health colour.
        assert_eq!(&pixels[0..4], &[0, 0, 0, 0]);
        let middle = ((8 * 16 + 8) * 4) as usize;
        assert_eq!(&pixels[middle..middle + 4], &[0xFF, 0x2E, 0xC2, 0x7E]);
    }

    #[test]
    fn the_glyph_is_the_same_picture_in_both_pixel_orders() {
        let rgba = alert_glyph_rgba(16, [0x2E, 0xC2, 0x7E]);
        let argb = alert_glyph_argb(16, [0x2E, 0xC2, 0x7E]);
        assert_eq!(rgba.len(), argb.len());
        for pixel in 0..16 * 16 {
            let at = pixel * 4;
            assert_eq!(
                &argb[at..at + 4],
                &[rgba[at + 3], rgba[at], rgba[at + 1], rgba[at + 2]]
            );
        }
    }

    #[test]
    fn server_labels_describe_every_server() {
        let labels = server_labels(&[status("github", true), status("filesystem", false)]);
        assert_eq!(
            labels,
            vec!["github — running (1 tools)", "filesystem — exited"]
        );
    }

    #[test]
    fn the_tooltip_names_the_urls_a_client_can_use() {
        let info = TrayInfo {
            pid: 42,
            profile: "default".to_string(),
            hub_port: 37373,
            proxy_port: Some(8080),
            external_url: Some("https://laptop.example.ts.net".to_string()),
        };
        let text = tooltip(&info, &[status("github", true)]);
        assert!(text.contains("server up"), "{text}");
        assert!(text.contains("PID 42"), "{text}");
        assert!(text.contains("http://127.0.0.1:37373/mcp"), "{text}");
        assert!(text.contains("http://127.0.0.1:8080/mcp"), "{text}");
        assert!(text.contains("https://laptop.example.ts.net/mcp"), "{text}");
        // The default profile is just `mcp-ctl`; a named one says which it is.
        assert!(text.starts_with("mcp-ctl —"), "{text}");
        let work = TrayInfo {
            profile: "work".to_string(),
            ..info
        };
        assert!(
            tooltip(&work, &[]).starts_with("mcp-ctl (work) —"),
            "{}",
            tooltip(&work, &[])
        );
    }
}
