//! Portal-authorized keyboard insertion for Wayland desktops without wtype's
//! virtual-keyboard protocol. The listener's output worker owns this session.
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ashpd::desktop::remote_desktop::{DeviceType, RemoteDesktop};
use ashpd::desktop::{PersistMode, Session};
use color_eyre::eyre::{Result, WrapErr, eyre};
use reis::{PendingRequestResult, ei};
use xkbcommon::xkb;

const KEY_CTRL: u32 = 29;
const KEY_SHIFT: u32 = 42;
const KEY_V: u32 = 47;
const PORTAL_TIMEOUT: Duration = Duration::from_secs(60);
const DEVICE_TIMEOUT: Duration = Duration::from_secs(3);
// ei_callback is required by the EIS handshake even when no callback is used.
const KEYBOARD_INTERFACES: &[&str] = &[
    "ei_callback",
    "ei_connection",
    "ei_seat",
    "ei_device",
    "ei_keyboard",
    "ei_pingpong",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PasteKeys {
    control: u32,
    shift: u32,
    v: u32,
}

const DEFAULT_PASTE_KEYS: PasteKeys = PasteKeys {
    control: KEY_CTRL,
    shift: KEY_SHIFT,
    v: KEY_V,
};

pub(crate) fn uses_portal() -> bool {
    uses_portal_for(&std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default())
}

fn uses_portal_for(desktop: &str) -> bool {
    desktop
        .split(':')
        .any(|desktop| desktop.eq_ignore_ascii_case("KDE") || desktop.eq_ignore_ascii_case("GNOME"))
}

pub(crate) struct PortalKeyboard {
    // Keeping both proxies alive also keeps the portal's authorization alive.
    _proxy: RemoteDesktop<'static>,
    session: Session<'static, RemoteDesktop<'static>>,
    context: ei::Context,
    seats: HashMap<ei::Seat, u64>,
    devices: HashMap<ei::Device, ei::Keyboard>,
    keymaps: HashMap<ei::Keyboard, (xkb::Keymap, u32)>,
    active: Option<ei::Device>,
    last_serial: u32,
    sequence: u32,
}

impl PortalKeyboard {
    pub(crate) fn connect(stop: &AtomicBool) -> Result<Self> {
        let token_path = token_path()?;
        let token = read_token(&token_path);
        let deadline = Instant::now() + PORTAL_TIMEOUT;
        let (proxy, session) = authorize_until(stop, deadline, async {
            let proxy = RemoteDesktop::new().await?;
            let session = proxy.create_session().await?;
            Ok((proxy, session))
        })?;
        let permission = authorize_until(stop, deadline, async {
            proxy
                .select_devices(
                    &session,
                    DeviceType::Keyboard.into(),
                    token.as_deref(),
                    PersistMode::ExplicitlyRevoked,
                )
                .await?
                .response()?;
            let response = proxy.start(&session, None).await?.response()?;
            if !response.devices().contains(DeviceType::Keyboard) {
                return Err(eyre!("desktop portal did not grant keyboard control"));
            }
            let replacement = response.restore_token().map(str::to_owned);
            let fd = proxy.connect_to_eis(&session).await?;
            Ok((fd, replacement))
        });
        let (fd, replacement) = match permission {
            Ok(result) => result,
            Err(error) => {
                close_session(&session);
                return Err(error).wrap_err(
                    "could not authorize the Wayland paste shortcut through the desktop portal",
                );
            }
        };
        if let Some(token) = replacement
            && let Err(error) = write_token(&token_path, &token)
        {
            tracing::warn!(%error, "could not save desktop keyboard permission token");
        }
        let context = match ei::Context::new(UnixStream::from(fd)) {
            Ok(context) => context,
            Err(error) => {
                close_session(&session);
                return Err(error.into());
            }
        };
        let mut keyboard = Self {
            _proxy: proxy,
            session,
            context,
            seats: HashMap::new(),
            devices: HashMap::new(),
            keymaps: HashMap::new(),
            active: None,
            last_serial: 0,
            sequence: 0,
        };
        keyboard.handshake(stop)?;
        Ok(keyboard)
    }

    fn handshake(&mut self, stop: &AtomicBool) -> Result<()> {
        let deadline = Instant::now() + DEVICE_TIMEOUT;
        let mut connected = false;
        while !connected {
            self.poll(stop, deadline)?;
            while let Some(event) = self.context.pending_event() {
                match event {
                    PendingRequestResult::Request(ei::Event::Handshake(handshake, event)) => {
                        match event {
                            ei::handshake::Event::HandshakeVersion { .. } => {
                                handshake.handshake_version(1);
                                handshake.name("HEX dictation paste");
                                handshake.context_type(ei::handshake::ContextType::Sender);
                                for interface in KEYBOARD_INTERFACES {
                                    handshake.interface_version(interface, 1);
                                }
                                handshake.finish();
                                self.context.flush()?;
                            }
                            ei::handshake::Event::Connection { serial, .. } => {
                                self.last_serial = serial;
                                connected = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    PendingRequestResult::Request(_) => {}
                    error => return Err(eyre!("invalid EIS handshake: {error:?}")),
                }
            }
        }
        while self.active.is_none() {
            self.process_events()?;
            if self.active.is_none() {
                self.poll(stop, deadline)?;
            }
        }
        Ok(())
    }

    fn poll(&self, stop: &AtomicBool, deadline: Instant) -> Result<()> {
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(eyre!("paste cancelled while stopping the listener"));
            }
            if Instant::now() >= deadline {
                return Err(eyre!("desktop did not provide an active keyboard device"));
            }
            let mut fd = libc::pollfd {
                fd: self.context.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut fd, 1, 50) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready > 0 {
                self.context.read()?;
                return Ok(());
            }
        }
    }

    fn process_events(&mut self) -> Result<()> {
        while let Some(result) = self.context.pending_event() {
            let event = match result {
                PendingRequestResult::Request(event) => event,
                error => return Err(eyre!("invalid EIS keyboard event: {error:?}")),
            };
            match event {
                ei::Event::Connection(_, ei::connection::Event::Disconnected { .. }) => {
                    return Err(eyre!("desktop revoked keyboard control"));
                }
                ei::Event::Connection(_, ei::connection::Event::Ping { ping }) => ping.done(0),
                ei::Event::Connection(_, ei::connection::Event::Seat { seat }) => {
                    self.seats.insert(seat, 0);
                }
                ei::Event::Seat(seat, ei::seat::Event::Capability { mask, interface })
                    if interface == "ei_keyboard" =>
                {
                    self.seats.insert(seat, mask);
                }
                ei::Event::Seat(seat, ei::seat::Event::Done) => {
                    if let Some(mask) = self.seats.get(&seat).copied().filter(|mask| *mask != 0) {
                        seat.bind(mask);
                    }
                }
                ei::Event::Seat(seat, ei::seat::Event::Destroyed { serial }) => {
                    self.last_serial = serial;
                    self.seats.remove(&seat);
                    self.active = None;
                    self.devices.clear();
                    self.keymaps.clear();
                }
                ei::Event::Device(device, ei::device::Event::Interface { object })
                    if object.interface() == "ei_keyboard" =>
                {
                    if let Some(keyboard) = object.downcast() {
                        self.devices.insert(device, keyboard);
                    }
                }
                ei::Event::Device(device, ei::device::Event::Resumed { serial }) => {
                    self.last_serial = serial;
                    if self.devices.contains_key(&device) {
                        self.active = Some(device);
                    }
                }
                ei::Event::Device(device, ei::device::Event::Paused { serial }) => {
                    self.last_serial = serial;
                    if self.active.as_ref() == Some(&device) {
                        self.active = None;
                    }
                }
                ei::Event::Device(device, ei::device::Event::Destroyed { serial }) => {
                    self.last_serial = serial;
                    if self.active.as_ref() == Some(&device) {
                        self.active = None;
                    }
                    if let Some(keyboard) = self.devices.remove(&device) {
                        self.keymaps.remove(&keyboard);
                    }
                }
                ei::Event::Keyboard(keyboard, ei::keyboard::Event::Keymap { keymap, size, .. }) => {
                    self.keymaps
                        .insert(keyboard, (parse_keymap(keymap, size)?, 0));
                }
                ei::Event::Keyboard(
                    keyboard,
                    ei::keyboard::Event::Modifiers { serial, group, .. },
                ) => {
                    self.last_serial = serial;
                    if let Some((_, current_group)) = self.keymaps.get_mut(&keyboard) {
                        *current_group = group;
                    }
                }
                _ => {}
            }
        }
        self.context.flush()?;
        Ok(())
    }

    pub(crate) fn paste_shortcut(&mut self, stop: &AtomicBool, shift: bool) -> Result<()> {
        self.context.read()?;
        self.process_events()?;
        let deadline = Instant::now() + DEVICE_TIMEOUT;
        while self.active.is_none() {
            self.poll(stop, deadline)?;
            self.process_events()?;
        }
        if stop.load(Ordering::Acquire) {
            return Err(eyre!("paste cancelled while stopping the listener"));
        }
        let device = self
            .active
            .as_ref()
            .ok_or_else(|| eyre!("keyboard device unavailable"))?;
        let keyboard = self
            .devices
            .get(device)
            .ok_or_else(|| eyre!("keyboard interface unavailable"))?;
        let keys = match self.keymaps.get(keyboard) {
            Some((keymap, group)) => resolve_paste_keys(keymap, *group, shift)?,
            // The protocol permits omitting a keymap; in that case the server
            // defines its keycodes and the beta's physical US keys are the default.
            None => DEFAULT_PASTE_KEYS,
        };
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.sequence = self.sequence.wrapping_add(1);
        device.start_emulating(self.last_serial, self.sequence);
        let timestamp = time.tv_sec as u64 * 1_000_000 + time.tv_nsec as u64 / 1_000;
        for (index, (key, state)) in paste_sequence(shift, keys).into_iter().enumerate() {
            keyboard.key(key, state);
            device.frame(self.last_serial, timestamp + index as u64);
        }
        device.stop_emulating(self.last_serial);
        self.context
            .flush()
            .wrap_err("could not send the paste shortcut through the desktop portal")?;
        Ok(())
    }
}

impl Drop for PortalKeyboard {
    fn drop(&mut self) {
        close_session(&self.session);
    }
}

fn authorize_until<T>(
    stop: &AtomicBool,
    deadline: Instant,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    pollster::block_on(futures_lite::future::race(future, async {
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(eyre!(
                    "keyboard portal authorization cancelled during shutdown"
                ));
            }
            if Instant::now() >= deadline {
                return Err(eyre!("timed out waiting for desktop keyboard permission"));
            }
            async_io::Timer::after(Duration::from_millis(50)).await;
        }
    }))
}

fn close_session(session: &Session<'_, RemoteDesktop<'_>>) {
    let _ = pollster::block_on(futures_lite::future::race(session.close(), async {
        async_io::Timer::after(Duration::from_millis(500)).await;
        Ok(())
    }));
}

fn paste_sequence(shift: bool, keys: PasteKeys) -> Vec<(u32, ei::keyboard::KeyState)> {
    use ei::keyboard::KeyState::{Press, Released};
    let mut sequence = vec![(keys.control, Press)];
    if shift {
        sequence.push((keys.shift, Press));
    }
    sequence.extend([(keys.v, Press), (keys.v, Released)]);
    if shift {
        sequence.push((keys.shift, Released));
    }
    sequence.push((keys.control, Released));
    sequence
}

fn parse_keymap(fd: std::os::fd::OwnedFd, size: u32) -> Result<xkb::Keymap> {
    if !(2..=1_048_576).contains(&size) {
        return Err(eyre!("invalid desktop keyboard keymap length"));
    }
    let file = std::fs::File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() < u64::from(size) {
        return Err(eyre!(
            "desktop keyboard keymap is not a bounded regular file"
        ));
    }
    let mut bytes = vec![0; size as usize];
    // The fd passed over EIS shares its open-file offset with the sender. KDE
    // can leave that offset at EOF; read from the start without changing it.
    file.read_exact_at(&mut bytes, 0)?;
    parse_keymap_bytes(bytes)
}

fn parse_keymap_bytes(mut bytes: Vec<u8>) -> Result<xkb::Keymap> {
    // EIS advertises the keymap's byte length; KDE can provide text without a
    // trailing NUL. xkbcommon's string API takes care of termination itself.
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.contains(&0) {
        return Err(eyre!("desktop keyboard keymap contains an embedded NUL"));
    }
    xkb::Keymap::new_from_string(
        &xkb::Context::new(xkb::CONTEXT_NO_FLAGS),
        String::from_utf8(bytes)?,
        xkb::KEYMAP_FORMAT_TEXT_V1,
        xkb::KEYMAP_COMPILE_NO_FLAGS,
    )
    .ok_or_else(|| eyre!("could not load desktop keyboard keymap"))
}

fn key_for_symbol(keymap: &xkb::Keymap, group: u32, symbol: xkb::Keysym) -> Option<u32> {
    (keymap.min_keycode().raw()..=keymap.max_keycode().raw()).find_map(|code| {
        keymap
            .key_get_syms_by_level(xkb::Keycode::new(code), group, 0)
            .contains(&symbol)
            .then_some(code.checked_sub(8))
            .flatten()
    })
}

fn key_for_modifier(
    keymap: &xkb::Keymap,
    group: u32,
    symbols: &[xkb::Keysym],
    name: &str,
) -> Option<u32> {
    (keymap.min_keycode().raw()..=keymap.max_keycode().raw()).find_map(|code| {
        let key = xkb::Keycode::new(code);
        if !keymap
            .key_get_syms_by_level(key, group, 0)
            .iter()
            .any(|symbol| symbols.contains(symbol))
        {
            return None;
        }
        let mut state = xkb::State::new(keymap);
        state.update_mask(0, 0, 0, 0, 0, group);
        state.update_key(key, xkb::KeyDirection::Down);
        state
            .mod_name_is_active(name, xkb::STATE_MODS_EFFECTIVE)
            .then_some(code.checked_sub(8))
            .flatten()
    })
}

fn resolve_paste_keys(keymap: &xkb::Keymap, group: u32, shift: bool) -> Result<PasteKeys> {
    let control = key_for_modifier(
        keymap,
        group,
        &[xkb::Keysym::Control_L, xkb::Keysym::Control_R],
        xkb::MOD_NAME_CTRL,
    )
    .ok_or_else(|| eyre!("desktop keyboard layout has no Control key for paste"))?;
    let shift = if shift {
        key_for_modifier(
            keymap,
            group,
            &[xkb::Keysym::Shift_L, xkb::Keysym::Shift_R],
            xkb::MOD_NAME_SHIFT,
        )
        .ok_or_else(|| eyre!("desktop keyboard layout has no Shift key for paste"))?
    } else {
        KEY_SHIFT
    };
    let v = key_for_symbol(keymap, group, xkb::Keysym::v)
        .or_else(|| {
            // Non-Latin groups often have no Latin shortcut letter. Prefer the
            // active group's position (e.g. Dvorak), then a Latin group in the
            // same compositor keymap rather than blindly sending US evdev V.
            (0..keymap.num_layouts())
                .filter(|candidate| *candidate != group)
                .find_map(|candidate| key_for_symbol(keymap, candidate, xkb::Keysym::v))
        })
        .ok_or_else(|| eyre!("desktop keyboard layout has no V key for paste"))?;
    Ok(PasteKeys { control, shift, v })
}

fn token_path() -> Result<PathBuf> {
    let name = if std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .any(|part| part.eq_ignore_ascii_case("KDE"))
    {
        "kde"
    } else {
        "gnome"
    };
    Ok(crate::app_paths::support_dir()?.join(format!("portal-keyboard-{name}.token")))
}

fn read_token(path: &PathBuf) -> Option<String> {
    if path.metadata().ok()?.len() > 4096 {
        return None;
    }
    fs::read_to_string(path)
        .ok()
        .filter(|token| !token.is_empty())
}

fn write_token(path: &PathBuf, token: &str) -> Result<()> {
    if token.is_empty() || token.len() > 4096 {
        return Err(eyre!("invalid portal token length"));
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyboard_handshake_advertises_required_eis_interfaces() {
        for required in ["ei_callback", "ei_connection", "ei_seat", "ei_device"] {
            assert!(KEYBOARD_INTERFACES.contains(&required));
        }
        assert!(KEYBOARD_INTERFACES.contains(&"ei_keyboard"));
    }

    #[test]
    fn kde_and_gnome_use_the_portal_without_changing_hyprland() {
        for desktop in ["KDE", "GNOME", "X-GNOME:GNOME", "X-KDE:KDE"] {
            assert!(uses_portal_for(desktop));
        }
        for desktop in ["Hyprland", "sway", "", "NOTGNOME"] {
            assert!(!uses_portal_for(desktop));
        }
    }

    #[test]
    fn terminal_and_standard_shortcuts_release_every_key() {
        for shift in [true, false] {
            let sequence = paste_sequence(shift, DEFAULT_PASTE_KEYS);
            let pressed: Vec<_> = sequence
                .iter()
                .filter(|(_, state)| *state == ei::keyboard::KeyState::Press)
                .map(|(key, _)| *key)
                .collect();
            let released: Vec<_> = sequence
                .iter()
                .filter(|(_, state)| *state == ei::keyboard::KeyState::Released)
                .map(|(key, _)| *key)
                .collect();
            assert_eq!(pressed, released.into_iter().rev().collect::<Vec<_>>());
        }
    }

    #[test]
    fn portal_paste_resolves_v_from_the_compositor_keymap() {
        let context = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
        let us = xkb::Keymap::new_from_names(
            &context,
            "evdev",
            "pc105",
            "us",
            "",
            Some(String::new()),
            xkb::KEYMAP_COMPILE_NO_FLAGS,
        )
        .unwrap();
        let dvorak = xkb::Keymap::new_from_names(
            &context,
            "evdev",
            "pc105",
            "us",
            "dvorak",
            Some(String::new()),
            xkb::KEYMAP_COMPILE_NO_FLAGS,
        )
        .unwrap();
        assert_eq!(resolve_paste_keys(&us, 0, false).unwrap().v, KEY_V);
        assert_ne!(resolve_paste_keys(&dvorak, 0, false).unwrap().v, KEY_V);
    }

    #[test]
    fn kde_keymap_without_terminator_and_terminated_keymap_both_resolve_v() {
        let context = xkb::Context::new(xkb::CONTEXT_NO_FLAGS);
        let keymap = xkb::Keymap::new_from_names(
            &context,
            "evdev",
            "pc105",
            "us",
            "",
            Some(String::new()),
            xkb::KEYMAP_COMPILE_NO_FLAGS,
        )
        .unwrap();
        let bytes = keymap
            .get_as_string(xkb::KEYMAP_FORMAT_TEXT_V1)
            .into_bytes();
        assert_eq!(
            resolve_paste_keys(&parse_keymap_bytes(bytes.clone()).unwrap(), 0, false)
                .unwrap()
                .v,
            KEY_V
        );
        let mut terminated = bytes.clone();
        terminated.push(0);
        assert_eq!(
            resolve_paste_keys(&parse_keymap_bytes(terminated).unwrap(), 0, false)
                .unwrap()
                .v,
            KEY_V
        );
        let mut malformed = bytes;
        malformed.push(0);
        malformed.push(b'x');
        assert!(parse_keymap_bytes(malformed).is_err());
    }

    #[test]
    fn keymap_fd_with_offset_at_end_still_parses_from_start() {
        use std::io::{Seek, SeekFrom};
        use std::os::fd::FromRawFd;

        let keymap = xkb::Keymap::new_from_names(
            &xkb::Context::new(xkb::CONTEXT_NO_FLAGS),
            "evdev",
            "pc105",
            "us",
            "",
            Some(String::new()),
            xkb::KEYMAP_COMPILE_NO_FLAGS,
        )
        .unwrap();
        let bytes = keymap
            .get_as_string(xkb::KEYMAP_FORMAT_TEXT_V1)
            .into_bytes();
        let fd = unsafe { libc::memfd_create(c"hex-keymap-test".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&bytes).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(
            resolve_paste_keys(
                &parse_keymap(file.into(), bytes.len() as u32).unwrap(),
                0,
                false
            )
            .unwrap()
            .v,
            KEY_V
        );
    }

    #[test]
    fn swapped_caps_and_control_uses_the_real_control_modifier() {
        let keymap = xkb::Keymap::new_from_names(
            &xkb::Context::new(xkb::CONTEXT_NO_FLAGS),
            "evdev",
            "pc105",
            "us",
            "",
            Some("ctrl:swapcaps".into()),
            xkb::KEYMAP_COMPILE_NO_FLAGS,
        )
        .unwrap();
        let keys = resolve_paste_keys(&keymap, 0, true).unwrap();
        assert_eq!(keys.control, 58); // evdev Caps Lock now produces Control.
        assert_eq!(keys.shift, KEY_SHIFT);
        assert_eq!(keys.v, KEY_V);
        assert_eq!(paste_sequence(false, keys)[0].0, keys.control);
    }

    #[test]
    fn non_latin_group_uses_latin_shortcut_position_without_losing_dvorak() {
        let keymap = xkb::Keymap::new_from_names(
            &xkb::Context::new(xkb::CONTEXT_NO_FLAGS),
            "evdev",
            "pc105",
            "us,ru",
            "dvorak,",
            Some(String::new()),
            xkb::KEYMAP_COMPILE_NO_FLAGS,
        )
        .unwrap();
        assert_eq!(keymap.num_layouts(), 2);
        assert!(key_for_symbol(&keymap, 1, xkb::Keysym::v).is_none());
        let latin = resolve_paste_keys(&keymap, 0, false).unwrap();
        let russian = resolve_paste_keys(&keymap, 1, false).unwrap();
        assert_ne!(latin.v, KEY_V);
        assert_eq!(russian.v, latin.v);
        assert_eq!(russian.control, latin.control);
        assert!(resolve_paste_keys(&keymap, 1, true).is_ok());

        let russian_only = xkb::Keymap::new_from_names(
            &xkb::Context::new(xkb::CONTEXT_NO_FLAGS),
            "evdev",
            "pc105",
            "ru",
            "",
            Some(String::new()),
            xkb::KEYMAP_COMPILE_NO_FLAGS,
        )
        .unwrap();
        assert!(resolve_paste_keys(&russian_only, 0, false).is_err());
    }
}
