use super::*;
use crate::client::endpoint::{EndpointNegotiation, EndpointRegistry, EndpointTransport};

struct NoRequests(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl EndpointTransport for NoRequests {
    fn send(&mut self, _: &ClientMessage) -> std::io::Result<()> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

fn dispatch(
    state: &mut ClientShellState,
    actions: Vec<ClientShellAction>,
    endpoints: &mut EndpointRegistry,
    children: &mut Vec<std::process::Child>,
) -> bool {
    let mut commands = crate::client::endpoint_commands::EndpointCommands::default();
    let mut activation = None;
    crate::client::shell_runtime::dispatch_client_shell_actions(
        actions,
        &mut commands,
        endpoints,
        Some(state),
        children,
        &mut activation,
    )
    .unwrap()
    .1
}

fn assert_client_command_raw_valid_sibling(sibling: &str) {
    for source in [
        ClientShellKeybindingSource::Local,
        ClientShellKeybindingSource::RemoteLocal,
        ClientShellKeybindingSource::Endpoint,
    ] {
        for prefixed in [false, true] {
            let mut local = Config::default();
            local
                .keys
                .client_command
                .push(crate::config::ClientCommandKeybindConfig {
                    key: crate::config::BindingConfig::Many(vec![
                        " ctrl+y ".into(),
                        " prefix+y ".into(),
                        sibling.into(),
                    ]),
                    command: vec!["python3".into(), "-c".into(), "pass".into()],
                    description: None,
                });
            let mut state = ClientShellState::new(
                ClientShellConfig::from_config(&local).with_keybinding_source(source),
            );
            let mut initial = snapshot();
            initial.server_keybindings_toml = Some("[keys]\nprefix = 'ctrl+x'".into());
            state.cache_endpoint_snapshot_for_generation(
                &ClientEndpointId::Local,
                1,
                Box::new(initial),
            );
            assert!(state.activate_endpoint_projection(&ClientEndpointId::Local));
            assert_eq!(
                state.config.keybinds.keybinds.client_commands[0]
                    .bindings
                    .bindings
                    .len(),
                2
            );
            if prefixed {
                let prefix = if source == ClientShellKeybindingSource::Endpoint {
                    b"\x18"
                } else {
                    b"\x02"
                };
                assert!(state.handle_input_bytes(prefix).actions.is_empty());
                assert_eq!(state.mode, ClientShellMode::Prefix);
            }
            let captured = state.handle_input_bytes(if prefixed { b"y" } else { b"\x19" });
            assert_eq!(captured.actions.len(), 1,
                "valid raw shortcut must survive sibling {sibling:?}, source {source:?}, prefix {prefixed}");
            assert!(captured.requests.is_empty());
            // Reload keeps independent local authority even when the endpoint profile fails.
            state.config.apply_live_config(&local, &[], &[]);
            if source == ClientShellKeybindingSource::Endpoint {
                assert!(state
                    .config
                    .apply_snapshot_keybindings(Some("[keys"), &[])
                    .is_err());
            }
            let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut endpoints = EndpointRegistry::new(
                NoRequests(requests.clone()),
                1,
                EndpointNegotiation::default(),
            );
            let mut children = Vec::new();
            dispatch(&mut state, captured.actions, &mut endpoints, &mut children);
            assert_eq!(
                children.len(),
                1,
                "valid captured shortcut must still dispatch"
            );
            assert!(children[0].wait().unwrap().success());
            assert_eq!(requests.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn client_command_raw_valid_shortcuts_survive_empty_sibling() {
    for sibling in ["", "   "] {
        assert_client_command_raw_valid_sibling(sibling);
    }
}

#[test]
fn client_command_raw_valid_shortcuts_survive_malformed_sibling() {
    assert_client_command_raw_valid_sibling("not-a-valid-key");
}

#[test]
fn client_command_revocation_survives_invalid_endpoint_profile_reload() {
    let mut local: Config = toml::from_str(
        "[[keys.client_command]]\nkey = 'ctrl+y'\ncommand = ['python3', '-c', 'pass']",
    )
    .unwrap();
    let mut state = ClientShellState::new(
        ClientShellConfig::from_config(&local)
            .with_keybinding_source(ClientShellKeybindingSource::Endpoint),
    );
    let mut initial = snapshot();
    initial.server_keybindings_toml = Some("[keys]\nprefix = 'ctrl+x'".into());
    state.cache_endpoint_snapshot_for_generation(&ClientEndpointId::Local, 1, Box::new(initial));
    assert!(state.activate_endpoint_projection(&ClientEndpointId::Local));
    let captured = state.handle_input_bytes(b"\x19");
    assert_eq!(captured.actions.len(), 1);
    local.keys.client_command.clear();
    state.config.apply_live_config(&local, &[], &[]);
    assert!(state
        .config
        .apply_snapshot_keybindings(Some("[keys"), &[])
        .is_err());
    let mut endpoints = EndpointRegistry::new(
        NoRequests(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0))),
        1,
        EndpointNegotiation::default(),
    );
    let mut children = Vec::new();
    dispatch(&mut state, captured.actions, &mut endpoints, &mut children);
    for child in &mut children {
        child.wait().unwrap();
    }
    assert!(
        children.is_empty(),
        "revoked argv must not survive endpoint parse failure at dispatch"
    );
    let stale = state.handle_input_bytes(b"\x19");
    assert!(
        stale.actions.is_empty(),
        "stale effective binding must not authorize a new capture"
    );
    assert!(
        state.config.keybinds.keybinds.client_commands.is_empty(),
        "local revocation must update effective bindings independently of endpoint parsing"
    );
}

#[test]
fn client_command_rebinding_cannot_reauthorize_captured_old_binding() {
    let mut local: Config = toml::from_str(
        "[[keys.client_command]]\nkey = 'ctrl+y'\ncommand = ['python3', '-c', 'pass']",
    )
    .unwrap();
    let mut state = ClientShellState::new(
        ClientShellConfig::from_config(&local)
            .with_keybinding_source(ClientShellKeybindingSource::Endpoint),
    );
    let mut initial = snapshot();
    initial.server_keybindings_toml = Some("[keys]\nprefix = 'ctrl+x'".into());
    state.cache_endpoint_snapshot_for_generation(&ClientEndpointId::Local, 1, Box::new(initial));
    assert!(state.activate_endpoint_projection(&ClientEndpointId::Local));
    let captured = state.handle_input_bytes(b"\x19");
    assert_eq!(captured.actions.len(), 1);
    local.keys.client_command[0].key = crate::config::BindingConfig::one("ctrl+z");
    state.config.apply_live_config(&local, &[], &[]);
    state
        .config
        .apply_snapshot_keybindings(Some("[keys]\nprefix = 'ctrl+x'"), &[])
        .unwrap();
    let mut endpoints = EndpointRegistry::new(
        NoRequests(std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0))),
        1,
        EndpointNegotiation::default(),
    );
    let mut children = Vec::new();
    dispatch(&mut state, captured.actions, &mut endpoints, &mut children);
    for child in &mut children {
        child.wait().unwrap();
    }
    assert!(
        children.is_empty(),
        "another key authorizing identical argv must not authorize a stale captured binding"
    );
    assert_eq!(
        state.handle_input_bytes(b"\x1a").actions.len(),
        1,
        "the new binding must remain usable"
    );
}

#[test]
fn client_command_retained_keymap_cannot_replace_latest_local_authorization() {
    for revoked in ["remove", "argv", "binding"] {
        let mut local: Config =
            toml::from_str("[[keys.client_command]]\nkey = 'ctrl+y'\ncommand = ['trusted-helper']")
                .unwrap();
        let mut state = ClientShellState::new(
            ClientShellConfig::from_config(&local)
                .with_keybinding_source(ClientShellKeybindingSource::Endpoint),
        );
        let mut initial = snapshot();
        initial.server_keybindings_toml = Some("[keys]\nprefix = 'ctrl+x'".into());
        state.set_snapshot(Box::new(initial));
        let captured = state.handle_input_bytes(b"\x19");
        let [ClientShellAction::ClientCommand(invocation)] = &captured.actions[..] else {
            panic!("expected pre-revocation capture");
        };
        let previous = state.config.keybinds.keybinds.client_commands.clone();
        match revoked {
            "remove" => local.keys.client_command.clear(),
            "argv" => local.keys.client_command[0].command = vec!["replacement-helper".into()],
            "binding" => {
                local.keys.client_command[0].key = crate::config::BindingConfig::one("ctrl+z")
            }
            _ => unreachable!(),
        }
        state.config.apply_live_config(&local, &[], &[]);
        assert!(state
            .config
            .apply_snapshot_keybindings(Some("[keys"), &[])
            .is_err());
        // Model a retained keymap explicitly: neither capture nor dispatch may
        // mistake its entries for the separately updated local authority.
        state.config.keybinds.keybinds.client_commands = previous;
        assert!(
            !state.client_command_is_current(invocation),
            "dispatch must reject stale {revoked}"
        );
        assert!(
            state.handle_input_bytes(b"\x19").actions.is_empty(),
            "raw capture must reject stale {revoked}"
        );
        state
            .config
            .apply_snapshot_keybindings(Some("[keys]\nprefix = 'ctrl+x'"), &[])
            .unwrap();
        if revoked == "remove" {
            assert!(state.config.keybinds.keybinds.client_commands.is_empty());
        } else {
            assert_eq!(
                state.config.keybinds.keybinds.client_commands[0].command,
                local.keys.client_command[0].command
            );
        }
    }
}

fn mouse_selected_client() -> ClientShellState {
    let local: Config = toml::from_str(
        "[ui]\ncopy_on_select = false\n[[keys.client_command]]\nkey = ['ctrl+y', 'prefix+y']\ncommand = ['trusted-helper']",
    ).unwrap();
    let mut state = ClientShellState::new(ClientShellConfig::from_config(&local));
    state.set_snapshot(Box::new(snapshot()));
    let mut frame = surface();
    frame.panes[0].content_revision = 42;
    state.set_pane_surface(frame);
    state.compose(106, 20).unwrap();
    let pane = &state.hits.panes[0];
    let (x, y) = (pane.inner_rect.x + 1, pane.inner_rect.y + 1);
    for event in [
        format!("\x1b[<0;{x};{y}M"),
        format!("\x1b[<32;{};{y}M", x + 2),
        format!("\x1b[<0;{};{y}m", x + 2),
    ] {
        state.handle_input_bytes(event.as_bytes());
    }
    assert!(state
        .selection
        .as_ref()
        .is_some_and(crate::selection::Selection::is_visible));
    state
}

fn assert_mouse_selection_capture(outcome: ClientShellInput) {
    let [ClientShellAction::ClientCommand(invocation)] = &outcome.actions[..] else {
        panic!("expected native command capture: {:?}", outcome.actions);
    };
    assert_eq!(
        invocation.context["selection"],
        serde_json::json!({
            "pane_id": "pane_1", "anchor": {"row": 0, "col": 0},
            "cursor": {"row": 0, "col": 2}, "content_revision": 42,
        }),
        "raw command must capture the ordinary mouse selection"
    );
    assert!(outcome.requests.is_empty());
}

#[test]
fn client_command_raw_direct_key_preserves_mouse_selection() {
    let mut state = mouse_selected_client();
    assert_mouse_selection_capture(state.handle_input_bytes(b"\x19"));
}

#[test]
fn client_command_raw_prefix_keys_preserve_mouse_selection() {
    let mut state = mouse_selected_client();
    let prefix = state.handle_input_bytes(b"\x02");
    assert!(prefix.actions.is_empty());
    assert_eq!(state.mode, ClientShellMode::Prefix);
    assert_mouse_selection_capture(state.handle_input_bytes(b"y"));
}

#[test]
fn client_command_raw_unrelated_keys_still_clear_mouse_selection() {
    for bytes in [b"a".as_slice(), b"\x02x", b"\x02\x1b", b"\x02\x02"] {
        let mut state = mouse_selected_client();
        state.handle_input_bytes(bytes);
        assert!(
            state.selection.is_none(),
            "unrelated input must retain existing clearing: {bytes:?}"
        );
    }
}

pub(super) fn isolated_client_command_test(name: &str, environment: &[(&str, &str)]) -> bool {
    if std::env::var("HERDR_CLIENT_COMMAND_TEST_CHILD").as_deref() == Ok(name) {
        return false;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.args(["--exact", name, "--nocapture", "--test-threads=1"]);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("HERDR_")
            || key.to_string_lossy().starts_with("HERMES_")
        {
            child.env_remove(key);
        }
    }
    child.env("HERDR_CLIENT_COMMAND_TEST_CHILD", name);
    for (key, value) in environment {
        child.env(key, value);
    }
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "isolated child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "child must actually execute its assertion: {:?}",
        output
    );
    true
}

#[test]
fn client_command_route_rejects_client_only_socket_override() {
    if isolated_client_command_test("client::shell::tests::client_commands::client_command_route_rejects_client_only_socket_override", &[("HERDR_CLIENT_SOCKET_PATH", "/synthetic/other-client.sock")]) { return; }
    let local: Config =
        toml::from_str("[[keys.client_command]]\nkey = 'ctrl+y'\ncommand = ['trusted-helper']")
            .unwrap();
    let config = ClientShellConfig::from_config(&local)
        .with_local_endpoint(&crate::server::socket_paths::client_socket_path());
    let mut state = ClientShellState::new(config);
    state.set_snapshot(Box::new(snapshot()));
    assert!(
        state.handle_input_bytes(b"\x19").actions.is_empty(),
        "client-only override must not send other-server focus to the default API"
    );
    assert!(state.config.client_command_local_route.is_none());
}

#[test]
fn client_command_route_checks_actual_with_local_endpoint_socket() {
    let config = ClientShellConfig::from_config(&Config::default())
        .with_local_endpoint(std::path::Path::new("/synthetic/unrelated-client.sock"));
    assert!(config.client_command_local_route.is_none(), "actual client connection, not the environment's default socket, must determine route admission");
}

#[test]
fn client_command_route_accepts_paired_api_socket_override() {
    if isolated_client_command_test("client::shell::tests::client_commands::client_command_route_accepts_paired_api_socket_override", &[("HERDR_SOCKET_PATH", "/synthetic/paired.sock"), ("HERDR_CLIENT_SOCKET_PATH", "/synthetic/ignored-client.sock")]) { return; }
    let config = ClientShellConfig::from_config(&Config::default())
        .with_local_endpoint(&crate::server::socket_paths::client_socket_path());
    assert_eq!(
        config.client_command_local_route.unwrap()["server_socket"],
        "/synthetic/paired.sock"
    );
}

#[test]
fn client_command_route_rejects_unpaired_direct_remote_socket() {
    if isolated_client_command_test("client::shell::tests::client_commands::client_command_route_rejects_unpaired_direct_remote_socket", &[("HERDR_CLIENT_REMOTE_TARGET", "direct@host"), ("HERDR_CLIENT_REMOTE_SESSION", "agents"), ("HERDR_REMOTE_KEYBINDINGS", "local"), ("HERDR_CLIENT_SOCKET_PATH", "/synthetic/bridge.sock")]) { return; }
    let config = ClientShellConfig::from_config(&Config::default())
        .with_local_endpoint(std::path::Path::new("/synthetic/another.sock"));
    assert!(
        config.client_command_local_route.is_none(),
        "remote route must belong to the actual launcher bridge socket"
    );
}

#[test]
fn client_command_environment_fixtures_forbid_global_mutations() {
    for source in [
        include_str!("client_commands.rs"),
        include_str!("keybindings_settings.rs"),
    ] {
        assert!(
            !source.contains(concat!("std::env::", "set_var("))
                && !source.contains(concat!("std::env::", "remove_var(")),
            "new client-command fixtures must use child-process env, not race other constructors"
        );
    }
}

#[cfg(unix)]
#[test]
fn client_command_environment_children_leave_parallel_constructors_unchanged() {
    let route = ClientShellConfig::from_config(&Config::default()).client_command_local_route;
    let before: std::collections::BTreeMap<_, _> = std::env::vars_os().collect();
    std::thread::scope(|scope| {
        scope.spawn(super::keybindings_settings::client_command_direct_remote_route_is_captured_from_the_local_launcher);
        scope.spawn(
            client_command_dispatch_runs_local_argv_on_a_remote_endpoint_with_clean_detached_env,
        );
        for _ in 0..100 {
            assert_eq!(
                ClientShellConfig::from_config(&Config::default()).client_command_local_route,
                route
            );
        }
    });
    assert_eq!(
        std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>(),
        before
    );
}

#[test]
fn client_command_dispatch_rechecks_committed_owner_before_launch() {
    for revoked in [
        "unavailable",
        "frozen",
        "generation",
        "snapshot",
        "boot",
        "offline",
        "configuration",
        "focus",
    ] {
        let mut config = Config::default();
        config
            .keys
            .client_command
            .push(crate::config::ClientCommandKeybindConfig {
                key: crate::config::BindingConfig::one("prefix+y"),
                command: vec!["python3".into(), "-c".into(), "pass".into()],
                description: None,
            });
        let mut state = ClientShellState::new(ClientShellConfig::from_config(&config));
        state.cache_endpoint_snapshot_for_generation(
            &ClientEndpointId::Local,
            1,
            Box::new(snapshot()),
        );
        assert!(state.activate_endpoint_projection(&ClientEndpointId::Local));
        let mut outcome = ClientShellInput::default();
        state.record_binding(
            crate::input::KeybindMatch::ClientCommand(
                state.config.keybinds.keybinds.client_commands[0].clone(),
            ),
            &mut outcome,
        );
        assert_eq!(outcome.actions.len(), 1);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut endpoints = EndpointRegistry::new(
            NoRequests(requests.clone()),
            1,
            EndpointNegotiation::default(),
        );
        match revoked {
            "unavailable" => endpoints = EndpointRegistry::empty(),
            "frozen" => endpoints.freeze_input(),
            "generation" => endpoints.insert(
                ClientEndpointId::Local,
                NoRequests(requests.clone()),
                2,
                EndpointNegotiation::default(),
                true,
            ),
            "snapshot" => {
                let mut next = snapshot();
                next.revision = 2;
                state.cache_endpoint_snapshot_for_generation(
                    &ClientEndpointId::Local,
                    1,
                    Box::new(next),
                );
            }
            "boot" => {
                let mut next = snapshot();
                next.boot_id = "new-boot".into();
                state.cache_endpoint_snapshot_for_generation(
                    &ClientEndpointId::Local,
                    1,
                    Box::new(next),
                );
            }
            "offline" => state
                .set_endpoint_status(&ClientEndpointId::Local, ClientEndpointStatus::Reconnecting),
            "configuration" => state.config.keybinds.keybinds.client_commands.clear(),
            "focus" => state.snapshot.as_mut().unwrap().focused_pane_id = None,
            _ => unreachable!(),
        }
        let mut children = Vec::new();
        let repaint = dispatch(&mut state, outcome.actions, &mut endpoints, &mut children);
        for child in &mut children {
            child.wait().unwrap();
        }
        assert!(children.is_empty(), "must not launch revoked {revoked}");
        assert!(repaint, "rejected {revoked} must be visible");
    }
}

#[cfg(unix)]
#[test]
fn client_command_dispatch_runs_local_argv_on_a_remote_endpoint_with_clean_detached_env() {
    let overrides = [
        "HERDR_SOCKET_PATH",
        "HERDR_CLIENT_SOCKET_PATH",
        "HERDR_ACTIVE_PANE_ID",
        "HERDR_PANE_ID",
        "HERDR_SESSION",
        "HERDR_REMOTE_KEYBINDINGS",
        "HERDR_CLIENT_CONTEXT_JSON",
        "HERDR_BIN_PATH",
        "HERDR_CLIENT_REMOTE_TARGET",
    ];
    let environment = overrides.map(|key| (key, "inherited-untrusted"));
    if isolated_client_command_test(
        "client::shell::tests::client_commands::client_command_dispatch_runs_local_argv_on_a_remote_endpoint_with_clean_detached_env",
        &environment,
    ) {
        return;
    }
    let path = std::env::temp_dir().join(format!(
        "herdr-client-command-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let code = "import json,os,sys,stat; json.dump({'argv':sys.argv[2:],'env':{k:v for k,v in os.environ.items() if k.startswith('HERDR_')},'input':sys.stdin.read(),'stdio_char':[stat.S_ISCHR(os.fstat(i).st_mode) for i in range(3)]},open(sys.argv[1],'w'))";
    let mut config = Config::default();
    config
        .keys
        .client_command
        .push(crate::config::ClientCommandKeybindConfig {
            key: crate::config::BindingConfig::one("prefix+y"),
            command: vec![
                "python3".into(),
                "-c".into(),
                code.into(),
                path.display().to_string(),
                "literal $(do-not-execute); spaced arg".into(),
            ],
            description: None,
        });
    let profile = crate::client::endpoint::SavedSshEndpoint {
        id: crate::client::endpoint::ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap(),
        label: "Build".into(),
        target: "dev@host".into(),
        session: "agents".into(),
        enabled: true,
    };
    let remote = ClientEndpointId::Ssh(profile.id.clone());
    let mut state = ClientShellState::new(ClientShellConfig::from_config(&config));
    state.set_endpoint_catalog(&[profile]);
    state.set_endpoint_status(&remote, ClientEndpointStatus::Online);
    state.cache_endpoint_snapshot_for_generation(&remote, 1, Box::new(snapshot()));
    assert!(state.activate_endpoint_projection(&remote));
    state.set_pane_surface(surface());
    let mut selected = crate::selection::Selection::absolute_range("pane_1".into(), (0, 0), (0, 1));
    selected.finish();
    state.selection = Some(selected);
    let mut outcome = ClientShellInput::default();
    state.record_binding(
        crate::input::KeybindMatch::ClientCommand(
            state.config.keybinds.keybinds.client_commands[0].clone(),
        ),
        &mut outcome,
    );
    let [ClientShellAction::ClientCommand(invocation)] = &outcome.actions[..] else {
        panic!("expected local capture");
    };
    let expected_context = invocation.context.clone();
    let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut endpoints = EndpointRegistry::empty();
    endpoints.insert(
        remote.clone(),
        NoRequests(requests.clone()),
        1,
        EndpointNegotiation::default(),
        true,
    );
    assert!(endpoints.set_active(&remote));
    endpoints.unfreeze_input();
    let mut children = Vec::new();
    let repaint = dispatch(&mut state, outcome.actions, &mut endpoints, &mut children);
    assert_eq!(
        children.len(),
        1,
        "must launch one local argv child, repaint={repaint}"
    );
    assert!(children[0].wait().unwrap().success());
    let result: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        result["argv"],
        serde_json::json!(["literal $(do-not-execute); spaced arg"])
    );
    assert_eq!(result["input"], "");
    assert_eq!(result["stdio_char"], serde_json::json!([true, true, true]));
    let env = result["env"].as_object().unwrap();
    assert_eq!(
        env.len(),
        2,
        "only trusted binary and JSON context may survive: {env:?}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            env["HERDR_CLIENT_CONTEXT_JSON"].as_str().unwrap()
        )
        .unwrap(),
        expected_context
    );
    assert_eq!(
        env["HERDR_BIN_PATH"],
        crate::platform::launch_executable()
            .unwrap()
            .display()
            .to_string()
    );
    assert_eq!(requests.load(std::sync::atomic::Ordering::Relaxed), 0);
}
