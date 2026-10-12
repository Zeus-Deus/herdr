use super::*;

pub(super) fn local_route_context(socket_path: &std::path::Path) -> Option<serde_json::Value> {
    if let Ok(target) = std::env::var("HERDR_CLIENT_REMOTE_TARGET") {
        let session = std::env::var("HERDR_CLIENT_REMOTE_SESSION").ok()?;
        let bridge = std::env::var_os(crate::server::socket_paths::CLIENT_SOCKET_PATH_ENV_VAR)?;
        if target.is_empty()
            || crate::session::validate_name(&session).is_err()
            || !crate::client::handshake::is_remote_client_process()
            || std::path::Path::new(&bridge) != socket_path
        {
            return None;
        }
        return Some(serde_json::json!({"ssh_target": target, "session": session}));
    }
    if crate::client::handshake::is_remote_client_process() {
        return None;
    }
    let api_socket = crate::api::socket_path();
    if crate::server::socket_paths::derive_client_socket_from_api_socket(&api_socket) != socket_path
    {
        // A legacy client-only override need not have a corresponding JSON API.
        // Never pair its focus with the default API merely because both are local.
        return None;
    }
    Some(serde_json::json!({
        "session": crate::session::active_name().unwrap_or_else(|| crate::session::DEFAULT_SESSION_NAME.into()),
        "server_socket": api_socket.display().to_string(),
    }))
}

/// Internal, process-local action. Never sent through a protocol codec.
#[derive(Debug, PartialEq)]
pub(crate) struct ClientCommandInvocation {
    pub(crate) endpoint_id: ClientEndpointId,
    pub(crate) generation: Option<u64>,
    pub(crate) boot_id: String,
    pub(crate) revision: u64,
    pub(crate) command: Vec<String>,
    binding: crate::config::ClientCommandKeybind,
    pub(crate) context: serde_json::Value,
}

pub(crate) fn spawn_client_command(
    invocation: &ClientCommandInvocation,
) -> std::io::Result<std::process::Child> {
    let (program, args) = invocation
        .command
        .split_first()
        .ok_or_else(|| std::io::Error::other("empty client command argv"))?;
    let mut command = std::process::Command::new(program);
    command.args(args);
    crate::platform::configure_background_command(&mut command);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Pane ids, socket overrides, direct SSH routing and old context must never leak in.
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("HERDR_")
        {
            command.env_remove(key);
        }
    }
    command.env("HERDR_BIN_PATH", crate::platform::launch_executable()?);
    command.env(
        "HERDR_CLIENT_CONTEXT_JSON",
        serde_json::to_string(&invocation.context).map_err(std::io::Error::other)?,
    );
    command.spawn()
}

impl ClientShellState {
    pub(crate) fn client_command_is_current(&self, invocation: &ClientCommandInvocation) -> bool {
        self.capture_client_command(&invocation.binding)
            .is_ok_and(|current| &current == invocation)
    }

    pub(super) fn record_client_command(
        &mut self,
        binding: crate::config::ClientCommandKeybind,
        outcome: &mut ClientShellInput,
    ) {
        match self.capture_client_command(&binding) {
            Ok(invocation) => outcome
                .actions
                .push(ClientShellAction::ClientCommand(Box::new(invocation))),
            Err(message) => {
                self.set_endpoint_error(format!("Client command rejected: {message}"));
                outcome.repaint = true;
            }
        }
    }

    fn capture_client_command(
        &self,
        binding: &crate::config::ClientCommandKeybind,
    ) -> Result<ClientCommandInvocation, &'static str> {
        if !self.config.client_command_is_authorized(binding)
            || !self
                .config
                .keybinds
                .keybinds
                .client_commands
                .contains(binding)
        {
            return Err("binding is not in the trusted local configuration");
        }
        let snapshot = self.snapshot.as_deref().ok_or("endpoint has no snapshot")?;
        let endpoint = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == self.active_endpoint_id)
            .ok_or("endpoint unavailable")?;
        let cached = endpoint
            .snapshot
            .as_deref()
            .ok_or("endpoint has no snapshot")?;
        if endpoint.status != ClientEndpointStatus::Online {
            return Err("endpoint is not ready");
        }
        if endpoint.snapshot_generation != self.active_snapshot_generation
            || cached.boot_id != snapshot.boot_id
            || cached.revision != snapshot.revision
        {
            return Err("stale or foreign endpoint snapshot");
        }
        if let Some(workspace_id) = &snapshot.focused_workspace_id {
            if !snapshot
                .workspaces
                .iter()
                .any(|workspace| &workspace.workspace_id == workspace_id)
            {
                return Err("workspace disappeared");
            }
        }
        if let Some(tab_id) = &snapshot.focused_tab_id {
            let tab = snapshot
                .tabs
                .iter()
                .find(|tab| &tab.tab_id == tab_id)
                .ok_or("tab disappeared")?;
            if snapshot
                .focused_workspace_id
                .as_ref()
                .is_some_and(|workspace| workspace != &tab.workspace_id)
            {
                return Err("tab belongs to another workspace");
            }
        }
        if let Some(pane_id) = &snapshot.focused_pane_id {
            let pane = snapshot
                .panes
                .iter()
                .find(|pane| &pane.pane_id == pane_id)
                .ok_or("pane disappeared")?;
            if snapshot
                .focused_workspace_id
                .as_ref()
                .is_some_and(|workspace| workspace != &pane.workspace_id)
                || snapshot
                    .focused_tab_id
                    .as_ref()
                    .is_some_and(|tab| tab != &pane.tab_id)
            {
                return Err("pane belongs to another workspace or tab");
            }
        }
        let selection = match self
            .selection
            .as_ref()
            .filter(|selection| selection.is_visible())
        {
            Some(selection) => {
                if snapshot.focused_pane_id.as_deref() != Some(selection.pane_id.as_str()) {
                    return Err("selection belongs to another pane");
                }
                let frame = self
                    .pane_surface
                    .as_ref()
                    .ok_or("selection has no displayed surface")?;
                if self.pane_surface_generation != self.active_snapshot_generation
                    || frame.boot_id != snapshot.boot_id
                    || frame.projection_revision != snapshot.revision
                {
                    return Err("stale or foreign selection surface");
                }
                let pane = frame
                    .panes
                    .iter()
                    .find(|pane| pane.pane_id == selection.pane_id)
                    .ok_or("selection pane disappeared")?;
                let (anchor, cursor) = selection.ordered_cells();
                Some(crate::api::schema::PaneSelectionReadParams {
                    pane_id: selection.pane_id.clone(),
                    anchor: crate::api::schema::PaneTextPoint {
                        row: anchor.0,
                        col: anchor.1,
                    },
                    cursor: crate::api::schema::PaneTextPoint {
                        row: cursor.0,
                        col: cursor.1,
                    },
                    content_revision: Some(pane.content_revision),
                })
            }
            None => None,
        };
        let mut context = serde_json::json!({
            "version": 1,
            "endpoint_id": self.active_endpoint_id.storage_key(),
        });
        if let Some(profile) = self.client_command_profiles.get(&self.active_endpoint_id) {
            context["machine_id"] = serde_json::json!(profile.id.as_str());
            context["ssh_target"] = serde_json::json!(profile.target);
            context["session"] = serde_json::json!(profile.session);
        } else {
            if !self.active_endpoint_id.is_local() {
                return Err("SSH profile unavailable");
            }
            let route = self
                .config
                .client_command_local_route
                .as_ref()
                .and_then(|value| value.as_object())
                .ok_or("local endpoint route unavailable")?;
            for (key, value) in route {
                context[key] = value.clone();
            }
        }
        for (key, value) in [
            ("workspace_id", &snapshot.focused_workspace_id),
            ("tab_id", &snapshot.focused_tab_id),
            ("pane_id", &snapshot.focused_pane_id),
        ] {
            if let Some(value) = value {
                context[key] = serde_json::Value::String(value.clone());
            }
        }
        if let Some(selection) = selection {
            context["selection"] = serde_json::json!(selection);
        }
        Ok(ClientCommandInvocation {
            endpoint_id: self.active_endpoint_id.clone(),
            generation: self.active_snapshot_generation,
            boot_id: snapshot.boot_id.clone(),
            revision: snapshot.revision,
            command: binding.command.clone(),
            binding: binding.clone(),
            context,
        })
    }
}
