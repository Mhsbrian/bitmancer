// src/commands.rs
//
// Slash-command handling. The old client threaded a dozen `handle_*_command`
// futures through the main loop, each mutating shared state and returning a
// bool; this returns an outcome the loop applies instead.

use crate::geo::GeoService;
use crate::geohash;
use crate::mesh::MeshService;
use crate::peer_id::short_display;

pub enum CommandOutcome {
    /// Not a command at all — send it to the active conversation.
    NotACommand,
    /// Show these lines in the current conversation.
    Reply(Vec<String>),
    SetNickname(String),
    ClearConversation,
    ToggleDebug,
    /// Open the world map overlay.
    OpenMap,
    /// Open the image viewer on the nth-newest image (1 = newest).
    OpenImage(Option<usize>),
    /// Join a geohash location channel.
    JoinGeohash(String),
    /// Leave a geohash channel, or the active one when None.
    LeaveGeohash(Option<String>),
    /// Hand a peer our Nostr address so they can reach us off-mesh.
    SetFavorite { target: String, favorite: bool },
    /// Put a local file on the mesh.
    SendFile(String),
    /// Destroy the stored identity and quit. Irreversible.
    WipeIdentity,
    /// Refuse all traffic from a peer, by fingerprint.
    BlockPeer(String),
    /// Stop refusing traffic from a peer.
    UnblockPeer(String),
    /// Send an encrypted private message. The target is a resolved peer ID, not
    /// a nickname: resolution can fail or be ambiguous, and that is worth
    /// reporting to the user before anything is encrypted.
    SendDirectMessage { target: String, content: String },
    Quit,
}

pub fn handle(
    line: &str,
    mesh: &MeshService,
    geo: &GeoService,
    connected: bool,
) -> CommandOutcome {
    let trimmed = line.trim();
    if !trimmed.starts_with('/') {
        return CommandOutcome::NotACommand;
    }

    let mut parts = trimmed.split_whitespace();
    let command = parts.next().unwrap_or("").to_lowercase();
    let rest = trimmed[command.len()..].trim();

    match command.as_str() {
        "/help" => CommandOutcome::Reply(help_text()),
        "/exit" | "/quit" => CommandOutcome::Quit,
        "/clear" => CommandOutcome::ClearConversation,
        "/name" | "/nick" => {
            if rest.is_empty() {
                return CommandOutcome::Reply(vec!["Usage: /name <nickname>".to_string()]);
            }
            CommandOutcome::SetNickname(rest.to_string())
        }
        "/status" => CommandOutcome::Reply(status_lines(mesh, connected)),
        "/debug" => CommandOutcome::ToggleDebug,
        "/map" => CommandOutcome::OpenMap,
        "/img" | "/image" | "/pic" => {
            CommandOutcome::OpenImage(rest.trim().parse::<usize>().ok())
        }
        "/online" | "/w" | "/who" => CommandOutcome::Reply(online_lines(mesh)),
        "/fingerprint" => CommandOutcome::Reply(vec![
            format!("Your peer ID:     {}", mesh.my_peer_id),
            format!("Your fingerprint: {}", mesh.my_fingerprint()),
        ]),
        "/public" => CommandOutcome::Reply(vec![
            "The mesh has a single public conversation; you are already in it.".to_string(),
        ]),

        // Location channels. `/j #9q8yy` is the familiar spelling; `/geo` is
        // the explicit one. Both reach the same Nostr-backed channels the
        // phone app shows.
        "/geo" | "/j" | "/join" => {
            let argument = rest.trim();
            match argument {
                "" => CommandOutcome::Reply(geo_help(geo)),
                "off" | "leave" => CommandOutcome::LeaveGeohash(None),
                "list" | "ls" => CommandOutcome::Reply(geo_list(geo)),
                _ => {
                    let candidate = geohash::normalize(argument);
                    if geohash::is_valid(&candidate) {
                        CommandOutcome::JoinGeohash(candidate)
                    } else {
                        CommandOutcome::Reply(vec![
                            format!("{argument:?} is not a geohash."),
                            "Location channels are named by geohash, e.g. /geo #9q8yy.".to_string(),
                            "Valid characters are 0-9 and b-z without a, i, l or o.".to_string(),
                        ])
                    }
                }
            }
        }
        "/leave" => CommandOutcome::LeaveGeohash(None),

        // Password-protected mesh channels are gone for good.
        "/pass" | "/transfer" => CommandOutcome::Reply(vec![
            format!("{command}: password-protected mesh channels were removed from"),
            "the bitchat protocol in July 2025. Location channels (/geo) have".to_string(),
            "no passwords or owners.".to_string(),
        ]),
        "/channels" => CommandOutcome::Reply(geo_list(geo)),

        "/dm" | "/msg" => {
            let Some((who, text)) = rest.split_once(char::is_whitespace) else {
                return CommandOutcome::Reply(vec![
                    format!("Usage: {command} <nickname> <message>"),
                    "The first private message opens an encrypted channel, so it".to_string(),
                    "may take a moment to arrive.".to_string(),
                ]);
            };
            let text = text.trim();
            if text.is_empty() {
                return CommandOutcome::Reply(vec![format!("Usage: {command} <nickname> <message>")]);
            }
            // A bare peer ID is accepted so two peers sharing a nickname can
            // still be reached.
            let target = if mesh.peers.contains_key(who) {
                Ok(who.to_string())
            } else {
                mesh.peer_id_for_nickname(who)
            };
            match target {
                Ok(target) => CommandOutcome::SendDirectMessage {
                    target,
                    content: text.to_string(),
                },
                Err(reason) => CommandOutcome::Reply(vec![reason]),
            }
        }
        "/fav" | "/favorite" | "/unfav" | "/unfavorite" if rest.is_empty() => {
            let listed = mesh.favorites.ours();
            if listed.is_empty() {
                CommandOutcome::Reply(vec![
                    "No favourites yet.".to_string(),
                    "/fav <nickname> hands them your Nostr address, so they can".to_string(),
                    "reach you when Bluetooth cannot.".to_string(),
                ])
            } else {
                let mut lines = vec![format!("Favourites ({}):", listed.len())];
                for (_, entry) in listed {
                    // Say plainly whether a route actually exists. A favourite
                    // that has not answered is not a way to reach anyone.
                    let state = match (entry.mutual(), entry.reachable_over_nostr()) {
                        (true, true) => "mutual, reachable off-mesh",
                        (false, true) => "reachable off-mesh",
                        _ => "no address yet",
                    };
                    lines.push(format!("  {:<16} {state}", entry.nickname));
                }
                CommandOutcome::Reply(lines)
            }
        }
        "/fav" | "/favorite" | "/unfav" | "/unfavorite" => {
            let favorite = command == "/fav" || command == "/favorite";
            let target = if mesh.peers.contains_key(rest) {
                Ok(rest.to_string())
            } else {
                mesh.peer_id_for_nickname(rest)
            };
            match target {
                Ok(target) => CommandOutcome::SetFavorite { target, favorite },
                Err(reason) => CommandOutcome::Reply(vec![reason]),
            }
        }

        "/send" | "/sendfile" if rest.is_empty() => CommandOutcome::Reply(vec![
            "Usage: /send <path to a file>".to_string(),
            "The file goes to everyone on the mesh, in fragments.".to_string(),
        ]),
        "/send" | "/sendfile" => CommandOutcome::SendFile(rest.to_string()),

        // Deliberately two steps. There is no undo, and the cost of an
        // accidental wipe is the user's whole identity.
        "/wipe" | "/panic" if rest != "confirm" => CommandOutcome::Reply(vec![
            "This destroys your identity key, your Noise key, your location-".to_string(),
            "channel seed, your block list and every conversation in this".to_string(),
            "session, then quits. Peers will see you as a stranger afterwards.".to_string(),
            "It cannot be undone.".to_string(),
            String::new(),
            format!("Type  {command} confirm  to go ahead."),
        ]),
        "/wipe" | "/panic" => CommandOutcome::WipeIdentity,

        "/block" if rest.is_empty() => {
            let blocked = mesh.blocked_labels();
            if blocked.is_empty() {
                CommandOutcome::Reply(vec!["Nobody is blocked.".to_string()])
            } else {
                let mut lines = vec![format!("Blocked ({}):", blocked.len())];
                lines.extend(blocked.into_iter().map(|label| format!("  {label}")));
                lines.push("Use /unblock <name> to undo.".to_string());
                CommandOutcome::Reply(lines)
            }
        }
        "/block" => {
            // Blocking needs the peer's announced key, so resolve to a peer we
            // actually know rather than to a bare label.
            let target = if mesh.peers.contains_key(rest) {
                Ok(rest.to_string())
            } else {
                mesh.peer_id_for_nickname(rest)
            };
            match target {
                Ok(peer_id) => CommandOutcome::BlockPeer(peer_id),
                Err(reason) => CommandOutcome::Reply(vec![reason]),
            }
        }
        "/unblock" if rest.is_empty() => {
            CommandOutcome::Reply(vec!["Usage: /unblock <nickname, peer ID or fingerprint>".to_string()])
        }
        // Unblocking takes the raw text: the peer may be long gone from the
        // list, in which case only the stored fingerprint is left to match.
        "/unblock" => CommandOutcome::UnblockPeer(rest.to_string()),

        unknown => CommandOutcome::Reply(vec![
            format!("Unknown command: {unknown}"),
            "Type /help to see what is available.".to_string(),
        ]),
    }
}

fn status_lines(mesh: &MeshService, connected: bool) -> Vec<String> {
    let mut lines = vec![
        "━━━ Status ━━━".to_string(),
        format!(
            "  Link:        {}",
            if connected {
                "connected to a bitchat peer"
            } else {
                "scanning"
            }
        ),
        format!("  Peers:       {}", mesh.peers.len()),
        format!("  Nickname:    {}", mesh.nickname),
        format!("  Peer ID:     {}", mesh.my_peer_id),
    ];
    if !mesh.peers.is_empty() {
        lines.push("  Known peers:".to_string());
        let mut peers: Vec<_> = mesh.peers.values().collect();
        peers.sort_by(|a, b| a.nickname.cmp(&b.nickname));
        for peer in peers {
            lines.push(format!(
                "    {} ({}){}",
                peer.nickname,
                short_display(&peer.peer_id),
                if peer.verified { "" } else { " unverified" }
            ));
        }
    }
    lines
}

fn online_lines(mesh: &MeshService) -> Vec<String> {
    if mesh.peers.is_empty() {
        return vec!["Nobody else is on the mesh right now.".to_string()];
    }
    let mut lines = vec![format!("{} peer(s) online:", mesh.peers.len())];
    for nickname in mesh.nicknames() {
        lines.push(format!("  {nickname}"));
    }
    lines
}

fn geo_help(geo: &GeoService) -> Vec<String> {
    let mut lines = vec![
        "Location channels are geohash cells shared with the phone app,".to_string(),
        "carried over Nostr relays rather than Bluetooth.".to_string(),
        "  /geo #9q8yy           Join a channel by geohash".to_string(),
        "  /geo list             Show joined channels".to_string(),
        "  /geo off              Leave the active channel".to_string(),
        "  /map                  Browse them on the world map".to_string(),
        "Precision sets the area: 2 region, 4 province, 5 city,".to_string(),
        "6 neighborhood, 7 block, 8 building.".to_string(),
    ];
    if !geo.joined().is_empty() {
        lines.push(String::new());
        lines.extend(geo_list(geo));
    }
    lines
}

fn geo_list(geo: &GeoService) -> Vec<String> {
    let joined = geo.joined();
    if joined.is_empty() {
        return vec!["No location channels joined. Try /geo #9q8yy.".to_string()];
    }
    let mut lines = vec![format!("{} location channel(s):", joined.len())];
    for geohash in joined {
        let count = geo.participant_count(&geohash);
        lines.push(format!(
            "  #{geohash}  {} participant(s), {} relay(s)",
            count,
            geo.relays_for(&geohash).len()
        ));
    }
    lines
}

fn help_text() -> Vec<String> {
    vec![
        "━━━ BitChat Commands ━━━".to_string(),
        "  /help                 Show this help".to_string(),
        "  /name <nickname>      Change your nickname and re-announce".to_string(),
        "  /map                  World map of live location channels".to_string(),
        "  /img [n]              View the newest image link (or the nth back)".to_string(),
        "  /geo #<geohash>       Join a location channel (over Nostr)".to_string(),
        "  /geo list, /geo off   List or leave location channels".to_string(),
        "  /online, /w           List peers on the mesh".to_string(),
        "  /status               Link, peer and identity info".to_string(),
        "  /fingerprint          Show your peer ID and key fingerprint".to_string(),
        "  /debug                Toggle a trace of every packet received".to_string(),
        "  /clear                Clear the current conversation".to_string(),
        "  /exit                 Quit".to_string(),
        "Anything else you type is sent to the public mesh.".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mesh() -> MeshService {
        MeshService::new([1; 32], [2; 32], "tui")
    }

    fn geo() -> GeoService {
        GeoService::new([3; 32], "tui")
    }

    #[test]
    fn plain_text_is_not_a_command() {
        assert!(matches!(
            handle("hello there", &mesh(), &geo(), true),
            CommandOutcome::NotACommand
        ));
    }

    #[test]
    fn name_requires_an_argument() {
        match handle("/name", &mesh(), &geo(), true) {
            CommandOutcome::Reply(lines) => assert!(lines[0].contains("Usage")),
            _ => panic!("expected usage text"),
        }
        assert!(matches!(
            handle("/name  bob ", &mesh(), &geo(), true),
            CommandOutcome::SetNickname(name) if name == "bob"
        ));
    }

    #[test]
    fn geohash_channels_can_be_joined_by_either_spelling() {
        for command in ["/geo #9q8yy", "/geo 9q8yy", "/j #9Q8YY", "/join 9q8yy"] {
            match handle(command, &mesh(), &geo(), true) {
                CommandOutcome::JoinGeohash(geohash) => assert_eq!(geohash, "9q8yy"),
                _ => panic!("{command} should join"),
            }
        }
    }

    #[test]
    fn invalid_geohashes_are_explained_not_joined() {
        // 'a', 'i', 'l' and 'o' are not in the geohash alphabet.
        match handle("/geo #dev-team", &mesh(), &geo(), true) {
            CommandOutcome::Reply(lines) => {
                assert!(lines[0].contains("not a geohash"), "{lines:?}")
            }
            _ => panic!("expected an explanation"),
        }
    }

    #[test]
    fn geo_off_leaves_the_active_channel() {
        assert!(matches!(
            handle("/geo off", &mesh(), &geo(), true),
            CommandOutcome::LeaveGeohash(None)
        ));
        assert!(matches!(
            handle("/leave", &mesh(), &geo(), true),
            CommandOutcome::LeaveGeohash(None)
        ));
    }

    #[test]
    fn geo_list_reports_joined_channels() {
        let mut geo = geo();
        geo.join("9q8yy");
        match handle("/geo list", &mesh(), &geo, true) {
            CommandOutcome::Reply(lines) => {
                assert!(lines.iter().any(|l| l.contains("#9q8yy")), "{lines:?}");
                assert!(lines.iter().any(|l| l.contains("relay")), "{lines:?}");
            }
            _ => panic!("expected a channel list"),
        }
    }

    #[test]
    fn removed_mesh_channel_features_still_explain_themselves() {
        for command in ["/pass hunter2", "/transfer @bob"] {
            match handle(command, &mesh(), &geo(), true) {
                CommandOutcome::Reply(lines) => {
                    assert!(lines.join(" ").contains("removed"), "{command}: {lines:?}")
                }
                _ => panic!("{command} should reply"),
            }
        }
    }

    #[test]
    fn commands_are_case_insensitive_and_quit_works() {
        assert!(matches!(
            handle("/EXIT", &mesh(), &geo(), true),
            CommandOutcome::Quit
        ));
        assert!(matches!(
            handle("/Help", &mesh(), &geo(), true),
            CommandOutcome::Reply(_)
        ));
    }

    #[test]
    fn status_reports_the_derived_identity() {
        let mesh = mesh();
        match handle("/status", &mesh, &geo(), false) {
            CommandOutcome::Reply(lines) => {
                assert!(lines.iter().any(|l| l.contains(&mesh.my_peer_id)));
                assert!(lines.iter().any(|l| l.contains("scanning")));
            }
            _ => panic!("expected status reply"),
        }
    }
}
