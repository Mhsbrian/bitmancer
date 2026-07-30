// src/topology.rs
//
// The shape of the mesh around us.
//
// Three things this client does are currently invisible. It holds up to six BLE
// links and shows one number. It forwards other people's packets and says
// nothing. It can carry a whole channel to the internet and reports a counter.
// None of that can be checked from the outside, which is how an evening goes on
// screenshots and log archaeology. This is the instrument panel.
//
// Two facts make a real graph possible, and both are already true:
//
//   - **Hearing an announce proves a direct link.** `relay.rs` refuses to
//     forward presence, so an announce cannot have been passed along by anyone:
//     if we have it, it came off the peer's own radio. Every peer we know is a
//     neighbour, with no bookkeeping needed to establish it.
//   - **Peers gossip who *they* can see.** Upstream fills the announce's
//     `directNeighbors` TLV with its connected peer IDs, up to ten. We have
//     always parsed that field and always thrown it away. It is the only view we
//     get of the mesh past our own radio.
//
// Because announces are never relayed, we only ever hear claims from peers we
// are directly linked to — so the map has a hard depth of two: us, our
// neighbours, and the peers our neighbours name. That bound is a property of the
// protocol, not a simplification.
//
// Claims are *advisory*, which upstream says too. A peer naming a neighbour is
// making a statement, not offering proof, and nothing here treats the two alike:
// a link we observed and a link someone asserted are different kinds of edge and
// stay labelled as such.
//
// We consume this field and do not fill it, which is a constraint rather than a
// choice. An announce must stay under the 100-byte compression threshold or the
// verifier re-encodes it compressed, the bytes stop matching our signature and
// every announce we send is rejected as forged. With the three mandatory TLVs and
// a full-length nickname there are two bytes spare, and one neighbour costs ten.
// It costs this view nothing — our own links are known locally without asking
// anyone — so the only thing lost is the courtesy of appearing in *other*
// clients' maps. Emitting becomes possible if upstream turns out to sign the
// uncompressed form, which is worth reading their source for and not worth
// guessing at.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// How we came to know about a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Us.
    Ourselves,
    /// We heard their announce, which means we hold a link to them.
    Direct,
    /// Only named in a neighbour's announce. We cannot talk to them without
    /// someone in between, and we are taking that someone's word for it.
    Gossiped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub peer_id: String,
    /// Nickname where we have one; gossiped peers are usually nameless, because
    /// a name arrives with an announce and theirs never reached us.
    pub label: String,
    pub reach: Reach,
    /// 0 for us, 1 direct, 2 gossiped.
    pub hops: usize,
}

/// An edge, and whether we saw it or were told about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    /// True for our own links, which we observed. False for a claim.
    pub observed: bool,
}

#[derive(Debug, Default)]
pub struct Topology {
    us: String,
    /// Peers whose announce reached us — which is to say, our links.
    direct: BTreeSet<String>,
    /// What each peer says it can see.
    claims: BTreeMap<String, BTreeSet<String>>,
    names: BTreeMap<String, String>,
}

impl Topology {
    /// Builds the picture from what the mesh layer knows.
    ///
    /// Ordered containers throughout: this is redrawn continuously, and a graph
    /// whose nodes change position between frames because a hash iterated
    /// differently is a graph nobody can read.
    pub fn build<'a>(
        us: &str,
        peers: impl Iterator<Item = (&'a str, &'a str, &'a [String])>,
    ) -> Self {
        let mut topology = Self {
            us: us.to_string(),
            ..Default::default()
        };
        for (peer_id, nickname, claimed) in peers {
            topology.direct.insert(peer_id.to_string());
            if !nickname.is_empty() {
                topology.names.insert(peer_id.to_string(), nickname.to_string());
            }
            let mut theirs: BTreeSet<String> = claimed
                .iter()
                .map(|id| id.to_lowercase())
                .filter(|id| id != &topology.us && id != &peer_id.to_lowercase())
                .collect();
            // A peer claiming us is true and uninteresting — we already know,
            // and drawing it would double every spoke.
            theirs.remove(&topology.us);
            topology.claims.insert(peer_id.to_string(), theirs);
        }
        topology
    }

    /// Every node, ourselves first, then by hop distance and name.
    pub fn nodes(&self) -> Vec<Node> {
        let mut nodes = vec![Node {
            peer_id: self.us.clone(),
            label: "you".to_string(),
            reach: Reach::Ourselves,
            hops: 0,
        }];

        for peer_id in &self.direct {
            nodes.push(Node {
                peer_id: peer_id.clone(),
                label: self.label_for(peer_id),
                reach: Reach::Direct,
                hops: 1,
            });
        }

        for peer_id in self.gossiped() {
            nodes.push(Node {
                label: self.label_for(&peer_id),
                peer_id,
                reach: Reach::Gossiped,
                hops: 2,
            });
        }
        nodes
    }

    /// Peers named by a neighbour that we cannot hear ourselves.
    pub fn gossiped(&self) -> BTreeSet<String> {
        self.claims
            .values()
            .flatten()
            .filter(|id| !self.direct.contains(*id))
            .cloned()
            .collect()
    }

    /// Every edge: our links first, then the claims.
    pub fn edges(&self) -> Vec<Edge> {
        let mut edges: Vec<Edge> = self
            .direct
            .iter()
            .map(|peer_id| Edge {
                from: self.us.clone(),
                to: peer_id.clone(),
                observed: true,
            })
            .collect();

        // Claims are undirected in effect — if A says it sees B, that is one
        // edge however many times it is said — so they are collapsed onto a
        // sorted pair to keep one line per relationship.
        let mut claimed: BTreeSet<(String, String)> = BTreeSet::new();
        for (peer_id, theirs) in &self.claims {
            for other in theirs {
                let pair = if peer_id < other {
                    (peer_id.clone(), other.clone())
                } else {
                    (other.clone(), peer_id.clone())
                };
                claimed.insert(pair);
            }
        }
        edges.extend(claimed.into_iter().map(|(from, to)| Edge {
            from,
            to,
            observed: false,
        }));
        edges
    }

    /// The groups of peers that could still reach each other if we vanished.
    ///
    /// More than one means we are the only thing joining them: the moment when
    /// holding several links stops being a statistic and starts being the reason
    /// two people can talk. Computed on claims alone, because a path that runs
    /// through us is exactly what is being excluded.
    pub fn islands_without_us(&self) -> Vec<BTreeSet<String>> {
        let mut adjacency: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut everyone: BTreeSet<String> = self.direct.clone();
        everyone.extend(self.gossiped());

        for (peer_id, theirs) in &self.claims {
            for other in theirs {
                adjacency
                    .entry(peer_id.clone())
                    .or_default()
                    .insert(other.clone());
                adjacency
                    .entry(other.clone())
                    .or_default()
                    .insert(peer_id.clone());
            }
        }

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut islands = Vec::new();
        for start in &everyone {
            if seen.contains(start) {
                continue;
            }
            let mut island = BTreeSet::new();
            let mut queue = VecDeque::from([start.clone()]);
            while let Some(current) = queue.pop_front() {
                if !seen.insert(current.clone()) {
                    continue;
                }
                island.insert(current.clone());
                for next in adjacency.get(&current).into_iter().flatten() {
                    if !seen.contains(next) {
                        queue.push_back(next.clone());
                    }
                }
            }
            islands.push(island);
        }
        islands
    }

    /// Whether we are the only path between two parts of the mesh.
    pub fn we_are_a_bridge(&self) -> bool {
        self.islands_without_us().len() > 1
    }

    /// Where to draw everything, on a unit-ish plane with us at the origin.
    ///
    /// Rings by hop distance, because that is the one thing about a mesh worth
    /// seeing at a glance: who we can reach ourselves, and who we can only reach
    /// through somebody. A gossiped peer is placed near the neighbour that named
    /// it rather than anywhere on its ring, so the claim is legible as a claim by
    /// *that* peer — otherwise the outer ring is a row of strangers with lines
    /// crossing the middle to find them.
    pub fn layout(&self) -> BTreeMap<String, (f64, f64)> {
        let mut places = BTreeMap::new();
        places.insert(self.us.clone(), (0.0, 0.0));

        let direct: Vec<&String> = self.direct.iter().collect();
        let spokes = direct.len().max(1) as f64;
        for (index, peer_id) in direct.iter().enumerate() {
            // Start at twelve o'clock and go clockwise, so a single peer sits
            // above us rather than off to one side.
            let angle = std::f64::consts::FRAC_PI_2 - (index as f64 / spokes) * std::f64::consts::TAU;
            places.insert((*peer_id).clone(), (angle.cos(), angle.sin()));
        }

        // Each neighbour's claims fan out beyond it, within a wedge narrow
        // enough that they read as belonging to that neighbour.
        const WEDGE: f64 = 0.55;
        for (peer_id, theirs) in &self.claims {
            let Some(&(anchor_x, anchor_y)) = places.get(peer_id) else {
                continue;
            };
            let outward = anchor_y.atan2(anchor_x);
            let unseen: Vec<&String> = theirs
                .iter()
                .filter(|id| !self.direct.contains(*id))
                .collect();
            let spread = unseen.len().max(1) as f64;
            for (index, other) in unseen.iter().enumerate() {
                // Centred on the neighbour's own bearing: one claim sits
                // directly beyond it, several fan evenly either side.
                let offset = (index as f64 + 0.5) / spread - 0.5;
                let angle = outward + offset * WEDGE;
                places
                    .entry((*other).clone())
                    .or_insert((angle.cos() * 2.0, angle.sin() * 2.0));
            }
        }
        places
    }

    fn label_for(&self, peer_id: &str) -> String {
        self.names
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| crate::peer_id::short_display(peer_id))
    }

    pub fn direct_count(&self) -> usize {
        self.direct.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: &str = "0000000000000000";

    /// A peer and the neighbours it claims.
    fn peer(id: &str, name: &str, claims: &[&str]) -> (String, String, Vec<String>) {
        (
            id.to_string(),
            name.to_string(),
            claims.iter().map(|c| c.to_string()).collect(),
        )
    }

    fn build(peers: &[(String, String, Vec<String>)]) -> Topology {
        Topology::build(
            US,
            peers
                .iter()
                .map(|(id, name, claims)| (id.as_str(), name.as_str(), claims.as_slice())),
        )
    }

    #[test]
    fn hearing_an_announce_is_proof_of_a_link() {
        // The invariant the whole model rests on: relay.rs refuses to forward
        // presence, so an announce cannot have been passed along. Every peer we
        // know of is therefore one we can reach directly.
        let peers = [peer("aa11bb22cc33dd44", "bob", &[])];
        let topology = build(&peers);
        let nodes = topology.nodes();
        assert_eq!(nodes[0].reach, Reach::Ourselves);
        assert_eq!(nodes[1].reach, Reach::Direct);
        assert_eq!(nodes[1].hops, 1);
        assert_eq!(nodes[1].label, "bob");
    }

    #[test]
    fn a_neighbours_neighbour_is_two_hops_out() {
        // The only view we get past our own radio, and it comes free in a field
        // we were already parsing and discarding.
        let peers = [peer("aa11bb22cc33dd44", "bob", &["ff99ee88dd77cc66"])];
        let topology = build(&peers);

        let nodes = topology.nodes();
        let gossiped: Vec<&Node> = nodes
            .iter()
            .filter(|node| node.reach == Reach::Gossiped)
            .collect();
        assert_eq!(gossiped.len(), 1);
        assert_eq!(gossiped[0].peer_id, "ff99ee88dd77cc66");
        assert_eq!(gossiped[0].hops, 2);
    }

    #[test]
    fn a_peer_we_can_hear_is_never_listed_as_gossip() {
        // Two neighbours who can see each other must appear once each, as
        // direct. Counting them twice would inflate the mesh.
        let peers = [
            peer("aa11bb22cc33dd44", "bob", &["bb22cc33dd44ee55"]),
            peer("bb22cc33dd44ee55", "carol", &["aa11bb22cc33dd44"]),
        ];
        let topology = build(&peers);
        assert!(topology.gossiped().is_empty());
        assert_eq!(topology.nodes().len(), 3, "us and two neighbours");
    }

    #[test]
    fn a_peer_claiming_us_is_not_drawn_twice() {
        // True, and uninteresting: we already know we can hear them.
        let peers = [peer("aa11bb22cc33dd44", "bob", &[US])];
        let topology = build(&peers);
        assert!(topology.gossiped().is_empty());
        let edges = topology.edges();
        let claimed: Vec<&Edge> = edges.iter().filter(|edge| !edge.observed).collect();
        assert!(claimed.is_empty(), "our own spoke is already an observed edge");
    }

    #[test]
    fn a_peer_claiming_itself_is_ignored() {
        let peers = [peer("aa11bb22cc33dd44", "bob", &["AA11BB22CC33DD44"])];
        let topology = build(&peers);
        assert!(topology.gossiped().is_empty());
    }

    #[test]
    fn observed_and_claimed_edges_are_kept_apart() {
        // A link we saw and a link someone asserted are different kinds of
        // knowledge. Upstream calls claims advisory; drawing them identically
        // would present hearsay as measurement.
        let peers = [peer("aa11bb22cc33dd44", "bob", &["ff99ee88dd77cc66"])];
        let topology = build(&peers);
        let edges = topology.edges();

        let ours: Vec<&Edge> = edges.iter().filter(|edge| edge.observed).collect();
        assert_eq!(ours.len(), 1);
        assert_eq!(ours[0].from, US);

        let theirs: Vec<&Edge> = edges.iter().filter(|edge| !edge.observed).collect();
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].to, "ff99ee88dd77cc66");
    }

    #[test]
    fn one_relationship_is_one_edge_however_often_it_is_claimed() {
        let peers = [
            peer("aa11bb22cc33dd44", "bob", &["ff99ee88dd77cc66"]),
            peer("bb22cc33dd44ee55", "carol", &["ff99ee88dd77cc66"]),
        ];
        let topology = build(&peers);
        let claimed = topology.edges().into_iter().filter(|edge| !edge.observed).count();
        assert_eq!(claimed, 2, "two different peers, two different relationships");

        // But the same relationship asserted from both ends is still one line.
        let mutual = [
            peer("aa11bb22cc33dd44", "bob", &["bb22cc33dd44ee55"]),
            peer("bb22cc33dd44ee55", "carol", &["aa11bb22cc33dd44"]),
        ];
        let topology = build(&mutual);
        let claimed = topology.edges().into_iter().filter(|edge| !edge.observed).count();
        assert_eq!(claimed, 1);
    }

    #[test]
    fn we_are_a_bridge_when_nothing_else_joins_two_groups() {
        // The moment holding several links stops being a statistic. Bob and
        // Carol are both ours, and neither can see the other.
        let peers = [
            peer("aa11bb22cc33dd44", "bob", &[]),
            peer("bb22cc33dd44ee55", "carol", &[]),
        ];
        let topology = build(&peers);
        assert!(topology.we_are_a_bridge());
        assert_eq!(topology.islands_without_us().len(), 2);
    }

    #[test]
    fn we_are_not_a_bridge_when_the_mesh_holds_without_us() {
        let peers = [
            peer("aa11bb22cc33dd44", "bob", &["bb22cc33dd44ee55"]),
            peer("bb22cc33dd44ee55", "carol", &["aa11bb22cc33dd44"]),
        ];
        let topology = build(&peers);
        assert!(!topology.we_are_a_bridge(), "they can reach each other directly");
        assert_eq!(topology.islands_without_us().len(), 1);
    }

    #[test]
    fn a_lone_peer_is_not_a_bridge() {
        // One neighbour cannot be cut off from anyone.
        let peers = [peer("aa11bb22cc33dd44", "bob", &[])];
        let topology = build(&peers);
        assert!(!topology.we_are_a_bridge());
    }

    #[test]
    fn an_empty_mesh_is_just_us() {
        let topology = build(&[]);
        assert_eq!(topology.nodes().len(), 1);
        assert!(topology.edges().is_empty());
        assert!(!topology.we_are_a_bridge());
        assert_eq!(topology.direct_count(), 0);
    }

    #[test]
    fn a_chain_through_us_is_two_islands() {
        // Bob sees Dave, Carol sees Erin, and nobody joins the two pairs except
        // us. Four peers, two islands, one bridge.
        let peers = [
            peer("aa11bb22cc33dd44", "bob", &["dd44ee55ff66aa11"]),
            peer("bb22cc33dd44ee55", "carol", &["ee55ff66aa11bb22"]),
        ];
        let topology = build(&peers);
        let islands = topology.islands_without_us();
        assert_eq!(islands.len(), 2);
        assert!(topology.we_are_a_bridge());
        assert!(islands.iter().all(|island| island.len() == 2));
    }

    #[test]
    fn everything_gets_a_place_and_we_are_the_origin() {
        let peers = [
            peer("aa11bb22cc33dd44", "bob", &["ff99ee88dd77cc66"]),
            peer("bb22cc33dd44ee55", "carol", &[]),
        ];
        let topology = build(&peers);
        let places = topology.layout();

        assert_eq!(places.get(US), Some(&(0.0, 0.0)));
        for node in topology.nodes() {
            assert!(
                places.contains_key(&node.peer_id),
                "{} has nowhere to be drawn",
                node.peer_id
            );
        }
    }

    #[test]
    fn rings_are_by_hop_distance() {
        // The one thing worth seeing at a glance: who we can reach ourselves,
        // and who we can only reach through somebody.
        let peers = [peer("aa11bb22cc33dd44", "bob", &["ff99ee88dd77cc66"])];
        let topology = build(&peers);
        let places = topology.layout();

        let radius = |peer_id: &str| {
            let (x, y) = places[peer_id];
            (x * x + y * y).sqrt()
        };
        assert!((radius("aa11bb22cc33dd44") - 1.0).abs() < 0.001, "direct on the inner ring");
        assert!((radius("ff99ee88dd77cc66") - 2.0).abs() < 0.001, "gossiped further out");
    }

    #[test]
    fn a_lone_neighbour_sits_above_us() {
        // Rather than off to one side, which reads as though something is
        // missing from the other half of the picture.
        let peers = [peer("aa11bb22cc33dd44", "bob", &[])];
        let places = build(&peers).layout();
        let (x, y) = places["aa11bb22cc33dd44"];
        assert!(x.abs() < 0.001, "centred horizontally, got x={x}");
        assert!(y > 0.9, "and above, got y={y}");
    }

    #[test]
    fn neighbours_do_not_sit_on_top_of_each_other() {
        let peers: Vec<_> = ["aa11", "bb22", "cc33", "dd44", "ee55", "ff66"]
            .iter()
            .map(|id| peer(&format!("{id}00000000cccc"), id, &[]))
            .collect();
        let places = build(&peers).layout();
        let spots: Vec<(f64, f64)> = peers
            .iter()
            .map(|(id, _, _)| places[id])
            .collect();
        for (index, first) in spots.iter().enumerate() {
            for second in &spots[index + 1..] {
                let apart = ((first.0 - second.0).powi(2) + (first.1 - second.1).powi(2)).sqrt();
                assert!(apart > 0.4, "two peers drawn {apart} apart");
            }
        }
    }

    #[test]
    fn a_claim_is_drawn_beyond_the_peer_that_made_it() {
        // Otherwise the outer ring is a row of strangers with lines crossing the
        // middle of the picture to reach them.
        let peers = [
            peer("aa11bb22cc33dd44", "bob", &["ff99ee88dd77cc66"]),
            peer("bb22cc33dd44ee55", "carol", &["1122334455667788"]),
        ];
        let places = build(&peers).layout();

        let bearing = |peer_id: &str| {
            let (x, y) = places[peer_id];
            y.atan2(x)
        };
        let gap = |a: &str, b: &str| {
            let difference = (bearing(a) - bearing(b)).abs();
            difference.min(std::f64::consts::TAU - difference)
        };
        assert!(
            gap("ff99ee88dd77cc66", "aa11bb22cc33dd44") < 0.4,
            "bob's claim should sit beyond bob"
        );
        assert!(
            gap("1122334455667788", "bb22cc33dd44ee55") < 0.4,
            "carol's claim should sit beyond carol"
        );
    }

    #[test]
    fn the_picture_is_the_same_every_time_it_is_drawn() {
        // Redrawn continuously. A graph whose nodes move between frames because
        // a hash iterated differently cannot be read, let alone trusted.
        let peers = [
            peer("ff99ee88dd77cc66", "zed", &["aa11bb22cc33dd44"]),
            peer("aa11bb22cc33dd44", "bob", &["cc33dd44ee55ff66"]),
            peer("bb22cc33dd44ee55", "carol", &[]),
        ];
        let first = build(&peers);
        let again = build(&peers);
        assert_eq!(first.nodes(), again.nodes());
        assert_eq!(first.edges(), again.edges());
        assert_eq!(first.islands_without_us(), again.islands_without_us());
        assert_eq!(first.layout(), again.layout());
    }

    #[test]
    fn a_nameless_peer_is_shown_by_its_id() {
        // A gossiped peer usually has no name: a nickname arrives with an
        // announce, and theirs never reached us.
        let peers = [peer("aa11bb22cc33dd44", "", &["ff99ee88dd77cc66"])];
        let topology = build(&peers);
        for node in topology.nodes().iter().filter(|n| n.reach != Reach::Ourselves) {
            assert!(!node.label.is_empty(), "every node needs something to draw");
        }
    }
}
