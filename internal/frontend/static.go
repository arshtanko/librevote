package frontend

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LibreVote Node</title>
  <style>
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #0f172a; color: #e2e8f0; }
    main { max-width: 1040px; margin: 0 auto; padding: 32px 20px 48px; }
    header { display: flex; gap: 16px; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #334155; padding-bottom: 24px; }
    h1 { margin: 0; font-size: clamp(2rem, 6vw, 4rem); line-height: .95; letter-spacing: -0.05em; }
    .tag { margin-top: 8px; color: #93c5fd; font-weight: 700; text-transform: uppercase; letter-spacing: .14em; font-size: .8rem; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-top: 24px; }
    section { background: #111827; border: 1px solid #334155; border-radius: 18px; padding: 20px; box-shadow: 0 18px 60px rgb(0 0 0 / .22); }
    h2 { margin: 0 0 14px; font-size: 1rem; color: #bfdbfe; }
    dl { margin: 0; display: grid; gap: 14px; }
    dt { color: #94a3b8; font-size: .82rem; }
    dd { margin: 3px 0 0; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    textarea, input, select { width: 100%; box-sizing: border-box; border-radius: 12px; border: 1px solid #475569; background: #020617; color: #e2e8f0; padding: 12px; font: inherit; }
    textarea { min-height: 110px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    label { display: grid; gap: 6px; color: #94a3b8; font-size: .86rem; margin-top: 12px; }
    label.inline { display: flex; align-items: center; gap: 8px; }
    input[type="checkbox"] { width: auto; }
    button { margin-top: 12px; border: 0; border-radius: 999px; padding: 10px 18px; background: #38bdf8; color: #082f49; font-weight: 800; cursor: pointer; }
    button:disabled { opacity: .6; cursor: wait; }
    .list { display: grid; gap: 8px; margin-top: 8px; }
    .item { background: #020617; border: 1px solid #1e293b; border-radius: 10px; padding: 9px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9rem; }
    .peer-row { display: flex; gap: 8px; align-items: flex-start; background: #020617; border: 1px solid #1e293b; border-radius: 10px; padding: 9px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9rem; }
    .invite-card { background: #020617; border: 1px solid #1e293b; border-radius: 10px; padding: 12px; margin-bottom: 8px; }
    .invite-card h3 { margin: 0 0 6px; color: #bfdbfe; font-size: .95rem; }
    .invite-card p { margin: 0 0 8px; color: #94a3b8; font-size: .82rem; }
    .invite-card .peers { font-size: .8rem; color: #64748b; margin: 4px 0; }
    .span-2 { grid-column: 1 / -1; }
    .muted { color: #94a3b8; }
    .message { margin-top: 12px; white-space: pre-wrap; }
    .ok { color: #86efac; }
    .bad { color: #fca5a5; }
    @media (max-width: 760px) { header { display: block; } .grid { grid-template-columns: 1fr; } main { padding-top: 22px; } }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <div class="tag">Equal peer node</div>
        <h1>LibreVote Node</h1>
      </div>
      <button id="refresh">Refresh</button>
    </header>

    <div class="grid">
      <section>
        <h2>Network</h2>
        <dl>
          <div><dt>Peer ID</dt><dd id="peer-id">loading...</dd></div>
          <div><dt>Connected peers</dt><dd id="connected">loading...</dd></div>
          <div><dt>Active peer IDs</dt><dd><div id="active-peers" class="list"></div></dd></div>
          <div><dt>Listen multiaddrs</dt><dd><div id="listen" class="list"></div></dd></div>
          <div><dt>Configured bootstrap addresses</dt><dd><div id="bootstrap" class="list"></div></dd></div>
        </dl>
      </section>

      <section>
        <h2>Connect Peer</h2>
        <p class="muted">Connect to the P2P mesh first. Paste one or more full bootstrap multiaddrs.</p>
        <textarea id="bootstrap-input" spellcheck="false" placeholder="/ip4/127.0.0.1/tcp/9000/p2p/12D3KooW..."></textarea>
        <button id="connect">Connect and refresh</button>
        <div id="message" class="message"></div>
      </section>

      <section class="span-2" id="create-section">
        <h2>Create Election Invitation</h2>
        <p class="muted">Connect to peers first. Only invited peers become voters. Any invited peer may finalize after all acceptances sync.</p>
        <label>Title<input id="invite-title" value="LibreVote Election"></label>
        <label>Options, one per line<textarea id="invite-options">yes
no</textarea></label>
        <label class="inline"><input id="include-self" type="checkbox"> Include self as accepted voter</label>
        <div><dt class="muted">Select connected peers to invite</dt><div id="peer-picker" class="list"></div></div>
        <button id="create-invite">Create Invitation</button>
        <div id="invite-message" class="message"></div>
      </section>

      <section class="span-2">
        <h2>Invitations</h2>
        <div id="invitations" class="list"></div>
      </section>

      <section class="span-2">
        <h2>Election Status</h2>
        <dl>
          <div><dt>Status</dt><dd id="election-available">loading...</dd></div>
          <div><dt>Title</dt><dd id="election-title">loading...</dd></div>
          <div><dt>Election ID</dt><dd id="election-id">loading...</dd></div>
          <div><dt>Options</dt><dd><div id="election-options" class="list"></div></dd></div>
          <div><dt>Accepted voter allowlist</dt><dd><div id="election-voters" class="list"></div></dd></div>
          <div><dt>This node voting status</dt><dd id="local-voter">loading...</dd></div>
          <div><dt>Tally key set</dt><dd id="tally-key-set">loading...</dd></div>
          <div><dt>Valid ballots</dt><dd id="valid-ballots">loading...</dd></div>
        </dl>
        <div id="election-message" class="message muted"></div>
      </section>

      <section class="span-2">
        <h2>Vote</h2>
        <p id="vote-waiting" class="muted">Voting unlocks only after an invitation is accepted and finalized.</p>
        <div id="vote-form" hidden>
          <label>Choice<select id="vote-choice"></select></label>
          <button id="cast-vote">Cast Vote</button>
        </div>
        <div id="vote-message" class="message muted"></div>
      </section>
    </div>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    let networkStatus = {};
    let electionStatus = {};

    function renderList(id, items) {
      const el = $(id);
      el.innerHTML = '';
      if (!items || items.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.textContent = 'none reported';
        el.appendChild(empty);
        return;
      }
      for (const item of items) {
        const div = document.createElement('div');
        div.className = 'item';
        div.textContent = item;
        el.appendChild(div);
      }
    }

    async function refreshStatus() {
      const res = await fetch('/api/network/status');
      networkStatus = await res.json();
      $('peer-id').textContent = networkStatus.peer_id || 'not available yet';
      $('connected').textContent = (networkStatus.connected_peer_count || 0) + ' connected';
      renderList('active-peers', networkStatus.connected_peer_ids || []);
      renderList('listen', networkStatus.listen_multiaddrs || []);
      renderList('bootstrap', networkStatus.bootstrap_peers || []);
      renderPeerPicker(networkStatus.connected_peer_ids || []);
      await refreshElectionStatus();
    }

    async function refreshElectionStatus() {
      const res = await fetch('/api/elections/status');
      electionStatus = await res.json();
      if (!res.ok) throw new Error(electionStatus.error || ('election status failed with ' + res.status));
      renderElectionStatus(electionStatus);
      renderInvitations(electionStatus.invitations || [], electionStatus.pending_invitations || []);
    }

    function renderPeerPicker(peers) {
      const el = $('peer-picker');
      el.innerHTML = '';
      if (!peers.length) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.textContent = 'No connected peers.';
        el.appendChild(empty);
        return;
      }
      for (const peer of peers) {
        const label = document.createElement('label');
        label.className = 'peer-row';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.value = peer;
        input.id = 'peer-' + peer;
        label.append(input, document.createTextNode(peer));
        el.appendChild(label);
      }
    }

    function renderElectionStatus(status) {
      $('create-section').hidden = Boolean(status.available);
      $('election-available').textContent = status.available ? 'finalized locally' : 'not finalized locally';
      $('election-title').textContent = status.title || 'not available yet';
      $('election-id').textContent = status.election_id || 'not available yet';
      renderList('election-options', status.available ? (status.options || []) : []);
      renderList('election-voters', status.available ? (status.eligible_voter_ids || []) : []);
      if (!status.available) {
        $('local-voter').textContent = 'Accept an invitation, then wait for finalize.';
      } else if (status.local_voter_id) {
        $('local-voter').textContent = status.local_voter_signable ? ('Eligible: ' + status.local_voter_id) : ('Not in voter set: ' + status.local_voter_id);
      } else {
        $('local-voter').textContent = 'Local peer ID is not available.';
      }
      $('tally-key-set').textContent = status.tally_key_set_available ? 'available' : 'not available';
      $('valid-ballots').textContent = String(status.valid_ballot_count || 0);
      $('election-message').textContent = status.message || '';
      $('election-message').className = 'message ' + (status.available ? 'ok' : 'muted');
      renderVoteForm(status);
    }

    function renderInvitations(invitations, pending) {
      const el = $('invitations');
      el.innerHTML = '';
      const seen = new Set();
      const all = [...invitations, ...pending].filter(invite => {
        if (seen.has(invite.election_id)) return false;
        seen.add(invite.election_id);
        return true;
      });
      if (!all.length) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.textContent = 'No invitations have synced locally.';
        el.appendChild(empty);
        return;
      }
      for (const invite of all) {
        const card = document.createElement('div');
        card.className = 'invite-card';

        const h3 = document.createElement('h3');
        h3.textContent = invite.title + (invite.finalized ? ' [FINALIZED]' : invite.local_accepted ? ' [ACCEPTED]' : invite.local_declined ? ' [DECLINED]' : invite.local_invited ? ' [PENDING ACCEPT]' : '');
        card.appendChild(h3);

        const idP = document.createElement('p');
        idP.textContent = 'ID: ' + invite.election_id + ' | Creator: ' + invite.creator_peer_id;
        card.appendChild(idP);

        const peersP = document.createElement('p');
        peersP.className = 'peers';
        peersP.textContent = 'Invited: ' + (invite.invited_peer_ids || []).join(', ') + ' | Accepted: ' + (invite.accepted_peer_ids || []).join(', ') + ' | Declined: ' + (invite.declined_peer_ids || []).join(', ');
        card.appendChild(peersP);

        if (invite.local_invited && !invite.local_accepted && !invite.local_declined && !invite.finalized) {
          const acceptBtn = document.createElement('button');
          acceptBtn.textContent = 'Accept Invitation';
          acceptBtn.onclick = () => acceptInvitation(invite.election_id);
          card.appendChild(acceptBtn);

          const declineBtn = document.createElement('button');
          declineBtn.textContent = 'Decline';
          declineBtn.style.marginLeft = '8px';
          declineBtn.onclick = () => declineInvitation(invite.election_id);
          card.appendChild(declineBtn);
        }

        const isCreator = networkStatus.peer_id === invite.creator_peer_id;
        if (!invite.finalized && isCreator && (invite.accepted_peer_ids || []).length > 0) {
          const btn = document.createElement('button');
          btn.textContent = 'Finalize Election';
          btn.onclick = () => finalizeElection(invite.election_id);
          card.appendChild(btn);
        }

        el.appendChild(card);
      }
    }

    function renderVoteForm(status) {
      const ready = Boolean(status.available && status.tally_key_set_available);
      const configured = Boolean(status.local_voter_id);
      const signable = Boolean(status.local_voter_signable);
      const voted = Boolean(status.local_voter_voted);
      $('vote-waiting').hidden = ready && configured && signable && !voted;
      $('vote-form').hidden = !ready || !configured || !signable || voted;
      if (!ready) return $('vote-waiting').textContent = status.available ? 'Waiting for TallyKeySet.' : 'Waiting for accepted voters to be finalized.';
      if (!configured) return $('vote-waiting').textContent = 'Local peer ID is not available.';
      if (!signable) return $('vote-waiting').textContent = 'This node is not in the accepted voter set.';
      if (voted) return $('vote-waiting').textContent = 'Vote already cast.';
      const select = $('vote-choice');
      select.innerHTML = '';
      for (const opt of (status.options || [])) {
        const o = document.createElement('option');
        o.value = opt;
        o.textContent = opt;
        select.appendChild(o);
      }
    }

    async function acceptInvitation(electionID) {
      const res = await fetch('/api/elections/accept', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({election_id: electionID})
      });
      if (!res.ok) {
        const err = await res.json();
        alert('Accept failed: ' + err.error);
        return;
      }
      await refreshElectionStatus();
    }

    async function declineInvitation(electionID) {
      const res = await fetch('/api/elections/decline', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({election_id: electionID})
      });
      if (!res.ok) {
        const err = await res.json();
        alert('Decline failed: ' + err.error);
        return;
      }
      await refreshElectionStatus();
    }

    async function finalizeElection(electionID) {
      const res = await fetch('/api/elections/finalize', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({election_id: electionID})
      });
      if (!res.ok) {
        const err = await res.json();
        alert('Finalize failed: ' + err.error);
        return;
      }
      await refreshElectionStatus();
    }

    $('refresh').onclick = () => refreshStatus();

    $('connect').onclick = async () => {
      const input = $('bootstrap-input').value.trim();
      if (!input) return;
      $('connect').disabled = true;
      $('message').textContent = '';
      $('message').className = 'message';
      try {
        const addrs = input.split('\n').map(s => s.trim()).filter(Boolean);
        const res = await fetch('/api/network/connect', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({bootstrap_multiaddrs: addrs})
        });
        const data = await res.json();
        if (data.error) {
          $('message').textContent = 'Error: ' + data.error;
          $('message').className = 'message bad';
        } else {
          const connected = (data.connected || []).length;
          const failed = (data.failed || []).length;
          $('message').textContent = 'Connected: ' + connected + ', Failed: ' + failed + (data.warnings && data.warnings.length ? '\n' + data.warnings.join('\n') : '');
          $('message').className = 'message ' + (failed === 0 && !data.warnings?.length ? 'ok' : 'muted');
        }
      } catch(e) {
        $('message').textContent = 'Error: ' + e.message;
        $('message').className = 'message bad';
      } finally {
        $('connect').disabled = false;
        await refreshStatus();
      }
    };

    $('create-invite').onclick = async () => {
      const title = $('invite-title').value.trim();
      const optionsText = $('invite-options').value.trim();
      const options = optionsText ? optionsText.split('\n').map(s => s.trim()).filter(Boolean) : [];
      const includeSelf = $('include-self').checked;
      const selectedPeers = [];
      document.querySelectorAll('#peer-picker input[type="checkbox"]:checked').forEach(cb => {
        selectedPeers.push(cb.value);
      });
      if (!title) { alert('Title is required'); return; }
      if (options.length < 2) { alert('At least two options are required'); return; }
      if (selectedPeers.length === 0 && !includeSelf) { alert('Select at least one peer to invite or check include-self'); return; }
      $('create-invite').disabled = true;
      $('invite-message').textContent = '';
      try {
        const res = await fetch('/api/elections/invite', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({title, options, invited_peer_ids: selectedPeers, include_self: includeSelf})
        });
        const data = await res.json();
        if (!res.ok) {
          $('invite-message').textContent = 'Error: ' + data.error;
          $('invite-message').className = 'message bad';
        } else {
          $('invite-message').textContent = 'Invitation created for: ' + data.election_id;
          $('invite-message').className = 'message ok';
          await refreshElectionStatus();
        }
      } catch(e) {
        $('invite-message').textContent = 'Error: ' + e.message;
        $('invite-message').className = 'message bad';
      } finally {
        $('create-invite').disabled = false;
      }
    };

    $('cast-vote').onclick = async () => {
      const choice = $('vote-choice').value;
      if (!choice) return;
      $('cast-vote').disabled = true;
      $('vote-message').textContent = '';
      try {
        const res = await fetch('/api/vote/cast', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({choice})
        });
        const data = await res.json();
        if (!res.ok) {
          $('vote-message').textContent = 'Error: ' + data.error;
          $('vote-message').className = 'message bad';
        } else {
          $('vote-message').textContent = 'Vote cast: ' + data.choice + ' (status: ' + data.status + ')';
          $('vote-message').className = 'message ok';
          await refreshElectionStatus();
        }
      } catch(e) {
        $('vote-message').textContent = 'Error: ' + e.message;
        $('vote-message').className = 'message bad';
      } finally {
        $('cast-vote').disabled = false;
      }
    };

    refreshStatus();
  </script>
</body>
</html>`
