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
    main { max-width: 980px; margin: 0 auto; padding: 32px 20px 48px; }
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
    textarea { min-height: 120px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    label { display: grid; gap: 6px; color: #94a3b8; font-size: .86rem; margin-top: 12px; }
    button { margin-top: 12px; border: 0; border-radius: 999px; padding: 10px 18px; background: #38bdf8; color: #082f49; font-weight: 800; cursor: pointer; }
    button:disabled { opacity: .6; cursor: wait; }
    .list { display: grid; gap: 8px; margin-top: 8px; }
    .item { background: #020617; border: 1px solid #1e293b; border-radius: 10px; padding: 9px; word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9rem; }
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
        <div class="tag">Network screen</div>
        <h1>LibreVote Node</h1>
      </div>
      <button id="refresh">Refresh</button>
    </header>

    <div class="grid">
      <section>
        <h2>Node Status</h2>
        <dl>
          <div><dt>Peer ID</dt><dd id="peer-id">loading...</dd></div>
          <div><dt>Connected peers</dt><dd id="connected">loading...</dd></div>
          <div><dt>Listen multiaddrs</dt><dd><div id="listen" class="list"></div></dd></div>
          <div><dt>Configured bootstrap addresses</dt><dd><div id="bootstrap" class="list"></div></dd></div>
        </dl>
      </section>

      <section>
        <h2>Connect Peer</h2>
        <p class="muted">Paste one or more full bootstrap multiaddrs. Whitespace, commas, and new lines are accepted.</p>
        <textarea id="bootstrap-input" spellcheck="false" placeholder="/ip4/127.0.0.1/tcp/9000/p2p/12D3KooW..."></textarea>
        <button id="connect">Connect and refresh</button>
        <div id="message" class="message"></div>
      </section>

      <section class="span-2">
        <h2>Election</h2>
        <dl>
          <div><dt>Availability</dt><dd id="election-available">loading...</dd></div>
          <div><dt>Title</dt><dd id="election-title">loading...</dd></div>
          <div><dt>Election ID</dt><dd id="election-id">loading...</dd></div>
          <div><dt>Options</dt><dd><div id="election-options" class="list"></div></dd></div>
          <div><dt>Eligible voters</dt><dd><div id="election-voters" class="list"></div></dd></div>
          <div><dt>Local signable voters</dt><dd><div id="signable-voters" class="list"></div></dd></div>
          <div><dt>Tally key set</dt><dd id="tally-key-set">loading...</dd></div>
          <div><dt>Ballots seen</dt><dd id="ballots-seen">loading...</dd></div>
          <div><dt>Valid ballots</dt><dd id="valid-ballots">loading...</dd></div>
        </dl>
        <button id="start-election">Start Election</button>
        <div id="election-message" class="message muted"></div>
      </section>

      <section class="span-2">
        <h2>Vote</h2>
        <p id="vote-waiting" class="muted">Waiting for a local election and tally key set.</p>
        <div id="vote-form" hidden>
          <label>Voter
            <input id="voter-id" list="voter-list" placeholder="voter-1" autocomplete="off">
            <datalist id="voter-list"></datalist>
          </label>
          <label>Choice
            <select id="vote-choice"></select>
          </label>
          <button id="cast-vote">Cast Vote</button>
        </div>
        <div id="vote-message" class="message muted"></div>
      </section>
    </div>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);

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
      const status = await res.json();
      $('peer-id').textContent = status.peer_id || 'not available yet';
      $('connected').textContent = (status.connected_peer_count || 0) + ' (' + (status.connected_peer_label || 'connected peers') + ')';
      renderList('listen', status.listen_multiaddrs || []);
      renderList('bootstrap', status.bootstrap_peers || []);
      await refreshElectionStatus();
    }

    async function refreshElectionStatus() {
      const res = await fetch('/api/election/status');
      const status = await res.json();
      if (!res.ok) throw new Error(status.error || ('election status failed with ' + res.status));
      renderElectionStatus(status);
    }

    function renderElectionStatus(status) {
      $('election-available').textContent = status.available ? 'available locally' : 'not available locally';
      $('election-title').textContent = status.title || 'not available yet';
      $('election-id').textContent = status.election_id || 'not available yet';
      renderList('election-options', status.options || []);
      renderList('election-voters', status.eligible_voter_ids || status.voter_ids || []);
      renderList('signable-voters', status.voter_ids || []);
      $('tally-key-set').textContent = status.tally_key_set_available ? 'available' : 'not available';
      $('ballots-seen').textContent = String(status.ballots_seen || 0);
      $('valid-ballots').textContent = String(status.valid_ballot_count || 0);
      $('election-message').textContent = status.message || '';
      $('election-message').className = 'message ' + (status.available ? 'ok' : 'muted');
      renderVoteForm(status);
    }

    function renderVoteForm(status) {
      const voters = status.voter_ids || [];
      const ready = Boolean(status.available && status.tally_key_set_available);
      const signable = voters.length > 0;
      $('vote-waiting').hidden = ready && signable;
      $('vote-form').hidden = !ready;
      $('cast-vote').disabled = !signable;
      $('voter-id').disabled = !signable;
      $('vote-choice').disabled = !signable;
      if (!ready) {
        $('vote-waiting').textContent = status.available ? 'Waiting for a valid TallyKeySet before voting.' : 'Waiting for a local election before voting.';
        return;
      }
      if (!signable) {
        $('vote-waiting').textContent = status.message || 'Election is available, but this node has no local signing keys for eligible voters.';
      }
      const voterList = $('voter-list');
      voterList.innerHTML = '';
      for (const voter of voters) {
        const option = document.createElement('option');
        option.value = voter;
        voterList.appendChild(option);
      }
      if (!$('voter-id').value && voters.length > 0) $('voter-id').value = voters[0];

      const choices = status.options || [];
      const choiceSelect = $('vote-choice');
      const previous = choiceSelect.value;
      choiceSelect.innerHTML = '';
      for (const choice of choices) {
        const option = document.createElement('option');
        option.value = choice;
        option.textContent = choice;
        choiceSelect.appendChild(option);
      }
      if (previous && choices.includes(previous)) choiceSelect.value = previous;
    }

    function connectionDetails(body) {
      const lines = [];
      if (body.error) lines.push(body.error);
      if (body.message) lines.push(body.message);
      if (body.invalid_entries && body.invalid_entries.length) lines.push('invalid entries:\n' + body.invalid_entries.map((e) => e.entry + ': ' + e.error).join('\n'));
      if (body.failed && body.failed.length) lines.push('failed:\n' + body.failed.join('\n'));
      if (body.warnings && body.warnings.length) lines.push('warnings:\n' + body.warnings.join('\n'));
      return lines.filter(Boolean).join('\n');
    }

    async function connectPeer() {
      $('connect').disabled = true;
      $('message').className = 'message';
      $('message').textContent = 'connecting...';
      try {
        const res = await fetch('/api/network/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ bootstrap: $('bootstrap-input').value })
        });
        const body = await res.json();
        if (!res.ok) {
          throw new Error(connectionDetails(body) || ('request failed with status ' + res.status));
        }
        const lines = ['connected: ' + body.connected.length, 'connected peers now: ' + body.connected_peer_count];
        const details = connectionDetails(body);
        if (details) lines.push(details);
        $('message').className = 'message ok';
        $('message').textContent = lines.join('\n');
        await refreshStatus();
      } catch (err) {
        $('message').className = 'message bad';
        $('message').textContent = err.message;
      } finally {
        $('connect').disabled = false;
      }
    }

    async function startElection() {
      $('start-election').disabled = true;
      $('election-message').className = 'message';
      $('election-message').textContent = 'starting election...';
      try {
        const res = await fetch('/api/election/start', { method: 'POST' });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || ('start failed with status ' + res.status));
        renderElectionStatus(body);
      } catch (err) {
        $('election-message').className = 'message bad';
        $('election-message').textContent = err.message;
      } finally {
        $('start-election').disabled = false;
      }
    }

    async function castVote() {
      $('cast-vote').disabled = true;
      $('vote-message').className = 'message';
      $('vote-message').textContent = 'casting vote...';
      try {
        const res = await fetch('/api/vote/cast', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ voter_id: $('voter-id').value, choice: $('vote-choice').value })
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error || ('vote failed with status ' + res.status));
        $('vote-message').className = 'message ok';
        $('vote-message').textContent = body.message + (body.object_id ? '\nobject: ' + body.object_id : '');
        await refreshElectionStatus();
      } catch (err) {
        $('vote-message').className = 'message bad';
        $('vote-message').textContent = err.message;
      } finally {
        $('cast-vote').disabled = false;
      }
    }

    $('refresh').addEventListener('click', refreshStatus);
    $('connect').addEventListener('click', connectPeer);
    $('start-election').addEventListener('click', startElection);
    $('cast-vote').addEventListener('click', castVote);
    refreshStatus().catch((err) => { $('peer-id').textContent = err.message; });
  </script>
</body>
</html>`
