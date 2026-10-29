/**
 * ChronosHunt Frontend Controller
 * Handles DFIR case switching, chronological timeline rendering,
 * time delta calculation from initial foothold, and phase filtering.
 */

let allCases = [];
let currentCase = null;
let activePhaseFilter = 'ALL';

document.addEventListener('DOMContentLoaded', () => {
    loadMetrics();
    loadCases();
    setupEventListeners();
});

function setupEventListeners() {
    // Case dropdown change
    document.getElementById('case-select').addEventListener('change', (e) => {
        selectCase(e.target.value);
    });

    // Phase Filter Pills
    document.querySelectorAll('.pill').forEach(pill => {
        pill.addEventListener('click', (e) => {
            document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
            e.target.classList.add('active');
            activePhaseFilter = e.target.getAttribute('data-phase');
            renderTimeline();
        });
    });

    // Search bar
    document.getElementById('timeline-search').addEventListener('input', () => {
        renderTimeline();
    });

    // Export brief
    document.getElementById('btn-export-brief').addEventListener('click', () => {
        if (!currentCase) return;
        window.open(`/api/cases/${currentCase.id}/export`, '_blank');
    });

    // Reset samples
    document.getElementById('btn-reset-samples').addEventListener('click', async () => {
        try {
            const res = await fetch('/api/cases/load-samples', { method: 'POST' });
            if (res.ok) {
                showToast('Sample breach cases reloaded');
                await loadCases();
                loadMetrics();
            }
        } catch (err) {
            console.error(err);
        }
    });

    // Modal
    const modal = document.getElementById('case-modal');
    document.getElementById('btn-new-case').addEventListener('click', () => {
        modal.style.display = 'flex';
    });
    document.getElementById('modal-close').addEventListener('click', () => {
        modal.style.display = 'none';
    });
    document.getElementById('modal-cancel').addEventListener('click', () => {
        modal.style.display = 'none';
    });

    document.getElementById('modal-submit').addEventListener('click', async () => {
        const case_name = document.getElementById('new-case-name').value || 'Ad-Hoc Forensic Case';
        const threat_actor = document.getElementById('new-threat-actor').value || 'Unknown Adversary';
        const target_organization = document.getElementById('new-target-org').value || 'Enterprise Client';
        const incident_type = document.getElementById('new-incident-type').value;
        const raw_artifacts_json = document.getElementById('new-artifacts-json').value.trim();

        if (!raw_artifacts_json) {
            alert('Please provide JSON artifacts array.');
            return;
        }

        try {
            const res = await fetch('/api/cases', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    case_name,
                    threat_actor,
                    target_organization,
                    incident_type,
                    raw_artifacts_json
                })
            });

            if (res.ok) {
                const createdCase = await res.json();
                modal.style.display = 'none';
                showToast('Forensic case timeline reconstructed!');
                await loadCases();
                selectCase(createdCase.id);
                loadMetrics();
            } else {
                const errData = await res.json();
                alert(`Error: ${errData.detail || 'Could not parse artifacts'}`);
            }
        } catch (err) {
            console.error(err);
            alert('Failed submitting case telemetry');
        }
    });
}

async function loadMetrics() {
    try {
        const res = await fetch('/api/metrics');
        if (res.ok) {
            const data = await res.json();
            document.getElementById('metric-cases').textContent = data.active_cases;
            document.getElementById('metric-artifacts').textContent = data.correlated_artifacts;
            document.getElementById('metric-pivots').textContent = data.identified_adversary_pivots;
            document.getElementById('metric-dwell').textContent = data.average_adversary_dwell_time;
        }
    } catch (err) {
        console.error(err);
    }
}

async function loadCases() {
    try {
        const res = await fetch('/api/cases');
        if (res.ok) {
            allCases = await res.json();
            const selectEl = document.getElementById('case-select');
            selectEl.innerHTML = allCases.map(c => `<option value="${c.id}">${escapeHtml(c.case_name)}</option>`).join('');

            if (allCases.length > 0) {
                selectCase(allCases[0].id);
            }
        }
    } catch (err) {
        console.error(err);
    }
}

function selectCase(caseId) {
    currentCase = allCases.find(c => c.id === caseId);
    if (!currentCase) return;

    // Update Hero Banner
    document.getElementById('case-actor').textContent = currentCase.threat_actor;
    document.getElementById('case-type').textContent = currentCase.incident_type;
    document.getElementById('case-id').textContent = currentCase.id;
    document.getElementById('case-title').textContent = currentCase.case_name;
    document.getElementById('case-target').textContent = currentCase.target_organization;
    document.getElementById('case-hosts').textContent = `${currentCase.affected_hosts.length} Hosts (${currentCase.affected_hosts.join(', ')})`;
    document.getElementById('case-users').textContent = `${currentCase.compromised_accounts.length} Accounts (${currentCase.compromised_accounts.join(', ') || 'SYSTEM'})`;
    document.getElementById('case-summary').textContent = currentCase.forensic_summary;

    document.getElementById('case-dwell-display').textContent = currentCase.dwell_time_formatted;
    document.getElementById('case-window-display').textContent = `${currentCase.start_time.split('T')[1].replace('Z','')} UTC → ${currentCase.end_time.split('T')[1].replace('Z','')} UTC`;

    renderTimeline();
}

function renderTimeline() {
    const feed = document.getElementById('events-feed');
    if (!currentCase || !currentCase.timeline_events || currentCase.timeline_events.length === 0) {
        feed.innerHTML = `<div class="text-sub text-center py-4">No events found in this case timeline.</div>`;
        return;
    }

    const searchTerm = document.getElementById('timeline-search').value.toLowerCase();
    const firstEventTime = new Date(currentCase.timeline_events[0].timestamp.replace('Z', '+00:00')).getTime();

    const filtered = currentCase.timeline_events.filter(e => {
        if (activePhaseFilter !== 'ALL' && e.kill_chain_phase !== activePhaseFilter) return false;
        if (searchTerm) {
            const combined = `${e.process_name} ${e.command_line} ${e.host} ${e.user} ${e.mitre_id} ${e.mitre_name} ${e.pivot_description || ''}`.toLowerCase();
            return combined.includes(searchTerm);
        }
        return true;
    });

    if (filtered.length === 0) {
        feed.innerHTML = `<div class="text-sub text-center py-4">No events match the current filter or search criteria.</div>`;
        return;
    }

    feed.innerHTML = filtered.map(evt => {
        const evtTime = new Date(evt.timestamp.replace('Z', '+00:00')).getTime();
        const deltaSeconds = Math.max(0, Math.floor((evtTime - firstEventTime) / 1000));
        const deltaMins = Math.floor(deltaSeconds / 60);
        const deltaRemSecs = deltaSeconds % 60;
        const deltaStr = `+${deltaMins}m ${deltaRemSecs}s`;

        const isPivot = evt.is_adversary_pivot;
        const timeFormatted = evt.timestamp.replace('T', ' ').replace('Z', ' UTC');

        return `
            <div class="timeline-card ${isPivot ? 'pivot-card' : ''}">
                <div class="card-top">
                    <div class="time-badge-group">
                        <span class="timestamp-text">${timeFormatted}</span>
                        <span class="delta-badge">${deltaStr} from foothold</span>
                        <span class="badge" style="background:rgba(255,255,255,0.08); font-size:10px">${escapeHtml(evt.artifact_type)}</span>
                    </div>
                    <span class="phase-tag phase-${evt.kill_chain_phase}">${evt.kill_chain_phase.replace('_', ' ')}</span>
                </div>

                ${isPivot ? `
                    <div class="pivot-alert-banner">
                        <i class="fa-solid fa-triangle-exclamation text-red"></i>
                        <span>${escapeHtml(evt.pivot_description || 'Critical Adversary Pivot Detected')}</span>
                    </div>
                ` : ''}

                <div class="process-lineage-row">
                    ${evt.parent_process ? `
                        <span class="proc-node">${escapeHtml(evt.parent_process)}</span>
                        <span class="lineage-arrow"><i class="fa-solid fa-arrow-right"></i></span>
                    ` : ''}
                    <span class="proc-node spawned"><i class="fa-solid fa-terminal"></i> ${escapeHtml(evt.process_name || 'execution')}</span>
                    ${evt.pid ? `<span class="text-dim" style="font-size:11px">PID: ${evt.pid}</span>` : ''}
                </div>

                <div class="cmd-box">${escapeHtml(evt.command_line || 'No command arguments captured')}</div>

                <div class="card-footer-meta">
                    <div class="meta-tags-left">
                        <span><i class="fa-solid fa-desktop"></i> ${escapeHtml(evt.host)}</span>
                        <span><i class="fa-solid fa-user"></i> ${escapeHtml(evt.user)}</span>
                        ${evt.target_resource ? `<span><i class="fa-solid fa-bullseye text-cyan"></i> Target: <code>${escapeHtml(evt.target_resource)}</code></span>` : ''}
                    </div>

                    ${evt.mitre_id ? `
                        <a href="https://attack.mitre.org/techniques/${evt.mitre_id.replace('.', '/')}/" target="_blank" class="mitre-pill">
                            <i class="fa-solid fa-shield-halved"></i> ${evt.mitre_id} - ${escapeHtml(evt.mitre_name || '')}
                        </a>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function showToast(msg) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 2800);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
