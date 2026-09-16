const assert = require("assert");

class RolloutFrontendSimulator {
    constructor() {
        this.currentRolloutRelease = { id: 1, version: "1.5.0", release_channel: "stable", rollout_scope: "global" };
        this.lastRolloutSnapshot = null;
        this.rolloutRequestInFlight = false;
        this.rolloutRequestSeq = 0;
        this.renderedKPIs = null;
        this.renderedDevices = null;
        this.transientAlertShown = false;
        this.requestLog = [];
    }

    validarSchemaRollout(data) {
        if (!data || typeof data !== "object" || data.success !== true) return false;
        const summary = data.summary || data.counts;
        if (!summary || typeof summary !== "object") return false;
        if (!Array.isArray(data.devices)) return false;
        const up = summary.updated_count ?? summary.updated;
        const pend = summary.pending_count ?? summary.pending_update;
        if (typeof up !== "number" || typeof pend !== "number") return false;
        return true;
    }

    tratarErroRollout(status, detalhe = "") {
        this.transientAlertShown = true;
    }

    removerAvisoErroRollout() {
        this.transientAlertShown = false;
    }

    renderizarRollout(data) {
        const summary = data.summary || data.counts || {};
        const updated = summary.updated_count ?? summary.updated ?? 0;
        const pending = summary.pending_count ?? summary.pending_update ?? 0;
        const offline = summary.offline_count ?? summary.offline ?? 0;
        const notTargeted = summary.not_targeted_count ?? summary.not_targeted ?? 0;
        const onlineEligible = summary.online_eligible_count ?? (updated + pending);
        const total = summary.total_devices ?? (updated + pending + offline + notTargeted);
        const progressPct = summary.progress_percent ?? summary.progress_pct ?? (onlineEligible > 0 ? Number(((updated / onlineEligible) * 100).toFixed(1)) : 0.0);

        this.renderedKPIs = {
            updated,
            pending,
            offline,
            notTargeted,
            onlineEligible,
            total,
            progressPct,
            summaryText: `${updated} / ${onlineEligible} computadores online (${progressPct}%)`
        };

        const devices = [...(data.devices || [])];
        devices.sort((a, b) => {
            const deptA = (a.department || "").toLowerCase();
            const deptB = (b.department || "").toLowerCase();
            if (deptA !== deptB) return deptA.localeCompare(deptB, "pt-BR");

            const nameA = (a.display_name || a.hostname || "").toLowerCase();
            const nameB = (b.display_name || b.hostname || "").toLowerCase();
            if (nameA !== nameB) return nameA.localeCompare(nameB, "pt-BR");

            const hostA = (a.hostname || "").toLowerCase();
            const hostB = (b.hostname || "").toLowerCase();
            if (hostA !== hostB) return hostA.localeCompare(hostB, "pt-BR");

            return (a.id || 0) - (b.id || 0);
        });
        this.renderedDevices = devices;
    }

    async carregarProgressoRollout(releaseId, mockFetch) {
        if (!releaseId) return;
        if (this.rolloutRequestInFlight) {
            this.requestLog.push(`blocked_in_flight_seq_${this.rolloutRequestSeq}`);
            return;
        }
        this.rolloutRequestInFlight = true;
        const seq = ++this.rolloutRequestSeq;
        this.requestLog.push(`start_seq_${seq}`);

        try {
            const resp = await mockFetch(`/api/admin/releases/${releaseId}/rollout-progress`);
            if (!resp.ok) {
                this.tratarErroRollout(resp.status);
                return;
            }
            const data = await resp.json();

            if (seq !== this.rolloutRequestSeq) {
                this.requestLog.push(`discarded_old_seq_${seq}_curr_${this.rolloutRequestSeq}`);
                return;
            }

            if (!this.validarSchemaRollout(data)) {
                this.tratarErroRollout(200, "Schema inválido");
                return;
            }

            this.lastRolloutSnapshot = data;
            this.removerAvisoErroRollout();
            this.renderizarRollout(data);
            this.requestLog.push(`rendered_seq_${seq}`);
        } catch (err) {
            this.tratarErroRollout(0, err.message);
        } finally {
            this.rolloutRequestInFlight = false;
        }
    }
}

async function runTests() {
    console.log("=== INICIANDO TESTES DE FRONTEND ROLLOUT ===");

    // Teste 1: Validação de Schema (Canonical vs Alias)
    {
        const sim = new RolloutFrontendSimulator();
        assert.strictEqual(sim.validarSchemaRollout(null), false);
        assert.strictEqual(sim.validarSchemaRollout({ success: false }), false);
        assert.strictEqual(sim.validarSchemaRollout({ success: true, summary: {} }), false);
        assert.strictEqual(sim.validarSchemaRollout({ success: true, summary: { updated_count: "invalid" }, devices: [] }), false);
        
        const validCanonical = {
            success: true,
            summary: {
                total_devices: 31,
                online_eligible_count: 27,
                updated_count: 1,
                pending_count: 26,
                offline_count: 4,
                not_targeted_count: 0,
                progress_percent: 3.7
            },
            devices: []
        };
        assert.strictEqual(sim.validarSchemaRollout(validCanonical), true);

        const validCounts = {
            success: true,
            counts: {
                total_devices: 31,
                online_eligible: 27,
                updated: 1,
                pending_update: 26,
                offline: 4,
                not_targeted: 0
            },
            devices: []
        };
        assert.strictEqual(sim.validarSchemaRollout(validCounts), true);
        console.log("  [PASS] Teste 1: Validação de Schema (Canonical & Alias)");
    }

    // Teste 2: Renderização de KPIs com Denominador online_eligible_count
    {
        const sim = new RolloutFrontendSimulator();
        const payload = {
            success: true,
            summary: {
                total_devices: 31,
                online_eligible_count: 27,
                updated_count: 1,
                pending_count: 26,
                offline_count: 4,
                not_targeted_count: 0,
                progress_percent: 3.7
            },
            devices: []
        };
        sim.renderizarRollout(payload);
        assert.strictEqual(sim.renderedKPIs.updated, 1);
        assert.strictEqual(sim.renderedKPIs.pending, 26);
        assert.strictEqual(sim.renderedKPIs.offline, 4);
        assert.strictEqual(sim.renderedKPIs.notTargeted, 0);
        assert.strictEqual(sim.renderedKPIs.onlineEligible, 27);
        assert.strictEqual(sim.renderedKPIs.total, 31);
        assert.strictEqual(sim.renderedKPIs.summaryText, "1 / 27 computadores online (3.7%)");
        console.log("  [PASS] Teste 2: Renderização de KPIs e denominador de progresso");
    }

    // Teste 3: Polling Lento e Bloqueio de Concorrência (Item 6 & 12)
    {
        const sim = new RolloutFrontendSimulator();
        const mockSlowFetch = (delayMs, data) => () => new Promise(res => {
            setTimeout(() => res({ ok: true, json: async () => data }), delayMs);
        });

        const p1Data = {
            success: true,
            summary: { total_devices: 31, online_eligible_count: 27, updated_count: 1, pending_count: 26, offline_count: 4, not_targeted_count: 0, progress_percent: 3.7 },
            devices: []
        };

        const p1 = sim.carregarProgressoRollout(1, mockSlowFetch(80, p1Data));
        await new Promise(r => setTimeout(r, 30));
        await sim.carregarProgressoRollout(1, mockSlowFetch(10, p1Data));
        await p1;

        assert.ok(sim.requestLog.includes("start_seq_1"));
        assert.ok(sim.requestLog.includes("blocked_in_flight_seq_1"));
        assert.ok(sim.requestLog.includes("rendered_seq_1"));
        assert.strictEqual(sim.rolloutRequestInFlight, false);
        console.log("  [PASS] Teste 3: Polling lento (8s) impede corrida concorrente no tick de 5s");
    }

    // Teste 4: Recuperação de HTTP 502 sem Zerar Dados Prévios (Item 4 & 7)
    {
        const sim = new RolloutFrontendSimulator();
        const goodData = {
            success: true,
            summary: { total_devices: 31, online_eligible_count: 27, updated_count: 1, pending_count: 26, offline_count: 4, not_targeted_count: 0, progress_percent: 3.7 },
            devices: [{ id: 1, hostname: "PC-VICTOR", department: "TI", status: "updated" }]
        };

        await sim.carregarProgressoRollout(1, async () => ({ ok: true, json: async () => goodData }));
        assert.strictEqual(sim.renderedKPIs.updated, 1);
        assert.strictEqual(sim.transientAlertShown, false);
        assert.strictEqual(sim.lastRolloutSnapshot.summary.updated_count, 1);

        await sim.carregarProgressoRollout(1, async () => ({ ok: false, status: 502 }));
        assert.strictEqual(sim.renderedKPIs.updated, 1);
        assert.strictEqual(sim.renderedKPIs.pending, 26);
        assert.strictEqual(sim.transientAlertShown, true, "Alerta transitório deve ser ativado no 502");
        assert.strictEqual(sim.lastRolloutSnapshot.summary.updated_count, 1, "Snapshot válido deve ser preservado");

        const updatedData = {
            ...goodData,
            summary: { ...goodData.summary, updated_count: 2, pending_count: 25, progress_percent: 7.4 }
        };
        await sim.carregarProgressoRollout(1, async () => ({ ok: true, json: async () => updatedData }));
        assert.strictEqual(sim.renderedKPIs.updated, 2);
        assert.strictEqual(sim.transientAlertShown, false, "Alerta transitório deve ser desativado após recuperação");
        console.log("  [PASS] Teste 4: Tolerância a HTTP 502 (preservação de snapshot e recuperação limpa)");
    }

    // Teste 5: Ordenação Determinística Estável de Dispositivos (Item 10 & 11)
    {
        const sim = new RolloutFrontendSimulator();
        const payload = {
            success: true,
            summary: { total_devices: 4, online_eligible_count: 4, updated_count: 1, pending_count: 3, offline_count: 0, not_targeted_count: 0, progress_percent: 25.0 },
            devices: [
                { id: 10, department: "Operações", display_name: "PC 02", hostname: "PC-OP-02" },
                { id: 2, department: "Comercial", display_name: "Vendas B", hostname: "PC-COM-02" },
                { id: 1, department: "Comercial", display_name: "Vendas A", hostname: "PC-COM-01" },
                { id: 5, department: "Administrativo", display_name: "Diretoria", hostname: "PC-ADM-01" }
            ]
        };
        sim.renderizarRollout(payload);
        const sortedHosts = sim.renderedDevices.map(d => d.hostname);
        assert.deepStrictEqual(sortedHosts, ["PC-ADM-01", "PC-COM-01", "PC-COM-02", "PC-OP-02"]);
        console.log("  [PASS] Teste 5: Ordenação determinística estável da tabela");
    }

    console.log("\nTODOS OS TESTES DE FRONTEND PASSARAM COM 100% DE SUCESSO!");
}

runTests().catch(err => {
    console.error("FALHA NOS TESTES DE FRONTEND:", err);
    process.exit(1);
});
