const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const template = fs.readFileSync(
    path.join(__dirname, "..", "templates", "index.html"),
    "utf8"
);

function extractFunction(name) {
    const start = template.indexOf(`function ${name}(`);
    assert.notStrictEqual(start, -1, `${name} must exist in the dashboard template`);
    const open = template.indexOf("{", start);
    let depth = 0;
    for (let index = open; index < template.length; index++) {
        if (template[index] === "{") depth++;
        if (template[index] === "}") depth--;
        if (depth === 0) return template.slice(start, index + 1);
    }
    throw new Error(`Could not parse ${name}`);
}

const helpers = [
    extractFunction("getRefreshIntervalSeconds"),
    extractFunction("dashboardEndpointsForView")
].join("\n");

const context = {
    document: { hidden: false },
    currentView: "dashboard",
    viewRefreshSeconds: {
        dashboard: 15,
        computadores: 15,
        setores: 30,
        alertas: 30,
        politicas: 30,
        configuracoes: 60
    }
};
vm.createContext(context);
vm.runInContext(helpers, context);

assert.deepStrictEqual(
    Array.from(context.dashboardEndpointsForView("dashboard")),
    ["/api/stats"]
);
assert.deepStrictEqual(
    Array.from(context.dashboardEndpointsForView("computadores")),
    ["/api/devices"]
);
assert.deepStrictEqual(
    Array.from(context.dashboardEndpointsForView("setores")),
    ["/api/stats", "/api/devices"]
);
assert.strictEqual(context.getRefreshIntervalSeconds(), 15);
context.document.hidden = true;
assert.strictEqual(context.getRefreshIntervalSeconds(), 120);

assert.ok(template.includes('document.addEventListener("visibilitychange"'));
assert.ok(template.includes("new AbortController()"));
assert.ok(template.includes('"If-None-Match"'));

console.log("Dashboard polling optimization tests passed.");
