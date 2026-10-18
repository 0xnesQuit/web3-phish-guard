/**
 * declarativeNetRequest blocking for *known* phishing hosts: the request is cancelled before anything
 * is fetched, so a listed drainer never gets to run. Heuristic verdicts still use the post-commit redirect.
 *
 * Session rules (rebuilt on worker start, never persisted) cover the freshest entries: the newest N
 * MetaMask hotlist domains, ScamSniffer's tail, and the full community lists. A high-priority allow rule
 * carries the user's trusted domains and the trusted-infrastructure list; per-host bypasses get their own rule.
 */

export const RULE_ALLOW = 1;
export const RULE_BYPASS_BASE = 100; // 100..999 bypass rules
export const RULE_BLOCK_BASE = 1000; // 1000.. block chunks
export const CHUNK = 1500;

type Rule = chrome.declarativeNetRequest.Rule;

/** Pure: build the rule set for a list of block domains and an allow set. */
export function buildRules(block: string[], allow: string[]): Rule[] {
  const rules: Rule[] = [];
  const allowSet = new Set(allow);
  const domains = [...new Set(block.filter((d) => d && !allowSet.has(d) && /^[a-z0-9.-]+$/.test(d)))];
  for (let i = 0; i < domains.length; i += CHUNK) {
    rules.push({
      id: RULE_BLOCK_BASE + rules.length,
      priority: 1,
      action: { type: "block" as chrome.declarativeNetRequest.RuleActionType },
      condition: { requestDomains: domains.slice(i, i + CHUNK), resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType] },
    });
  }
  if (allow.length) {
    rules.push({
      id: RULE_ALLOW,
      priority: 10,
      action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType },
      condition: { requestDomains: allow.slice(0, 5000), resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType] },
    });
  }
  return rules;
}

export async function applyRules(rules: Rule[]): Promise<void> {
  const dnr = chrome.declarativeNetRequest;
  if (!dnr?.updateSessionRules) return;
  const existing = await dnr.getSessionRules();
  const removeRuleIds = existing.filter((r) => r.id === RULE_ALLOW || r.id >= RULE_BLOCK_BASE).map((r) => r.id);
  try {
    await dnr.updateSessionRules({ removeRuleIds, addRules: rules });
  } catch (e) {
    // Firefox / older Chrome may reject large rule sets; fall back to fewer chunks rather than none.
    console.warn("[w3pg] DNR rules rejected, retrying with half the chunks", e);
    try { await dnr.updateSessionRules({ removeRuleIds, addRules: rules.filter((r) => r.id === RULE_ALLOW || r.id < RULE_BLOCK_BASE + Math.ceil((rules.length - 1) / 2)) }); } catch { /* give up: post-commit redirect still works */ }
  }
}

/** Let the user through to one host for the session (after "I understand the risk"). */
export async function addBypassRule(host: string): Promise<void> {
  const dnr = chrome.declarativeNetRequest;
  if (!dnr?.updateSessionRules) return;
  const existing = await dnr.getSessionRules();
  const used = new Set(existing.map((r) => r.id));
  let id = RULE_BYPASS_BASE;
  while (used.has(id) && id < RULE_BLOCK_BASE - 1) id++;
  await dnr.updateSessionRules({
    addRules: [{ id, priority: 20, action: { type: "allow" as chrome.declarativeNetRequest.RuleActionType }, condition: { requestDomains: [host], resourceTypes: ["main_frame" as chrome.declarativeNetRequest.ResourceType] } }],
  }).catch(() => undefined);
}
