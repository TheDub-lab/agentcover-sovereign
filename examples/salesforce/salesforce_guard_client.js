/**
 * salesforce_guard_client.js
 * -------------------------------------------------------------
 * Node sample that routes an Agentforce agent's actions through your
 * safety-protocol guard before executing. Use from a Salesforce
 * Function, a connected Node service, or a middleware layer that sits
 * between Agentforce and the outside world.
 *
 * The agent only performs the real action when guard.allowed === true.
 */
const GUARD_URL = process.env.GUARD_URL || 'https://your-guard-host.example.com/guard';

/**
 * Ask the guard to decide on an intent.
 * @returns {Promise<{allowed:boolean, outcome:string, blockReason:string|null, requestId:string}>}
 */
async function guard(actionType, target, method, params = {}, cost = 0.0) {
  const res = await fetch(GUARD_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action_type: actionType,   // 'api_call' | 'send_message' | 'payment'
      target,                    // endpoint or recipient
      method,                    // 'POST', 'x402', 'send_message', ...
      params,                    // action params object
      cost,                      // estimated USD
    }),
  });
  if (!res.ok) throw new Error(`Guard error ${res.status}`);
  return res.json();
}

/**
 * Wraps an agent action: guard it, and only run `doAction` on allow.
 * Returns the guard verdict if blocked (action NOT executed).
 */
async function guardedAction(actionType, target, method, params, cost, doAction) {
  const verdict = await guard(actionType, target, method, params, cost);
  if (!verdict.allowed) {
    console.log(`BLOCKED by guard: ${verdict.blockReason}`);
    return { executed: false, verdict };
  }
  const result = await doAction();   // the REAL action, only on allow
  return { executed: true, verdict, result };
}

/* ----- example: Agentforce agent wants to call an API ----- */
(async () => {
  // The agent PROPOSES; the guard DISPOSES.
  const out = await guardedAction(
    'api_call',
    'https://api.salesforce.com/v1/accounts',
    'POST',
    { query: 'sync accounts' },
    0.10,
    async () => {
      // This only runs if the guard allowed it.
      console.log('guard allowed — executing real API call');
      return { status: 'ok' };
    }
  );
  console.log(out);
})();
