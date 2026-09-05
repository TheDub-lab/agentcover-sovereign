/**
 * SalesforceGuardClient.cls
 * -------------------------------------------------------------
 * Drop-in Apex class that routes every agent action through your
 * safety-protocol guard BEFORE the action executes. The agent only
 * proceeds when the guard returns allowed = true.
 *
 * Deploy this as an Apex class. Call SalesforceGuard.guard(...) from
 * your Agentforce action / Flow / Apex before doing the real work.
 *
 * Guard must be reachable from your Salesforce org. Options:
 *   - Guard running on a public endpoint (e.g. your VPC / Heroku / a
 *     small container) with auth in front.
 *   - Or run it inside a Salesforce Function / External Service that
 *     can reach it.
 *   - For a local demo, expose it via a tunneling service and use that
 *     URL in GUARD_URL.
 */
public class SalesforceGuard {

    // Point this at your running guard. Use a Named Credential in prod
    // (keeps the URL + auth out of code). Example uses raw URL.
    private static final String GUARD_URL =
        'https://your-guard-host.example.com/guard';

    /**
     * Ask the guard to decide on an intent. Returns the guard's verdict.
     * actionType: 'api_call' | 'send_message' | 'payment'
     * target:     the endpoint / recipient the agent wants to hit
     * method:     e.g. 'POST', 'x402', 'send_message'
     * params:     JSON string of the action params
     * cost:       estimated USD cost of the action
     */
    public static GuardVerdict guard(String actionType, String target,
                                    String method, String params, Decimal cost) {

        HttpRequest req = new HttpRequest();
        req.setEndpoint(GUARD_URL);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/json');

        Map<String, Object> body = new Map<String, Object>{
            'action_type' => actionType,
            'target'      => target,
            'method'      => method,
            'params'      => (params == null ? new Map<String,Object>() : (Map<String,Object>) JSON.deserializeUntyped(params)),
            'cost'        => (cost == null ? 0.0 : cost)
        };
        req.setBody(JSON.serialize(body));
        req.setTimeout(10000);

        Http http = new Http();
        HttpResponse res = http.send(req);

        Map<String, Object> resp =
            (Map<String, Object>) JSON.deserializeUntyped(res.getBody());

        return new GuardVerdict(
            (Boolean) resp.get('allowed'),
            (String)  resp.get('outcome'),
            (String)  resp.get('block_reason'),
            (String)  resp.get('request_id')
        );
    }

    /** Convenience: only true when the guard explicitly allows. */
    public static Boolean isAllowed(String actionType, String target,
                                    String method, String params, Decimal cost) {
        return guard(actionType, target, method, params, cost).allowed;
    }

    public class GuardVerdict {
        public Boolean allowed;
        public String  outcome;
        public String  blockReason;
        public String  requestId;
        public GuardVerdict(Boolean a, String o, String b, String r) {
            allowed = a; outcome = o; blockReason = b; requestId = r;
        }
    }
}

/*
USAGE FROM AN AGENTFLOW / FLOW / APEX ACTION:

  // Before calling any external API from the agent:
  Boolean ok = SalesforceGuard.isAllowed(
      'api_call',
      'https://api.salesforce.com/v1/accounts',
      'POST',
      '{"query":"sync accounts"}',
      0.10
  );
  if (!ok) {
      // HALT — do not execute the action. Guard denied it.
      throw new GuardDeniedException('Action blocked by safety guard');
  }
  // ... proceed with the real call ...
*/
