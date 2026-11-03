// The push gateway `apassy-push` (docs/contracts/push-gateway-v1.md). The logic is in
// gateway.ts; workerd accepts only handlers as exports of this main module. Type exports
// are fine: they are erased.

import { handleGateway, type GatewayEnv } from "./gateway.ts";

export type { GatewayEnv } from "./gateway.ts";

export default {
  async fetch(request: Request, env: GatewayEnv): Promise<Response> {
    return handleGateway(request, env);
  },
};
