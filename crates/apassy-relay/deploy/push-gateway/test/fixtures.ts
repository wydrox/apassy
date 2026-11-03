// The synthetic values of docs/contracts/push-gateway-v1.md section 18, shared by the tests.
import type { HandlePayload } from "../src/handles.ts";

export function range(from: number, to: number): Uint8Array {
  const out = new Uint8Array(to - from + 1);
  for (let i = 0; i < out.length; i++) out[i] = from + i;
  return out;
}

export const V = {
  gatewayKey: "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8",
  iphoneToken: "a1".repeat(32),
  iphoneSecret: "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8",
  watchToken: "b2".repeat(32),
  watchSecret: "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8",
  issuedAt: 1790000000,
  handleExpiresAt: 1805552000,
  at: 1790000100,
  expiresAt: 1790000400,
  collapseId: "apassy-question",
  iphonePlaintext:
    '{"v":1,"kind":"iphone","token":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","environment":"production","bundle_id":"com.wydrox.apassy.companion","secret":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8","issued_at":1790000000,"expires_at":1805552000}',
  iphoneHandle:
    "AQEAAQIDBAUGBwgJCgtBJxpaTb1ogql77qaa1-7S86xCZwlugXGaT4PzL5NTfCFBpTDac2pO0SkZriCatsFILmsMt3V6FVKy5oQwVC_Xp0KbnZecVv6zArmDfifrV5jgi8MknGQGiRecJm9NW2etrseKbY4QHHDC16hpS29-n_ooa8Wf7_gDcl-gXUOCOht6OHZn7JjU2hewAbctZWpd_qZzpQMPBS4GKjewB9GMj8v0if9Q6ZZSlj1UQzXfSRw3Lme5AOFU5ggjW-mmefcljd5raXzDrJ-r7U7GcjJI-XAMcaScWgVAShGeklTDrvW8Qpt8C40X2UhL_GmK8G3vg9q7_5xrlTqrBrHrZRBMHwSQ3dMPyRp5zrrzBIgGn6IlRz7SLrGYTy4uHS4",
  iphoneProof: "-MmhDTmjMiBV6cNqCsq29jnlp9anOujN_dXLn6hbbnY",
  watchPlaintext:
    '{"v":1,"kind":"watch","token":"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2","environment":"production","bundle_id":"com.wydrox.apassy.companion.watchkitapp","secret":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8","issued_at":1790000000,"expires_at":1805552000}',
  watchHandle:
    "AQEQERITFBUWFxgZGhsCGEvzbKA4AcXPuDTJwi3BZGPnoSQ9aH8XBay_-VOQstGWIJlekXGdAALT_B73l_ZgGeZMEDAmyTp2zqYF69tWqZ_1R6DSxX2gstrWUC6hi0uL_AXLKTvezTUSly0XROF6ardVkVxMFK69c8oKF652vi9NMQVtpThfgcSo1b4B8urodIEdJzfJsnhSiQ2d5NFf0hi-5MRKb1hhk1whHjAU3e-pWX7QCq_bvnIu4-iml6auHpWStEPb5l8i9oVTE7ZxeOKQupMT1YV2MB-wVcUDzDx1kjox7A8NLoDDI84B00IU9fWhfFl2srTzPyfOPP8eKqBUfazI2uE1AUYBE8c3XkCdmXoCQiRLuWBv8G00W7pcFusI2_UX-MOYh1D253_JLDrQmxzREA",
  watchProof: "KxRYEBo7r3KCRqcOBVc8OpRsPuz2rRb4LxFQtvzzaBI",
  summary:
    "ICEiIyQlJicoKSorLZYy_9V2mK8YOxL9BrISycdM3QC8LastsrSZ2rydHt5kH7FQOVw3Z9Fcdh4X0rBDP0peQmDtu1ueo2qMc8jG-HaJeH5MYA7UnBcbZRxtOLpdrfxf1XCmrKUi-gmLBZxFvggJiX35uKUAdZwfhwUqeu6y8tnLbItuN-Yk4e_Jkqawp39RHi3ux-0DNm4DCs1Nlnki8MWzWpS7q_Yf1-3uwYdSdBlr-qq7uI6GCJiJ-79H4cte4JJnY8GQ0RvTh9ZbxyqpdIhFpoe0V1w2ZgierYd-NuopbMxBWD0nepd9qDJGCGmbMZG1CwxXrjC_l2986y7k_EjhkwIbDdeBxTVnZ67guVWth1D8h-UMVEvCKR3zc2ANEQ1Qrr-skb_eNEo0hnj6Bvx6MiFWKwMUV_PcRAFVpb7so6XLs1i2bkYSzEv-w_buoaz-EnNnMD70ddE-FuZDqHiWaar_Wo0dSHz5qf5hcXNT6x185swuTpTL8sKUr32di0Qa0ObJE6BCpMOdFlxGtaKrb7bu1svCr0nLWDhMhi2Tp8ibOnvYKei4HFG251WGQ8AxcJl_7m_NTDOq4bDlEOOaOgSF7KiofJolVL4sBk8oFlaTgp2-Jvn4rFU1c04OaWJGQfOaJIvpnRXa883CBzSKZ2sNaovOg00TUiQ8Dc31pqs-ZzE8xHmg7E7YbmDyG3-UPiey7OE407l9",
  iphoneProofWithSummary: "gyriDrKhiUeSYbgOm5weYj7NG6isjzaE3IEJp9qDV3g",
};

export const IPHONE: HandlePayload = {
  kind: "iphone",
  token: V.iphoneToken,
  environment: "production",
  bundle_id: "com.wydrox.apassy.companion",
  secret: V.iphoneSecret,
  issued_at: V.issuedAt,
  expires_at: V.handleExpiresAt,
};

export const WATCH: HandlePayload = {
  kind: "watch",
  token: V.watchToken,
  environment: "production",
  bundle_id: "com.wydrox.apassy.companion.watchkitapp",
  secret: V.watchSecret,
  issued_at: V.issuedAt,
  expires_at: V.handleExpiresAt,
};

