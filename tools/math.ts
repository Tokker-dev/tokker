// Subscription token math (issue #13). Pure library: converts a plan's
// published limits into a monthly token estimate, the window that binds it,
// and a $ / 1M-at-full-use figure, under a named assumption profile
// (data/profiles/*.json, default agentic-coding-v1). No I/O, no dependencies.
//
// This mirrors the spec implemented by crates/tokker-math; the shared test
// vectors in tests/vectors/token-math.json pin both implementations.
//
// Spec invariants (do not "fix" these without a spec change):
// - Operation order is exactly as written below: monthly units first
//   ((amount * 30) / 7 evaluates left-to-right), then the divisor, then the
//   tokens-per-call multiplier. Reorder and the last digits drift.
// - Off-peak multipliers are NEVER applied (e.g. Z.AI's 50% off-peak would
//   double tokens; the estimate stays at peak rates).
// - The string "unknown" is never derived: a missing cap, missing conversion
//   or unknown price yields "unknown"/null, never an invented number.
// - Exact ties on the monthly candidate prefer the coarser window:
//   monthly > weekly > daily > 5h_rolling.
// - ERRATUM 1 (per tests/vectors/token-math.json): a token-denominated cap is
//   already a token count and passes through WITHOUT the tokens-per-call
//   multiplier (cerebras 24M/day x 30 = 720M, stackblitz 10M/month = 10M).

/** Window names used by `limits_published[].window` in data/pricing.json. */
export type LimitWindow =
  | '5h_rolling'
  | 'daily'
  | 'weekly'
  | 'monthly'
  | 'per_request'
  | 'unspecified';

/** Window names that can bind a monthly volume estimate. */
export type BindingWindow = '5h_rolling' | 'daily' | 'weekly' | 'monthly';

/** Units used by `limits_published[].unit`. */
export type LimitUnit =
  | 'tokens'
  | 'requests'
  | 'prompts'
  | 'messages'
  | 'credits'
  | 'usd'
  | 'unspecified';

/** One entry of a plan's `limits_published`. Mirrors the dataset row's JSON keys. */
export interface LimitEntry {
  window: LimitWindow;
  unit: LimitUnit;
  amount: number | 'unknown';
  quote?: string;
}

/** Per-vendor unit conversions, keyed by vendor_id by the callers. */
export interface PlanConversions {
  /** Credits consumed by one standard call under the profile's token mix. */
  credits_per_call?: number;
  /** USD value of one credit, when the vendor publishes it (GitHub: 0.01). */
  usd_per_credit?: number;
  /** Where the conversion numbers come from. */
  source?: string;
}

/**
 * A subscription plan reduced to what the math needs. Field names mirror the
 * shared test vectors (tests/vectors/token-math.json) verbatim.
 */
export interface PlanInput {
  /** USD price per month; null when not applicable, "unknown" when unpublished. */
  price_usd_per_month: number | 'unknown' | null;
  /** Dataset row confidence; "secondary" makes every entry unusable. */
  confidence?: string;
  limits: LimitEntry[];
  conversions?: PlanConversions;
}

/** The `call` block of a profile file. */
export interface ProfileCall {
  input_tokens: number;
  cached_input_tokens: number;
  output_tokens: number;
  tokens_per_call: number;
}

/** The `windows` block of a profile file. */
export interface ProfileWindows {
  five_hour_windows_per_day: number;
  days_per_week: number;
  days_per_month: number;
}

/** The `reference_pricing` block of a profile file (USD per Mtok). */
export interface ProfileReferencePricing {
  currency?: string;
  input_per_mtok: number;
  cached_input_per_mtok: number;
  output_per_mtok: number;
}

/** Parsed shape of data/profiles/*.json. Keys mirror the JSON verbatim. */
export interface Profile {
  id: string;
  version?: number;
  title?: string;
  description?: string;
  policy?: string;
  call: ProfileCall;
  windows: ProfileWindows;
  reference_pricing: ProfileReferencePricing;
}

/**
 * Result of the estimate. The token/usd fields carry the dataset's own
 * "unknown" string (never null) so an enriched row can store them verbatim:
 * "unknown" means not derivable; bindingWindow is then null and the row's
 * binding_window stays null/absent.
 */
export interface EstimateResult {
  /** Math.round of the binding monthly candidate, or "unknown". */
  estTokensPerMonth: number | 'unknown';
  /** round4(price / unrounded tokens * 1e6), or "unknown" (no estimate or no price). */
  estUsdPerMtokAtFullUse: number | 'unknown';
  bindingWindow: BindingWindow | null;
  /** Min over usable 5h entries of the raw window amount in tokens, else null. */
  tokensPerWindow: number | null;
  /** Min over usable weekly entries, else tokensPerWindow * (W * 7), else null. */
  tokensPerWeek: number | null;
}

const VOLUME_WINDOWS: readonly LimitWindow[] = ['5h_rolling', 'daily', 'weekly', 'monthly'];
const CONVERTIBLE_UNITS: readonly LimitUnit[] = [
  'tokens',
  'requests',
  'prompts',
  'messages',
  'credits',
  'usd',
];
/** Higher = coarser; exact ties prefer the coarser window. */
const COARSENESS: Record<BindingWindow, number> = {
  monthly: 3,
  weekly: 2,
  daily: 1,
  '5h_rolling': 0,
};

function isNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

/** round4(x) = Math.round(x * 10000) / 10000. */
export function round4(x: number): number {
  return Math.round(x * 10000) / 10000;
}

/**
 * K: the profile's USD cost per standard call, from the reference rates:
 * ((I - c) * r_in + c * r_cached + o * r_out) / 1e6.
 * agentic-coding-v1: (2000*2 + 18000*0.2 + 1500*10) / 1e6 = 0.0226.
 * Throws when the profile's own numbers are inconsistent (tokens_per_call must
 * equal input + output; cached must not exceed input).
 */
export function profileCostPerCall(profile: Profile): number {
  const { input_tokens: i, cached_input_tokens: c, output_tokens: o, tokens_per_call: t } =
    profile.call;
  if (t !== i + o) {
    throw new Error(
      `profile ${profile.id}: tokens_per_call ${t} != input_tokens ${i} + output_tokens ${o}`
    );
  }
  if (c > i) {
    throw new Error(`profile ${profile.id}: cached_input_tokens ${c} > input_tokens ${i}`);
  }
  const r = profile.reference_pricing;
  return ((i - c) * r.input_per_mtok + c * r.cached_input_per_mtok + o * r.output_per_mtok) / 1e6;
}

/** A limit entry can bind a monthly volume estimate only under all of: */
function isUsable(entry: LimitEntry, plan: PlanInput): entry is LimitEntry & { amount: number } {
  return (
    isNumber(entry.amount) && // a number, never the string "unknown"
    VOLUME_WINDOWS.includes(entry.window) && // per_request/unspecified are never volume caps
    CONVERTIBLE_UNITS.includes(entry.unit) && // the unit must be convertible to tokens
    plan.confidence !== 'secondary' && // data rule 6: secondary caps are never derived
    (entry.unit !== 'credits' || hasCreditConversion(plan.conversions)) // credits need a published value
  );
}

function hasCreditConversion(conversions?: PlanConversions): boolean {
  return isNumber(conversions?.credits_per_call) || isNumber(conversions?.usd_per_credit);
}

/** Monthly units of a cap: 5h -> x(W*D); daily -> xD; weekly -> (amount*D)/7; monthly -> amount. */
function monthlyUnits(amount: number, window: LimitWindow, profile: Profile): number {
  const { five_hour_windows_per_day: w, days_per_month: d } = profile.windows;
  switch (window) {
    case '5h_rolling':
      return amount * (w * d);
    case 'daily':
      return amount * d;
    case 'weekly':
      return (amount * d) / 7; // left-to-right: (amount * 30) / 7
    case 'monthly':
      return amount;
    default:
      return Number.NaN; // unreachable: isUsable filtered other windows
  }
}

/**
 * Tokens for one entry over `units` of its cap: (units / divisor) * tokens_per_call,
 * in exactly this op order. `units` is the monthly-equivalent cap for the
 * minimum, and the raw window amount for tokens_per_window / tokens_per_week.
 */
function tokensCandidate(
  entry: LimitEntry & { amount: number },
  units: number,
  plan: PlanInput,
  profile: Profile,
  costPerCall: number
): number {
  const t = profile.call.tokens_per_call;
  switch (entry.unit) {
    case 'tokens':
      // ERRATUM 1: already a token count, no xT — equals (units / T) * T.
      return units;
    case 'credits': {
      const q = plan.conversions?.credits_per_call;
      if (isNumber(q)) return (units / q) * t;
      // usd_per_credit p instead of credits_per_call: ((units * p) / K) * T.
      const p = plan.conversions?.usd_per_credit as number;
      return ((units * p) / costPerCall) * t;
    }
    case 'usd':
      return (units / costPerCall) * t;
    default:
      // requests | prompts | messages: one unit = one call -> divisor 1.
      return (units / 1) * t;
  }
}

/**
 * Estimate a plan's monthly token allowance under a profile.
 * est_tokens_per_month = Math.round(min of usable monthly-equivalent candidates);
 * the minimum's window is binding_window (exact ties prefer the coarser window).
 * tokens_per_window / tokens_per_week take the MINIMUM usable cap in their
 * window (same binding semantics), converted from the RAW window amount
 * (never the monthly-equivalent); a daily cap is never extrapolated. Off-peak
 * multipliers are never applied. Nothing usable -> "unknown" everywhere and a
 * null binding.
 */
export function estimateForPlan(plan: PlanInput, profile: Profile): EstimateResult {
  const costPerCall = profileCostPerCall(profile);

  let tokensPerWindow: number | null = null;
  let tokensPerWeek: number | null = null;
  let best: { window: BindingWindow; tokens: number } | null = null;

  for (const entry of plan.limits) {
    if (!isUsable(entry, plan)) continue;
    const candidate = tokensCandidate(
      entry,
      monthlyUnits(entry.amount, entry.window, profile),
      plan,
      profile,
      costPerCall
    );

    // Per-window figures take the MINIMUM usable cap in that window, computed
    // from the raw published amount (never the monthly-equivalent).
    if (entry.window === '5h_rolling') {
      const tokens = tokensCandidate(entry, entry.amount, plan, profile, costPerCall);
      if (tokensPerWindow === null || tokens < tokensPerWindow) tokensPerWindow = tokens;
    }
    if (entry.window === 'weekly') {
      const tokens = tokensCandidate(entry, entry.amount, plan, profile, costPerCall);
      if (tokensPerWeek === null || tokens < tokensPerWeek) tokensPerWeek = tokens;
    }

    if (
      best === null ||
      candidate < best.tokens ||
      (candidate === best.tokens && COARSENESS[entry.window] > COARSENESS[best.window])
    ) {
      best = { window: entry.window, tokens: candidate };
    }
  }

  // No usable weekly entry but a usable 5h one: W * 7 windows per week (4 * 7
  // = 28). Daily caps are never extrapolated.
  if (tokensPerWeek === null && tokensPerWindow !== null) {
    tokensPerWeek =
      tokensPerWindow *
      (profile.windows.five_hour_windows_per_day * profile.windows.days_per_week);
  }

  if (best === null) {
    return {
      estTokensPerMonth: 'unknown',
      estUsdPerMtokAtFullUse: 'unknown',
      bindingWindow: null,
      tokensPerWindow,
      tokensPerWeek,
    };
  }

  // Values are positive, so Math.round is half-away-from-zero here.
  const estTokensPerMonth = Math.round(best.tokens);
  const price = plan.price_usd_per_month;
  const estUsdPerMtokAtFullUse = isNumber(price) ? round4((price / best.tokens) * 1e6) : 'unknown';

  return {
    estTokensPerMonth,
    estUsdPerMtokAtFullUse,
    bindingWindow: best.window,
    tokensPerWindow,
    tokensPerWeek,
  };
}

/**
 * USD price of a dataset subscription row: row.usd.price_month when a number;
 * else row.price_month when a number and currency === "USD"; else
 * price_month / fx.rates[currency] (a rate is one USD in the target currency);
 * else the string "unknown". Never invents a number.
 */
export function usdPriceMonthly(
  row: {
    currency?: string;
    price_month?: number | 'unknown' | null;
    usd?: { price_month?: number | 'unknown' | null };
  },
  fx: { rates?: Record<string, number> }
): number | 'unknown' {
  const usd = row.usd?.price_month;
  if (isNumber(usd)) return usd;
  const native = row.price_month;
  if (!isNumber(native)) return 'unknown';
  if (row.currency === 'USD') return native;
  const rate = fx.rates?.[row.currency ?? ''];
  if (!isNumber(rate) || rate <= 0) return 'unknown';
  return native / rate;
}

/** Minimal view of the dataset subscription row this function reads. */
export interface SubscriptionRow {
  vendor_id?: string;
  currency?: string;
  price_month?: number | 'unknown' | null;
  usd?: { price_month?: number | 'unknown' | null };
  confidence?: string;
  estimate_assumption?: string | null;
  limits_published?: LimitEntry[];
}

/** Enrichment result; field names mirror the dataset keys they are written to. */
export interface EnrichedEstimate {
  /** number, or the dataset string "unknown". */
  estTokensPerMonth: number | 'unknown';
  /** round4 number, or "unknown". */
  estUsdPerMtokAtFullUse: number | 'unknown';
  /** Which published window binds; null when the estimate is unknown. */
  bindingWindow: BindingWindow | null;
  /** The row's existing estimate_assumption, else the profile id. */
  estimateAssumption: string;
}

/**
 * Recompute a dataset row's estimate fields under a profile. Pure: `row` is
 * not mutated; the caller writes `bindingWindow` to the row's
 * binding_window if the build stores it. `conversions` maps vendor_id to its
 * credit conversion; `fx` backs usdPriceMonthly (defaults to USD-only).
 */
export function enrichSubscriptionRow(
  row: SubscriptionRow,
  profile: Profile,
  conversions: Record<string, PlanConversions> = {},
  fx: { rates?: Record<string, number> } = { rates: {} }
): EnrichedEstimate {
  const result = estimateForPlan(
    {
      price_usd_per_month: usdPriceMonthly(row, fx),
      confidence: row.confidence,
      limits: row.limits_published ?? [],
      conversions: row.vendor_id === undefined ? undefined : conversions[row.vendor_id],
    },
    profile
  );

  return {
    estTokensPerMonth: result.estTokensPerMonth,
    estUsdPerMtokAtFullUse: result.estUsdPerMtokAtFullUse,
    bindingWindow: result.estTokensPerMonth === 'unknown' ? null : result.bindingWindow,
    estimateAssumption:
      typeof row.estimate_assumption === 'string' && row.estimate_assumption.length > 0
        ? row.estimate_assumption
        : profile.id,
  };
}
