#!/usr/bin/env bash
# Makes the Apassy Connect products and prices in Stripe (docs/contracts/connect-billing-v1.md
# section 2; docs/OPERATIONS.md, "Billing"). Idempotent by lookup key: a price whose lookup key
# exists with the same amounts is kept; one with other amounts gets a new price that takes the
# lookup key over (`transfer_lookup_key=true`), and the old price is archived. Every price
# carries `metadata[apassy_plan]` (personal, family, team): the subscriptions that stay on an
# old price send events without a lookup key, and the relay reads the plan from that metadata
# and the price's interval (or keeps the plan it stored).
#
#   stripe-products.sh [--dry-run]          the sandbox of the logged-in Stripe CLI
#   CONFIRM_LIVE=yes stripe-products.sh --live [--dry-run]
#
# Needs the Stripe CLI (`stripe login`, or STRIPE_API_KEY) and jq. --dry-run only reads.
#
# Configuration (cents, VAT included; the defaults are the owner's prices of 2026-11-03):
#   CONNECT_PERSONAL_MONTH_CENTS=300   CONNECT_PERSONAL_YEAR_CENTS=3000
#   CONNECT_FAMILY_MONTH_CENTS=500     CONNECT_FAMILY_YEAR_CENTS=5000      (4 people)
#   APASSY_CONNECT_FAMILY_EXTRA_CENTS=100  APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS=1000
#   CONNECT_TEAM_MONTH_CENTS=400       CONNECT_TEAM_YEAR_CENTS=4000        (each member)
# Optional: CONNECT_TAX_CODE (the product tax code of new products, e.g. a SaaS code).
# Optional: APASSY_STRIPE_OLD_PERSONAL_PRODUCT and APASSY_STRIPE_OLD_TEAM_PRODUCT name the
# products of the old split (Personal EUR 1, Team EUR 2). They are renamed to Connect Personal
# and Connect Team, and their active prices without a Connect lookup key are archived.
set -euo pipefail

live=0
dry=0
for arg in "$@"; do
    case "$arg" in
        --live) live=1 ;;
        --dry-run) dry=1 ;;
        -h | --help)
            sed -n '2,23p' "$0"
            exit 0
            ;;
        *)
            echo "stripe-products.sh: unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

if [[ $live -eq 1 && "${CONFIRM_LIVE:-}" != "yes" ]]; then
    echo "stripe-products.sh: --live changes the live Stripe account; set CONFIRM_LIVE=yes to go on." >&2
    exit 2
fi

for tool in stripe jq; do
    if ! command -v "$tool" > /dev/null; then
        echo "stripe-products.sh: $tool is not installed." >&2
        exit 2
    fi
done

cents() {
    local name=$1 default=$2 value
    value=${!name:-$default}
    if [[ ! $value =~ ^[0-9]{1,7}$ ]]; then
        echo "stripe-products.sh: $name must be a whole number of cents." >&2
        exit 2
    fi
    printf '%s' "$((10#$value))"
}

personal_month=$(cents CONNECT_PERSONAL_MONTH_CENTS 300)
personal_year=$(cents CONNECT_PERSONAL_YEAR_CENTS 3000)
family_month=$(cents CONNECT_FAMILY_MONTH_CENTS 500)
family_year=$(cents CONNECT_FAMILY_YEAR_CENTS 5000)
family_extra_month=$(cents APASSY_CONNECT_FAMILY_EXTRA_CENTS 100)
family_extra_year=$(cents APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS 1000)
team_month=$(cents CONNECT_TEAM_MONTH_CENTS 400)
team_year=$(cents CONNECT_TEAM_YEAR_CENTS 4000)

mode_flags=()
if [[ $live -eq 1 ]]; then
    mode_flags=(--live)
    echo "stripe-products.sh: LIVE mode."
else
    echo "stripe-products.sh: sandbox (test) mode."
fi
[[ $dry -eq 1 ]] && echo "stripe-products.sh: dry run, nothing is changed."

# macOS bash 3.2 treats an empty array as unset under `set -u`, hence the `+` forms.
stripe_get() {
    stripe get ${mode_flags[@]+"${mode_flags[@]}"} "$@"
}

# A POST, or its description in a dry run. A rerun after a lost answer is safe without an
# idempotency key: products have fixed ids, and a new price is found by its lookup key.
stripe_post() {
    local path=$1
    shift
    if [[ $dry -eq 1 ]]; then
        echo "  would POST $path $*" >&2
        echo '{"id":"dry_run"}'
        return
    fi
    stripe post ${mode_flags[@]+"${mode_flags[@]}"} "$path" "$@"
}

# The product of a plan: a fixed id (apassy_connect_<plan>), or the old product when its id is
# given, renamed. Prints the product id.
ensure_product() {
    local plan=$1 name=$2 old=${3:-}
    local id=${old:-apassy_connect_$plan}
    local found
    found=$(stripe_get "/v1/products/$id" 2> /dev/null | jq -r '.id // empty' || true)
    if [[ -z $found ]]; then
        if [[ -n $old ]]; then
            echo "stripe-products.sh: the product $old does not exist." >&2
            exit 1
        fi
        echo "product $id: create \"$name\"" >&2
        local tax=()
        # The product tax code is the owner's choice in the dashboard (plan, owner step 1).
        [[ -n ${CONNECT_TAX_CODE:-} ]] && tax=(-d "tax_code=$CONNECT_TAX_CODE")
        stripe_post /v1/products -d "id=$id" -d "name=$name" -d "metadata[apassy_plan]=$plan" \
            ${tax[@]+"${tax[@]}"} > /dev/null
    else
        echo "product $id: set the name \"$name\"" >&2
        stripe_post "/v1/products/$id" -d "name=$name" -d "metadata[apassy_plan]=$plan" -d active=true > /dev/null
    fi
    printf '%s' "$id"
}

# Archives the active prices of a product that carry no Connect lookup key.
archive_old_prices() {
    local product=$1
    local ids
    ids=$(stripe_get /v1/prices -d "product=$product" -d active=true -d limit=100 |
        jq -r '.data[] | select((.lookup_key // "") | startswith("connect_") | not) | .id')
    for price in $ids; do
        echo "price $price of $product: archive" >&2
        stripe_post "/v1/prices/$price" -d active=false > /dev/null
    done
}

# The active price of a lookup key as JSON, or nothing.
price_of() {
    stripe_get /v1/prices -d "lookup_keys[]=$1" -d active=true -d "expand[]=data.tiers" |
        jq -c '.data[0] // empty'
}

# The plan of a lookup key (connect_<plan>_<interval>).
plan_of_key() {
    local key=${1#connect_}
    printf '%s' "${key%_*}"
}

# Gives a price `metadata[apassy_plan]` when it lacks it (a price of an earlier run).
ensure_plan_metadata() {
    local current=$1 plan=$2 id
    [[ -z $current ]] && return
    if jq -e --arg p "$plan" '(.metadata.apassy_plan // "") == $p' <<< "$current" > /dev/null; then
        return
    fi
    id=$(jq -r '.id' <<< "$current")
    echo "price $id: set metadata[apassy_plan]=$plan" >&2
    stripe_post "/v1/prices/$id" -d "metadata[apassy_plan]=$plan" > /dev/null
}

# A per-unit price (Personal, Team).
ensure_unit_price() {
    local product=$1 key=$2 interval=$3 amount=$4
    local current plan
    plan=$(plan_of_key "$key")
    current=$(price_of "$key")
    ensure_plan_metadata "$current" "$plan"
    if [[ -n $current ]] && jq -e --argjson a "$amount" --arg i "$interval" \
        '.currency == "eur" and .tax_behavior == "inclusive" and .billing_scheme == "per_unit"
         and .unit_amount == $a and .recurring.interval == $i' <<< "$current" > /dev/null; then
        echo "price $key: unchanged ($amount)" >&2
        return
    fi
    echo "price $key: create $amount a $interval" >&2
    stripe_post /v1/prices -d "product=$product" -d currency=eur -d tax_behavior=inclusive \
        -d "recurring[interval]=$interval" -d billing_scheme=per_unit -d "unit_amount=$amount" \
        -d "metadata[apassy_plan]=$plan" -d "lookup_key=$key" -d transfer_lookup_key=true > /dev/null
    archive_replaced "$current"
}

# The Family price: graduated tiers, tier 1 up to 4 people for a flat amount, tier 2 each
# further person.
ensure_family_price() {
    local product=$1 key=$2 interval=$3 flat=$4 extra=$5
    local current
    current=$(price_of "$key")
    ensure_plan_metadata "$current" family
    if [[ -n $current ]] && jq -e --argjson f "$flat" --argjson e "$extra" --arg i "$interval" \
        '.currency == "eur" and .tax_behavior == "inclusive" and .billing_scheme == "tiered"
         and .tiers_mode == "graduated" and (.tiers | length) == 2
         and .tiers[0].up_to == 4 and .tiers[0].flat_amount == $f and (.tiers[0].unit_amount // 0) == 0
         and .tiers[1].up_to == null and .tiers[1].unit_amount == $e
         and .recurring.interval == $i' <<< "$current" > /dev/null; then
        echo "price $key: unchanged ($flat, then $extra)" >&2
        return
    fi
    echo "price $key: create $flat for 4 people, then $extra each, a $interval" >&2
    stripe_post /v1/prices -d "product=$product" -d currency=eur -d tax_behavior=inclusive \
        -d "recurring[interval]=$interval" -d billing_scheme=tiered -d tiers_mode=graduated \
        -d "tiers[0][up_to]=4" -d "tiers[0][flat_amount]=$flat" -d "tiers[0][unit_amount]=0" \
        -d "tiers[1][up_to]=inf" -d "tiers[1][unit_amount]=$extra" \
        -d "metadata[apassy_plan]=family" -d "lookup_key=$key" -d transfer_lookup_key=true > /dev/null
    archive_replaced "$current"
}

# After a new price took the lookup key over, the replaced one is archived. Subscriptions on
# it keep it until they change plan in the portal; their events carry no lookup key, and the
# relay maps them by `metadata[apassy_plan]` (set above) or keeps the plan it stored. Their
# statuses, cancellations included, always apply.
archive_replaced() {
    local current=$1 old
    [[ -z $current ]] && return
    old=$(jq -r '.id' <<< "$current")
    echo "price $old: archive (replaced)" >&2
    stripe_post "/v1/prices/$old" -d active=false > /dev/null
}

personal=$(ensure_product personal "Connect Personal" "${APASSY_STRIPE_OLD_PERSONAL_PRODUCT:-}")
family=$(ensure_product family "Connect Family")
team=$(ensure_product team "Connect Team" "${APASSY_STRIPE_OLD_TEAM_PRODUCT:-}")

ensure_unit_price "$personal" connect_personal_month month "$personal_month"
ensure_unit_price "$personal" connect_personal_year year "$personal_year"
ensure_family_price "$family" connect_family_month month "$family_month" "$family_extra_month"
ensure_family_price "$family" connect_family_year year "$family_year" "$family_extra_year"
ensure_unit_price "$team" connect_team_month month "$team_month"
ensure_unit_price "$team" connect_team_year year "$team_year"

if [[ -n ${APASSY_STRIPE_OLD_PERSONAL_PRODUCT:-} ]]; then
    archive_old_prices "$personal"
fi
if [[ -n ${APASSY_STRIPE_OLD_TEAM_PRODUCT:-} ]]; then
    archive_old_prices "$team"
fi

echo "stripe-products.sh: done. Restart the relay, or wait an hour, for GET /v1/plans to show the prices."
