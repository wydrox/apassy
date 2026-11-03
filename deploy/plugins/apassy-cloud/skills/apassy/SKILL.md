---
name: apassy
description: Use the user's API credentials from their Apassy vault without seeing them. Use it when a task needs an API key or token that the user keeps in Apassy, or when the user says "use Apassy" or names an Apassy item.
---

# Apassy for cloud agents

Apassy keeps the user's credentials on the user's Mac. You never get a real value. You get
placeholders and base URLs. The user's Mac swaps a placeholder for the value when your request goes
through its base URL. The user allows each run on the Mac or the iPhone.

The MCP server `apassy` has three tools: `apassy_list_access`, `apassy_request_run`, and
`apassy_run_status`.

## Steps

1. **List access.** Call `apassy_list_access` with no arguments. Each item has an `item_id`, an
   `env_name` (the variable of its placeholder), its `hosts`, and its `base_url_vars`. If the list is
   empty, tell the user to choose credentials for this agent in Apassy → Bouncer → Agents (its page,
   **Choose Credentials…**). Do not guess item ids.

2. **Request a run.** Call `apassy_request_run` with:
   - `items`: the `item_id` of each item that the command needs.
   - `command`: the exact argv that you will run, one string for each argument. Use the variables, not
     values: for example `["curl", "-s", "-H", "Authorization: Bearer $HTTPBIN_TOKEN",
     "$APASSY_BASE_HTTPBIN_TOKEN/bearer"]`.
   - `purpose`: why, in one short sentence.
   - `user_request`: the user's own words that led to this run. Quote them. Do not write them yourself.

   Send the API request to the base URL (`APASSY_BASE_<ENV_NAME>`, or a provider variable such as
   `OPENAI_BASE_URL`), with the placeholder in the `Authorization` header, a key header such as
   `x-api-key`, or a key query parameter. A placeholder anywhere else is refused.

3. **Tell the user and wait.** The result has a `run_id` and the status `pending`. Tell the user:
   "Apassy asks you to allow this run on your Mac or iPhone." Then call `apassy_run_status` with the
   `run_id` (and `wait_secs` 20) again and again while the status is `pending`. The user has 5 minutes.

4. **Run the command.** When the status is `ready`, run the same command that you stated, with every
   variable of `session.env` set in its environment. Do not change the command. Do not add other
   commands to the same session.

5. **Report.** Give the user the result of the command. The API answers hold placeholders, not values.

## Rules

- Never print, log, echo, or store a variable of `session.env`, a placeholder, a base URL, or the
  session key. Do not put them in a file, a commit, a message, or your answer. Together they work as a
  credential until the session ends.
- Never ask the user for a secret value, and never try to read or print one.
- If the status is `denied`, `timed_out`, or `ended`, stop. Tell the user the status and the `note`.
  Do not request the run again without asking the user first. An `ended` run is final, also with a code
  that you do not know.
- If a call fails with `rate_limited` (HTTP 429), wait the `Retry-After` seconds before the next call.
  If it fails with `unauthenticated` or `token_expired` (HTTP 401), sign in again with the MCP
  authorization flow when your client offers it (the user allows it on their Mac); otherwise stop and
  tell the user that the connection ended, so they connect this agent again in Apassy.
- If the URL does not answer, the user's Mac may be locked, asleep, or offline, or Apassy may not run.
  Tell the user. Do not retry in a loop.
- Use only the items that the run needs. Use one run for one command.
