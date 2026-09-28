# Rule packs and provider files

The files here are the tool knowledge of the bouncer, as data.

| Path | Content | Format | Documentation |
| --- | --- | --- | --- |
| `*.json` | One rule pack per tool or group of tools: flag rules, known safe commands, roles, exceptions, writes | [`schema/rule-pack.schema.json`](schema/rule-pack.schema.json) | [Rule packs](../docs/operations/rule-packs.md) |
| `providers/*.json` | One file per API provider: value shapes, variable names, known hosts, suggested declaration | [`schema/provider.schema.json`](schema/provider.schema.json) | [Declarations](../docs/operations/declarations.md) |

The app embeds every file at build time (`src/broker/packs.rs`, `src/vault/providers.rs`). A new file needs one line there.

Check a file before you open a pull request:

```
cargo run --locked --features vault --bin apassy-packs -- validate packs/<tool>.json
```

The JSON Schemas describe the structure for an editor or a CI step. The command above runs the real loader and is the authority. How to write a pack, what "known safe" means, and how a pull request is reviewed: [CONTRIBUTING.md](../CONTRIBUTING.md).

## License

Everything in this directory is public domain under [CC0-1.0](LICENSE): the packs, the provider files, and the schemas. Use them in any tool, with or without attribution. The rest of the repository is [Apache-2.0](../LICENSE).
