# Contributing

Pull requests are reviewed by the project lead (see CODEOWNERS).

Before you open one:

```sh
gofmt -l .                 # must print nothing
go vet ./...
go test ./...
go run ./tools/gendocs     # after changing rules or their documentation
```

## Demo data

For screenshots and dashboard work, fill an empty data directory with a week
of activity on three hosts (addresses from the documentation ranges):

```sh
VIGIL_DEMO_DIR=/tmp/vigil-demo go test ./internal/server -run TestWriteDemoData
vigil-server user add -config demo.json you    # demo.json: {"data_dir": "/tmp/vigil-demo", ...}
```

## Adding a detection rule

1. Add the rule to `rules` in `internal/server/rules.go` (severity, ATT&CK
   technique, English and German alert title) and the logic in `evaluate`.
2. Document it in `ruleDocs` in `internal/server/rules_doc.go`: when it fires,
   known false positives, and what to do. The tests fail without this entry.
3. Run `go run ./tools/gendocs` and commit the updated `docs/rules.md`.

## Documentation

Pages live in `docs/` and are published with MkDocs Material on every push to
`main`. To preview locally:

```sh
python3 -m venv .venv && .venv/bin/pip install -r docs/requirements.txt
.venv/bin/mkdocs serve
```

## Security issues

Do not open public issues for vulnerabilities. Use GitHub's private
vulnerability reporting on this repository.
