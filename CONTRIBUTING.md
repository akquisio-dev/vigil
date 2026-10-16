# Contributing

Pull requests are reviewed by the project lead (see CODEOWNERS).

Before you open one:

```sh
gofmt -l .                 # must print nothing
go vet ./...
go test ./...
go run ./tools/gendocs     # after changing rules or their documentation
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
