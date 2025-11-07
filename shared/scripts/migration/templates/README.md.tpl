# {{REPO_NAME}}

{{DESCRIPTION}}

## Development

```bash
git clone git@github.com:{{ORG}}/{{REPO_NAME}}.git --recurse-submodules
cd {{REPO_NAME}}
# initialize/update submodules
git submodule update --init --recursive
```

## Tasks

```bash
make verify  # lint + test + build
```

## Version Info
Expose /version endpoint or CLI flag returning component versions.
