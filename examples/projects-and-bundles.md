# Projects and bundles

Create, save, copy, and reopen project work:

```text
project new BranchLab
project save
project save-as /Users/alex/Labs/BranchLab-copy.golan
project recent
project open-recent 1
project open /Users/alex/Labs/BranchLab.golan
```

Snapshot a reusable configuration source:

```text
project import config /Users/alex/Configs/lab.json
project config list
project config update <source-id>
project config export lab.json
project save
```

Open the guided bundle exporter:

```text
project export bundle
```

Or choose the bundle directly:

```text
project export bundle /Users/alex/Exports/Lab.golanproj metadata
project export bundle /Users/alex/Exports/Lab.golanproj sanitized
project export bundle /Users/alex/Exports/Lab.golanproj full
```

```text
project import bundle /Users/alex/Exports/Lab.golanproj RestoredLab
show project
```

`metadata` omits observations and captures, `sanitized` includes safe
observations without captures, and `full` may include selected automatic
captures. Transient revealed secrets are never included.
