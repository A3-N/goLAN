# Recovery

Restore live networking owned by the current Workbench session without
quitting:

```text
cleanup
show adapters
show health
```

Cleanup stops active goLAN runtimes, retries their scoped restoration, restores
staged adapters to their recorded pre-goLAN state, and clears staged live
settings. It preserves saved configs, policy history, project metadata, and
evidence. A `[WARN]` result remains safe to retry with `cleanup`.

Review interrupted or stale goLAN session directories:

```text
project sessions list
show health
```

Index a recoverable live session or archive only its stale association:

```text
project recover session <artifact-directory>
project sessions archive <artifact-directory>
```

Resolve a finalized goLAN capture that was not indexed:

```text
project recover attach <capture-path>
project recover archive <capture-path>
```

Resolve an unindexed goLAN policy artifact:

```text
project recover policy attach recovered-revision <path>
project recover policy archive <path>
```

```text
project journals list
project save
```

Recovery only reconciles artifacts created by goLAN. It is not a general PCAP
import path.
