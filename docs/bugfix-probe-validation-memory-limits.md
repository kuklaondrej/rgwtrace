# Bugfix: apply DWARF size limits during probe validation

Probe-entry validation also reads target ELF files and, for stripped targets,
separate debug files. These reads previously bypassed the configured
`--max-debug-file-bytes` limit or used a fixed default. Validation now receives
the same limit as native extraction, bounds both file reads, and shares one
cumulative decompression budget across every section loaded for a DWARF entry
check. This keeps imported artifacts and native metadata under the same memory
limit and prevents several individually valid compressed sections from exceeding
the per-file allowance together.

Regression tests cover oversized target images, oversized separate debug files,
and cumulative section decompression during `Dwarf::load`.
