# Bugfix: keep required library discovery inside the target root

When tracing with `--pid`, a required Ceph library absent from `/proc/<pid>/maps`
may be found through common library-directory guesses inside the process root.
If every guess is absent or unusable, discovery now returns an error instead of
continuing into host library paths. A host copy can have different code and
DWARF offsets from the target's copy, so probing it could silently miss events
or read incorrect fields.

Host library paths remain available when tracing without `--pid`. An optional
unmapped library such as `librbd` remains absent when no usable copy exists in
the target root.
