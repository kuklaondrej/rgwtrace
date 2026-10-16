# Bugfix: validate operations after `DW_OP_fbreg`

The native location-expression decoder returned as soon as it saw
`DW_OP_fbreg`. That skipped every later operation in the expression. For
example, `DW_OP_fbreg; DW_OP_deref` was treated as a plain frame-relative
address, although the dereference changes which location the variable denotes.

The decoder now applies the frame offset and continues through the remaining
operations. Supported offset operations are still evaluated; an unsupported
operation returns no location, which makes probe metadata fail closed instead
of describing the wrong address. A regression test covers a frame-relative
expression followed by `DW_OP_deref`.
