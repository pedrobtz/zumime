# The gctorture job (native-checks.yaml) sets ZUMIME_GCTORTURE=true. Tests
# that loop in R over the whole registry, a corpus or many allowlists check
# data and properties, not memory safety, and at step 20 they cost hours:
# r-actions recommends gating them there. They run everywhere else.
skip_if_gctorture <- function() {
  skip_if(identical(Sys.getenv("ZUMIME_GCTORTURE"), "true"),
    "a property test over many inputs; skipped under gctorture")
}
