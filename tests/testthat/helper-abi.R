# Symbol audit for test-abi.R. A helper rather than file scope, so testthat's
# parallel workers and shuffled runs see it.

zumime_dll_path <- function() {
  dll <- getLoadedDLLs()[["zumime"]]
  skip_if(is.null(dll), "zumime DLL is not loaded")
  path <- dll[["path"]]
  skip_if(!file.exists(path), "zumime shared object not found on disk")
  path
}

# Defined symbols in the dynamic symbol table: `-D --defined-only` on ELF,
# `-gU` (external and defined) on Mach-O. Windows exports from a .def file
# and $(C_VISIBILITY) is empty there, so the export set is not the build's to
# control.
exported_symbols <- function() {
  skip_on_os("windows")
  nm <- Sys.which("nm")
  skip_if(!nzchar(nm), "nm is not available")
  args <- if (Sys.info()[["sysname"]] == "Darwin") "-gU" else
    c("-D", "--defined-only")
  syms <- suppressWarnings(system2(
    nm,
    c(args, shQuote(zumime_dll_path())),
    stdout = TRUE,
    stderr = FALSE
  ))
  skip_if(length(syms) == 0L, "nm produced no output")
  syms
}

# A coverage or sanitizer runtime linked into the object exports symbols of
# its own, so the exact-export assertion is skipped on instrumented builds.
is_instrumented_build <- function() {
  if (identical(Sys.getenv("R_COVR"), "true")) {
    return(TRUE)
  }
  syms <- tryCatch(exported_symbols(), condition = function(e) character())
  any(grepl("gcov|__llvm_prof|asan|ubsan|tsan|msan|sancov", syms))
}
