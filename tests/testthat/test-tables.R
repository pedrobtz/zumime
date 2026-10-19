test_that("regenerating from the recorded sources reproduces the tables", {
  root <- source_root()
  skip_if(is.null(root), "tools/ is not available outside a source tree")
  skip_if_not_oracle_package("yaml")
  skip_if_not_oracle_package("digest")
  out <- withr::local_tempdir()
  status <- withr::with_dir(root, system2(
    file.path(R.home("bin"), "Rscript"),
    c("tools/generate-tables.R", paste0("--out=", out)),
    stdout = FALSE, stderr = FALSE
  ))
  expect_identical(status, 0L)

  header <- file.path(out, "src", "zumime_types.h")
  committed <- file.path(root, "src", "zumime_types.h")
  expect_identical(
    readBin(header, "raw", file.size(header)),
    readBin(committed, "raw", file.size(committed))
  )
  new <- new.env()
  load(file.path(out, "R", "sysdata.rda"), new)
  for (name in ls(new)) {
    expect_identical(new[[name]], get(name, asNamespace("zumime")), info = name)
  }
})

test_that("every type reaches the root without a cycle", {
  types <- mime_types()
  idx <- match(types$parent, types$type)
  cur <- seq_len(nrow(types))
  # Walk every type up together; a cycle would never reach the root.
  for (step in seq_len(nrow(types))) {
    nxt <- idx[cur]
    done <- is.na(nxt)
    if (all(done)) break
    cur[!done] <- nxt[!done]
  }
  expect_true(all(is.na(idx[cur])))
  expect_true(all(types$type[cur] == "application/octet-stream"))
  expect_lt(step, 16L)
})

test_that("every parent is a registered type", {
  types <- mime_types()
  parents <- types$parent[!is.na(types$parent)]
  expect_true(all(parents %in% types$type))
  expect_identical(types$type[is.na(types$parent)], "application/octet-stream")
})

test_that("an extension belongs to one type", {
  exts <- unlist(mime_types()$extensions)
  expect_false(anyDuplicated(exts) > 0)
})

test_that("the registry has the shape mime_types() documents", {
  types <- mime_types()
  expect_named(types, c(
    "type", "parent", "aliases", "extensions", "category", "detected_by"
  ))
  expect_type(types$aliases, "list")
  expect_type(types$extensions, "list")
  expect_true(all(types$detected_by %in% c(
    "signature", "container", "text", "extension", "registered"
  )))
  expect_identical(types$category, sub("/.*$", "", types$type))
})
