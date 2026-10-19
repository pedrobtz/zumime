# The file-type oracle (design section 7.3). Every fixture whose format
# zumime claims must be typed as file-type types it, or as a descendant of
# that type (zumime is more specific about OLE2 documents and Ogg codecs).
# The fixtures it does not claim are listed here, so the gap is explicit;
# the test also fails when one of them starts to agree, so the list stays
# exact. Design section 6.2 claims none of these formats.

test_that("every claimed file-type fixture is typed as file-type types it", {
  dir <- fixture_dir("file-type")
  answers <- file_type_answers()
  unclaimed <- unclaimed_fixtures()
  expect_true(all(unclaimed %in% answers$file))
  # mime_type() reads 4 KiB and the tails and offsets a result asks for.
  types <- mime_type(file.path(dir, answers$file))$type
  for (i in seq_len(nrow(answers))) {
    got <- types[i]
    agrees <- mime_is(got, answers$mime[i])
    if (answers$file[i] %in% unclaimed) {
      expect_false(agrees, info = paste(answers$file[i], "now agrees:", got))
    } else {
      expect_true(agrees,
        info = paste(answers$file[i], answers$mime[i], "got", got))
    }
  }
})
