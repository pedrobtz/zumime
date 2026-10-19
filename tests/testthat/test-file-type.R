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
  for (i in seq_len(nrow(answers))) {
    path <- file.path(dir, answers$file[i])
    got <- mime_sniff(readBin(path, "raw", file.size(path)), limit = 0)$type
    agrees <- mime_is(got, answers$mime[i])
    if (answers$file[i] %in% unclaimed) {
      expect_false(agrees, info = paste(answers$file[i], "now agrees:", got))
    } else {
      expect_true(agrees,
        info = paste(answers$file[i], answers$mime[i], "got", got))
    }
  }
})
