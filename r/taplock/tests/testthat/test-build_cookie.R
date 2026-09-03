test_that("build_cookie omits Domain by default", {
  expect_false(grepl("Domain", build_cookie("key", "value")))
})

test_that("build_cookie includes Domain when provided", {
  cookie <- build_cookie("key", "value", "example.com")
  expect_true(grepl("; Domain=example.com", cookie, fixed = TRUE))
})

test_that("build_cookie omits Domain for empty string", {
  expect_false(grepl("Domain", build_cookie("key", "value", "")))
})

test_that("build_cookie omits Domain for NULL/empty vector", {
  expect_false(grepl("Domain", build_cookie("key", "value", NULL)))
  expect_false(grepl("Domain", build_cookie("key", "value", character(0))))
})

test_that("build_cookie produces an HttpOnly, same-site lax cookie", {
  cookie <- build_cookie("access", "tok", "example.com")
  expect_true(grepl("; path=/; SameSite=Lax; HttpOnly", cookie, fixed = TRUE))
})
