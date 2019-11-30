load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["argon2.go"],
    importpath = "github.com/aschlosberg/phpcloud/argon2",
    visibility = ["//visibility:public"],
    deps = ["@org_golang_x_crypto//argon2:go_default_library"],
)

go_test(
    name = "go_default_test",
    srcs = ["argon2_test.go"],
    embed = [":go_default_library"],
)
