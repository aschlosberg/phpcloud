load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "awscryptod.go",
        "password.go",
    ],
    importpath = "github.com/aschlosberg/myaspire/awscryptod",
    visibility = ["//visibility:private"],
    deps = [
        "//argon2:go_default_library",
        "@com_github_golang_glog//:go_default_library",
        "@com_github_spiral_goridge//:go_default_library",
        "@org_golang_x_crypto//bcrypt:go_default_library",
    ],
)

go_binary(
    name = "awscryptod",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
    static = "on",
)

go_test(
    name = "go_default_test",
    srcs = [
        "awscryptod_test.go",
        "password_test.go",
    ],
    embed = [":go_default_library"],
    deps = [
        "//argon2:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_crypto//bcrypt:go_default_library",
    ],
)
