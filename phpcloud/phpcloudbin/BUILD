load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")

go_library(
    name = "go_default_library",
    srcs = ["phpcloudbin.go"],
    importpath = "github.com/aschlosberg/phpcloud/phpcloud/phpcloudbin",
    visibility = ["//visibility:private"],
    deps = [
        "//phpcloud:go_default_library",
        "@com_github_golang_glog//:go_default_library",
    ],
)

go_binary(
    name = "phpcloudbin",
    embed = [":go_default_library"],
    static = "on",
    visibility = ["//visibility:public"],
)
