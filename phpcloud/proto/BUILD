load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

proto_library(
    name = "phpcloud_proto",
    srcs = ["phpcloud.proto"],
    visibility = ["//visibility:public"],
)

go_proto_library(
    name = "phpcloud_go_proto",
    importpath = "github.com/aschlosberg/phpcloud/phpcloud/proto",
    proto = ":phpcloud_proto",
    visibility = ["//visibility:public"],
)

go_library(
    name = "go_default_library",
    embed = [":phpcloud_go_proto"],
    importpath = "github.com/aschlosberg/phpcloud/phpcloud/proto",
    visibility = ["//visibility:public"],
)
