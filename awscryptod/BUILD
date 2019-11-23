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
        "//awscryptod/proto:go_default_library",
        "@com_github_golang_glog//:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
        "@org_golang_x_crypto//bcrypt:go_default_library",
    ],
)

go_binary(
    name = "awscryptod",
    embed = [":go_default_library"],
    visibility = ["//visibility:public"],
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
        "//awscryptod/proto:go_default_library",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//connectivity:go_default_library",
        "@org_golang_x_crypto//bcrypt:go_default_library",
    ],
)
