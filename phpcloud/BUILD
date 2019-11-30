load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "aws.go",
        "crypto.go",
        "password.go",
        "phpcloud.go",
        "secrets.go",
    ],
    importpath = "github.com/aschlosberg/phpcloud/phpcloud",
    visibility = ["//visibility:private"],
    deps = [
        "//argon2:go_default_library",
        "@com_github_aws_aws_sdk_go//service/secretsmanager:go_default_library",
        "@com_github_aws_aws_sdk_go//service/secretsmanager/secretsmanageriface:go_default_library",
        "@com_github_golang_glog//:go_default_library",
        "@com_github_spiral_goridge//:go_default_library",
        "@org_golang_x_crypto//bcrypt:go_default_library",
    ],
)

go_binary(
    name = "phpcloud",
    embed = [":go_default_library"],
    static = "on",
    visibility = ["//visibility:public"],
)

go_test(
    name = "go_default_test",
    srcs = [
        "password_test.go",
        "phpcloud_test.go",
        "secrets_test.go",
    ],
    data = glob(["testdata/**"]),
    embed = [":go_default_library"],
    deps = [
        "//argon2:go_default_library",
        "@com_github_aws_aws_sdk_go//aws:go_default_library",
        "@com_github_aws_aws_sdk_go//service/secretsmanager:go_default_library",
        "@com_github_aws_aws_sdk_go//service/secretsmanager/secretsmanageriface:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_spiral_goridge//:go_default_library",
        "@org_golang_x_crypto//bcrypt:go_default_library",
    ],
)
