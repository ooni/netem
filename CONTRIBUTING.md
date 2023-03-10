# Contributing to ooni/netem

This is an open source project, and contributions are welcome! You are welcome
to open pull requests. An open pull request will be reviewed by a core
developer. The review may request you to apply changes. Once the assigned
reviewer is satisfied, they will merge the pull request.

## OONI Software Development Guidelines

Please, make sure you read [OONI Software Development Guidelines](
https://ooni.org/post/ooni-software-development-guidelines/). We try in
general to follow these guidelines when working on ooni/netem. In
the unlikely case where those guidelines conflict with this document, this
document will take precedence.

## Golang Resources

We use golang as our primary language for the development of OONI Probe CLI and do check out the resources below, quite useful to read before contributing.

- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Concurrency](https://go.dev/blog/pipelines) and [Data races](https://go.dev/ref/mem)
- [Channels Axioms](https://dave.cheney.net/2014/03/19/channel-axioms)

## Opening issues

Please, before opening a new issue, check whether the issue or feature request
you want us to consider has not already been reported by someone else. The
issue tracker is at [github.com/ooni/probe/issues](https://github.com/ooni/probe/issues).

## PR requirements

Every pull request that introduces new functionality should feature
comprehensive test coverage. Any pull request that modifies existing
functionality should pass existing tests. What's more, any new pull
request that modifies existing functionality should not decrease the
existing code coverage.

Long-running tests should be skipped when running tests in short mode
using `go test -short`. We prefer internal testing to external
testing. We generally have a file called `foo_test.go` with tests
for every `foo.go` file. Sometimes we separate long running
integration tests in a `foo_integration_test.go` file.

If there is a top-level DESIGN.md document, make sure such document is
kept in sync with code changes you have applied.

Do not submit large PRs. A reviewer can best service your PR if the
code changes are around 200-600 lines. (It is okay to add more changes
afterwards, if the reviewer asks you to do more work; the key point
here is that the PR should be reasonably sized when the review starts.)

In this vein, we'd rather structure a complex issue as a sequence of
small PRs, than have a single large PR address it all.

As a general rule, a PR is reviewed by reading the whole diff. Let us
know if you want us to read each diff individually, if you think that's
functional to better understand your changes.

## Code style requirements

Please, use `go fmt`, `go vet`, and `golint` to check your code
contribution before submitting a pull request. Make sure your code
is documented. At the minimum document all the exported symbols.

Make sure you commit `go.mod` and `go.sum` changes. Make sure you
run `go mod tidy` to minimize such changes.

## Code testing requirements

Make sure all tests pass with `go test -race ./...` run from the
top-level directory of this repository.

## Community Channels

Stuck somewhere or Have any questions? please join our [Slack Channels](https://slack.ooni.org/) or [IRC](ircs://irc.oftc.net:6697/#ooni). We're here to help and always available to discuss.
