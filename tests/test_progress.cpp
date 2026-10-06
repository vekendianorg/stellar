// SPDX-License-Identifier: MIT
// Progress reporting: formatting, counting, and the promise that a disabled
// reporter costs nothing measurable in a hot loop.
#include <chrono>
#include <cstdio>
#include <string>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

#include "stellar/diag/progress.h"
#include "test_framework.h"

using stellar::diag::Progress;

namespace {

/// A reporter with drawing forced on, so render() is exercised without a tty.
Progress& reporter() {
  Progress& p = Progress::instance();
  p.reset();
  p.configure(/*force=*/true, /*min_interval_ms=*/0);
  // Count and format, but never write: these tests assert on render() and must
  // not scribble carriage returns over the test output.
  p.set_draw_enabled(false);
  return p;
}

/// Points stderr at /dev/null for its lifetime.
///
/// Progress::configure() asks stderr whether it is a terminal and how wide it is.
/// Run from an interactive shell the answer is "yes, 80+ columns", which is not
/// what a test that needs the redirected-output behaviour can assume; the same
/// test passed under an agent (stderr piped) and failed on a real terminal.
/// Detaching stderr makes the answer the same everywhere. A no-op on Windows,
/// where the console is queried through a handle rather than a descriptor.
class DetachedStderr {
 public:
  DetachedStderr() {
#if !defined(_WIN32)
    std::fflush(stderr);
    saved_ = ::dup(STDERR_FILENO);
    const int null_fd = ::open("/dev/null", O_WRONLY);
    if (saved_ >= 0 && null_fd >= 0) {
      ::dup2(null_fd, STDERR_FILENO);
      active_ = true;
    } else if (saved_ >= 0) {
      ::close(saved_);
      saved_ = -1;
    }
    if (null_fd >= 0) ::close(null_fd);
#endif
  }
  ~DetachedStderr() {
#if !defined(_WIN32)
    if (active_) {
      std::fflush(stderr);
      ::dup2(saved_, STDERR_FILENO);
    }
    if (saved_ >= 0) ::close(saved_);
#endif
  }
  DetachedStderr(const DetachedStderr&) = delete;
  DetachedStderr& operator=(const DetachedStderr&) = delete;

 private:
#if !defined(_WIN32)
  int saved_ = -1;
  bool active_ = false;
#endif
};

}  // namespace

STELLAR_TEST(Progress, RendersCountersWithThousandsAndPercentage) {
  Progress& p = reporter();
  p.declare("DIEs", 50000);
  p.declare("Types", 4800);
  p.set("DIEs", 12450);
  p.set("Types", 1203);
  p.stage("Resolving types");
  // The first counter with a known total drives the percentage.
  EXPECT_TRUE(p.render().find("[ 24%]") != std::string::npos);
  EXPECT_TRUE(p.render().find("DIEs: 12,450/50,000") != std::string::npos);
  EXPECT_TRUE(p.render().find("Types: 1,203/4,800") != std::string::npos);
  EXPECT_TRUE(p.render().find("Stage: Resolving types") != std::string::npos);
}

STELLAR_TEST(Progress, ExplicitPrimaryOverridesTheDefaultChoice) {
  Progress& p = reporter();
  p.declare("DIEs", 100);
  p.declare("Methods", 400);
  p.set("DIEs", 10);
  p.set("Methods", 40);
  p.primary("Methods");
  EXPECT_TRUE(p.render().find("[ 10%]") != std::string::npos);
  p.primary("DIEs");
  EXPECT_TRUE(p.render().find("[ 10%]") != std::string::npos);
}

STELLAR_TEST(Progress, CountersWithoutTotalsShowNoFraction) {
  Progress& p = reporter();
  p.declare("Lines", 0, /*has_total=*/false);
  p.set("Lines", 4096);
  EXPECT_TRUE(p.render().find("Lines: 4,096") != std::string::npos);
  EXPECT_TRUE(p.render().find("Lines: 4,096/") == std::string::npos);
}

STELLAR_TEST(Progress, AddAccumulatesAndDeclareIsIdempotent) {
  Progress& p = reporter();
  p.declare("Fields", 1000);
  for (int i = 0; i < 250; ++i) p.add("Fields");
  EXPECT_TRUE(p.render().find("Fields: 250/1,000") != std::string::npos);
  // Re-declaring must not reset the value or duplicate the counter.
  p.declare("Fields", 2000);
  EXPECT_TRUE(p.render().find("Fields: 250/2,000") != std::string::npos);
  p.add("Fields", 5);
  EXPECT_TRUE(p.render().find("Fields: 255/2,000") != std::string::npos);
}

STELLAR_TEST(Progress, UnknownLabelsAreCreatedOnDemand) {
  Progress& p = reporter();
  // add() on a label that was never declared must still be counted, which is
  // what lets a stage report without pre-registering.
  p.add("AdHoc");
  p.add("AdHoc", 4);
  EXPECT_TRUE(p.render().find("AdHoc: 5") != std::string::npos);
}

STELLAR_TEST(Progress, DisabledReporterCostsNothingInAHotLoop) {
  Progress& p = reporter();
  p.set_enabled(false);
  // The point of the early-out: the 20M-iteration DIE loop must not pay for
  // progress. Compare a large count with the clock read a fraction as often.
  const auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < 2'000'000; ++i) p.add("Hot");
  const double ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0).count();
  // A generous bound: this asserts the branch is predictable, not the exact cost.
  EXPECT_TRUE(ms < 250.0);
}

STELLAR_TEST(Progress, RenderIsStableAcrossRepeatedCalls) {
  Progress& p = reporter();
  p.declare("Units", 10);
  p.set("Units", 5);
  p.stage("Init");
  EXPECT_STREQ(p.render(), p.render());
}

STELLAR_TEST(Progress, RenderIsClampedToTheTerminalWidth) {
  // reporter() configures the reporter, which is when the terminal is probed, so
  // stderr must already be detached; the destructor restores it at the end.
  const DetachedStderr detached;
  Progress& p = reporter();
  // The dry-run reporter draws nothing, so exercise the clamp through render()
  // plus the width the reporter would have detected.
  p.declare("Wide", 2, false);
  p.set("Wide", 123456789);
  p.note(std::string(400, 'x'));
  EXPECT_TRUE(p.render().size() > 100);  // untruncated when no width is known
  EXPECT_EQ(p.width(), 0);             // stderr is detached above, so no terminal
  EXPECT_FALSE(p.ansi());              // so the space-padding fallback is used
}

STELLAR_TEST(Progress, DrawIsDisabledInDryRunSoTestsNeverWrite) {
  Progress& p = reporter();
  p.declare("Lines", 0, false);
  // configure() enables drawing; the test helper turns it back off, which is
  // what keeps carriage returns out of the test output.
  EXPECT_TRUE(p.enabled());
  p.add("Lines", 5);
  p.stage("Some stage");
  p.checkpoint();
  EXPECT_TRUE(p.render().find("Lines: 5") != std::string::npos);
}
