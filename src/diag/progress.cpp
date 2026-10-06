// SPDX-License-Identifier: MIT
#include "stellar/diag/progress.h"

#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#define STELLAR_ISATTY _isatty
#define STELLAR_FILENO _fileno
#else
#include <sys/ioctl.h>
#include <unistd.h>
#define STELLAR_ISATTY isatty
#define STELLAR_FILENO fileno
#endif

#include <cstdlib>

#include "stellar/diag/metrics.h"

namespace stellar::diag {
namespace {

/// How many `add` calls may pass before the clock is consulted. Reading the
/// clock on every one of twenty million updates would be wasteful; doing it once
/// per few thousand is free and still smooth.
constexpr std::uint64_t kCheckEvery = 2048;

void append_thousands(std::string& out, std::uint64_t v) {
  char digits[24];
  int n = std::snprintf(digits, sizeof(digits), "%llu",
                        static_cast<unsigned long long>(v));
  for (int i = 0; i < n; ++i) {
    if (i != 0 && (n - i) % 3 == 0) out.push_back(',');
    out.push_back(digits[i]);
  }
}

/// Columns available on the attached terminal, or 0 when it cannot tell.
///
/// Used to clamp the status line so it never wraps.
int terminal_width() {
#if defined(_WIN32)
  CONSOLE_SCREEN_BUFFER_INFO csbi{};
  if (::GetConsoleScreenBufferInfo(::GetStdHandle(STD_ERROR_HANDLE), &csbi)) {
    const int w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    return w > 0 ? w : 0;
  }
  return 0;
#else
  struct winsize ws {};
  if (::ioctl(STELLAR_FILENO(stderr), TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
    return ws.ws_col;
  }
  return 0;
#endif
}

/// Whether the terminal can erase a line for us. A dumb terminal, or a
/// redirected stream, gets the space-padding fallback instead.
bool terminal_supports_ansi() {
  if (STELLAR_ISATTY(STELLAR_FILENO(stderr)) == 0) return false;
  const char* term = std::getenv("TERM");
  if (term != nullptr) {
    const std::string_view t(term);
    if (t == "dumb") return false;
  }
#if defined(_WIN32)
  return false;  // the Windows console handles the rewrite itself
#else
  return true;
#endif
}

}  // namespace

Progress& Progress::instance() {
  static Progress p;
  return p;
}

void Progress::configure(bool force, int min_interval_ms) {
  std::lock_guard<std::mutex> lock(mutex_);
  interval_ms_ = min_interval_ms > 0 ? min_interval_ms : 80;
  // Only draw over a terminal unless asked: a redirected log would otherwise
  // be one enormous line of carriage returns.
  enabled_.store(force || STELLAR_ISATTY(STELLAR_FILENO(stderr)) != 0,
                 std::memory_order_relaxed);
  draw_enabled_.store(true, std::memory_order_relaxed);
  // Only worth detecting when something will actually be drawn.
  ansi_ = enabled() && terminal_supports_ansi();
  width_ = enabled() ? terminal_width() : 0;
  last_draw_ms_ = 0;
  since_check_.store(kCheckEvery, std::memory_order_relaxed);
  drawn_ = false;
  dirty_ = false;
}

void Progress::reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  // The table is emptied before the slots are reused: a reader walking it
  // without a lock must never reach a slot that is about to be overwritten.
  count_.store(0, std::memory_order_release);
  primary_ = nullptr;
  stage_.clear();
  note_.clear();
  // Zero the counters with real stores. This used to be a memset, which is no
  // longer legal now that the numbers are relaxed atomics -- and it never
  // reset the labels anyway, since it is a struct with a pointer member.
  for (auto& c : counters_) {
    c.label.store(nullptr, std::memory_order_relaxed);
    c.value.store(0, std::memory_order_relaxed);
    c.total.store(0, std::memory_order_relaxed);
    c.has_total.store(false, std::memory_order_relaxed);
  }
  since_check_.store(0, std::memory_order_relaxed);
  dirty_ = false;
}

int Progress::find(const char* label) const {
  // Lock-free on purpose: this runs on every add() of a hot loop, and a stage
  // may be counting from one thread per core. A slot is published only once it
  // is completely filled (see declare_locked), so what is read here is either
  // absent or fully formed -- never half a counter.
  const std::size_t n = count_.load(std::memory_order_acquire);
  for (std::size_t i = 0; i < n; ++i) {
    if (counters_[i].label.load(std::memory_order_acquire) == label) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

int Progress::declare_locked(const char* label, std::uint64_t total, bool has_total) {
  const int existing = find(label);
  if (existing >= 0) {
    counters_[existing].total.store(total, std::memory_order_relaxed);
    counters_[existing].has_total.store(has_total, std::memory_order_relaxed);
    return existing;
  }
  const std::size_t slot = count_.load(std::memory_order_relaxed);
  if (slot >= kMaxCounters) return -1;
  Counter& c = counters_[slot];
  c.value.store(0, std::memory_order_relaxed);
  c.total.store(total, std::memory_order_relaxed);
  c.has_total.store(has_total, std::memory_order_relaxed);
  c.label.store(label, std::memory_order_relaxed);
  // Published last and with release: a reader that sees the new count sees a
  // counter that is already there, which is what makes find() safe without a
  // lock even while another thread is appending.
  count_.store(slot + 1, std::memory_order_release);
  return static_cast<int>(slot);
}

void Progress::declare(const char* label, std::uint64_t total, bool has_total) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (declare_locked(label, total, has_total) < 0) return;
  dirty_ = true;
}

void Progress::primary(const char* label) {
  std::lock_guard<std::mutex> lock(mutex_);
  primary_ = label;
  dirty_ = true;
}

void Progress::stage(std::string_view name) {
  std::lock_guard<std::mutex> lock(mutex_);
  const bool changed = stage_ != name;
  stage_.assign(name);
  dirty_ = true;
  if (!changed) return;
  // A stage change is a milestone worth keeping: finish the in-progress row and
  // start the new stage on a line of its own, rather than overwriting it.
  if (drawn_) {
    std::fputc('\n', stderr);
    std::fflush(stderr);
    drawn_ = false;
    last_len_ = 0;
  }
  // Stage changes are worth showing immediately (the body of checkpoint(),
  // which cannot be called here because it would re-take the lock).
  if (!enabled()) return;
  since_check_.store(0, std::memory_order_relaxed);
  draw_locked();
}

void Progress::note(std::string_view text) {
  std::lock_guard<std::mutex> lock(mutex_);
  note_.assign(text);
  dirty_ = true;
}

void Progress::set(const char* label, std::uint64_t value) {
  std::lock_guard<std::mutex> lock(mutex_);
  int i = find(label);
  // A label first seen here is added with no total, exactly as before; an
  // existing counter keeps the total it was declared with.
  if (i < 0) i = declare_locked(label, 0, false);
  if (i >= 0) counters_[i].value.store(value, std::memory_order_relaxed);
  dirty_ = true;
}

void Progress::add(const char* label, std::uint64_t n) {
  if (!enabled()) return;  // the hot path: one predictable branch
  int i = find(label);
  if (i < 0) {
    // First sight of this label. Rare -- a stage declares its counters before
    // the loop that fills them -- and the only case on this path that locks.
    std::lock_guard<std::mutex> lock(mutex_);
    i = declare_locked(label, 0, false);
    if (i < 0) return;
  }
  counters_[i].value.fetch_add(n, std::memory_order_relaxed);
  dirty_ = true;
  if (since_check_.fetch_add(1, std::memory_order_relaxed) + 1 < kCheckEvery) return;
  since_check_.store(0, std::memory_order_relaxed);
  const auto now = static_cast<std::int64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch())
          .count());
  // Several threads may reach here at once; only one gets to redraw, and it
  // draws under the lock so the shared buffer and the row on screen stay
  // coherent instead of being interleaved character by character.
  std::lock_guard<std::mutex> lock(mutex_);
  if (now - last_draw_ms_ < interval_ms_) return;
  draw_locked();
}

bool Progress::get(const char* label, std::uint64_t& value, std::uint64_t* total,
                   bool* has_total) const {
  const int i = find(label);
  if (i < 0) return false;
  const Counter& c = counters_[i];
  // Relaxed loads: the reader wants the current number, not a synchronised view.
  // A value one update behind is still the truth, and no reader can tear.
  value = c.value.load(std::memory_order_relaxed);
  if (total != nullptr) *total = c.total.load(std::memory_order_relaxed);
  if (has_total != nullptr) *has_total = c.has_total.load(std::memory_order_relaxed);
  return true;
}

bool Progress::primary_value(std::uint64_t& value, std::uint64_t& total) const {
  if (primary_ != nullptr) {
    const int i = find(primary_);
    if (i >= 0 && counters_[i].has_total && counters_[i].total != 0) {
      value = counters_[i].value;
      total = counters_[i].total;
      return true;
    }
  }
  // Otherwise the first counter that knows its total drives the percentage.
  for (std::size_t i = 0; i < count_; ++i) {
    if (counters_[i].has_total && counters_[i].total != 0) {
      value = counters_[i].value;
      total = counters_[i].total;
      return true;
    }
  }
  return false;
}

std::string Progress::render() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return render_locked();
}

std::string Progress::render_locked() const {
  buffer_.clear();
  std::uint64_t pv = 0, pt = 0;
  if (primary_value(pv, pt)) {
    const unsigned pct = pt != 0 ? static_cast<unsigned>((pv * 100) / pt) : 0;
    char head[32];
    std::snprintf(head, sizeof(head), "[%3u%%] ", pct);
    buffer_ += head;
  }
  bool first = true;
  const std::size_t n = count_.load(std::memory_order_acquire);
  for (std::size_t i = 0; i < n; ++i) {
    const Counter& c = counters_[i];
    const char* label = c.label.load(std::memory_order_acquire);
    if (label == nullptr) continue;
    if (!first) buffer_ += " | ";
    first = false;
    buffer_ += label;
    buffer_ += ": ";
    append_thousands(buffer_, c.value.load(std::memory_order_relaxed));
    const std::uint64_t total = c.total.load(std::memory_order_relaxed);
    if (c.has_total.load(std::memory_order_relaxed) && total != 0) {
      buffer_ += '/';
      append_thousands(buffer_, total);
    }
  }
  if (!stage_.empty()) {
    buffer_ += first ? "Stage: " : " | Stage: ";
    buffer_ += stage_;
  }
  if (!note_.empty()) {
    buffer_ += " | ";
    buffer_ += note_;
  }
  return buffer_;
}

void Progress::draw_locked() {
  if (!enabled() || !draw_enabled_.load(std::memory_order_relaxed)) return;
  std::string line = render_locked();

  // Clamp to the terminal so the line can never wrap. A wrapped status line is
  // the root cause of the old duplicated text: once the cursor has wrapped onto
  // a second row, a later carriage return only returns to the start of that row
  // and the first fragment stays on screen.
  //
  // When the width cannot be determined (a pty that reports none, for
  // instance) fall back to the conventional 80 rather than writing a line of
  // unbounded length and hoping.
  const int cols = width_ > 1 ? width_ : 80;
  if (line.size() > static_cast<std::size_t>(cols - 1)) {
    line.resize(static_cast<std::size_t>(cols - 1));
  }

  // Wipe the row first, then write exactly one line. No newline: the next update
  // replaces this one.
  clear_line_locked();
  std::fwrite(line.data(), 1, line.size(), stderr);
  std::fflush(stderr);
  last_len_ = line.size();
  drawn_ = true;
  dirty_ = false;
  last_draw_ms_ = static_cast<std::int64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch())
          .count());
}

void Progress::checkpoint() {
  if (!enabled()) return;
  std::lock_guard<std::mutex> lock(mutex_);
  since_check_.store(0, std::memory_order_relaxed);
  draw_locked();
}

void Progress::clear_line() {
  std::lock_guard<std::mutex> lock(mutex_);
  clear_line_locked();
}

void Progress::clear_line_locked() {
  if (!drawn_) return;
  if (ansi_) {
    // Erase the whole row, whatever is on it, then return to column 0.
    std::fputs("\x1b[2K\r", stderr);
  } else {
    // Fallback for terminals without ANSI, and for output that is redirected:
    // overwrite the known number of columns with spaces.
    std::fprintf(stderr, "\r%*s\r", static_cast<int>(last_len_), "");
  }
  std::fflush(stderr);
  drawn_ = false;
  last_len_ = 0;
}

void Progress::finish() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!drawn_) return;
  // Close the row before returning, so following output is not written over it.
  std::fputc('\n', stderr);
  std::fflush(stderr);
  clear_line_locked();
}

void Progress::finish_line(std::string_view line) {
  std::lock_guard<std::mutex> lock(mutex_);
  clear_line_locked();
  if (line.empty()) return;
  std::fprintf(stderr, "%.*s\n", static_cast<int>(line.size()), line.data());
  std::fflush(stderr);
}

void Progress::fail(std::string_view message) {
  finish_line(message);
}

}  // namespace stellar::diag
