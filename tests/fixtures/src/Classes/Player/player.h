// SPDX-License-Identifier: MIT
// The player: one aggregate that ties the hitbox body to the math helpers.
#pragma once

#include "Classes/Player/hitboxes/body.h"
#include "Classes/Util/math.h"

namespace game {

/// Deliberately never used outside player.cpp, so it is instantiated exactly
/// once and only there -- one DW_TAG_subprogram for one instantiation.
template <typename T>
T clamp_value(T v) {
  return static_cast<T>(v < static_cast<T>(0) ? static_cast<T>(0) : v);
}

/// Owns a Body and drives it. Three levels deep: Player -> Body -> Entity.
class Player {
 public:
  Player();

  void tick(float dt);

  int score() const;

 private:
  Body body_;
  int score_ = 0;
};

}  // namespace game
