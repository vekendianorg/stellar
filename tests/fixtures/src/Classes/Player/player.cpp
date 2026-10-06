// SPDX-License-Identifier: MIT
#include "Classes/Player/player.h"

namespace game {

// The library's only non-static global variable: DWARF describes it with a
// DW_AT_location and a size, so a dumper has to resolve an address rather than
// read a constant out of the section.
int player_registry_token = 0x5354454c;

Player::Player() { score_ = clamp_value<int>(0); }

void Player::tick(float dt) {
  body_.update(dt);
  score_ += static_cast<int>(body_.radius());
}

int Player::score() const { return score_; }

}  // namespace game
