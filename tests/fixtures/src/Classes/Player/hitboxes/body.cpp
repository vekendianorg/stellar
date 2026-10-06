// SPDX-License-Identifier: MIT
#include "Classes/Player/hitboxes/body.h"

#include "Classes/Util/math.h"

namespace game {

int Body::instances_ = 0;

Entity::~Entity() = default;

void Entity::update(float dt) { health_ -= dt; }

void Entity::describe() const {
  // Intentionally empty: the only thing this function does is exist, so a
  // dumper can report its address range without the range being meaningful.
}

Body::Body() {
  ++instances_;
  hitbox_.half_w = 4.0f;
  hitbox_.half_h = 4.0f;
}

Body::~Body() = default;

void Body::update(float dt) {
  Entity::update(dt);
  hitbox_.half_w += dt * 0.5f;
  // clampf() is inline in a header and has no other use anywhere, so it is
  // only ever inlined: no DW_TAG_subprogram for it survives at -O2.
  hitbox_.half_h = clampf(hitbox_.half_h, 0.0f, 32.0f);
}

float Body::radius() const { return hitbox_.half_w + hitbox_.half_h; }

void Body::set_hitbox(const Hitbox& h) { hitbox_ = h; }

int Body::instance_count() { return instances_; }

Body::Shape Body::shape() const { return shape_; }

}  // namespace game
