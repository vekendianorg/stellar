// SPDX-License-Identifier: MIT
// A hitbox body: the leaf of the player hierarchy.
//
// Hitbox's field offsets are fixed by the AArch64 AAPCS64 rules (natural
// member alignment, no tail padding needed here), so every one of the four
// fixture variants encodes the same values and they can be asserted without
// consulting the debug info that produced them.
#pragma once

namespace game {

/// Root of the hierarchy.
///
/// `update` is virtual and `describe` is not; neither is overridden by
/// `describe` anywhere, so the vtable of every derived type carries exactly one
/// overriding entry.
class Entity {
 public:
  virtual ~Entity();
  virtual void update(float dt);

  /// Non-virtual: reached through the static type only.
  void describe() const;

 protected:
  float health_ = 100.0f;
};

/// One axis-aligned hitbox, 16 bytes at offset 0 of the enclosing object.
struct Hitbox {
  float x;
  float y;
  float half_w;
  float half_h;
};

/// A player's body. Derives from Entity and overrides `update`.
class Body : public Entity {
 public:
  Body();
  ~Body() override;

  /// The virtual override; its out-of-line body lives in body.cpp.
  void update(float dt) override;

  /// Non-virtual member with a real out-of-line body in body.cpp.
  float radius() const;

  void set_hitbox(const Hitbox& h);

  /// Static data member: a declaration in the class, a definition in body.cpp.
  static int instances_;

  /// Static member function, so both static forms are present.
  static int instance_count();

  enum class Shape {
    kCircle,
    kBox,
    kCapsule,
  };

  Shape shape() const;

 private:
  Hitbox hitbox_{};
  Shape shape_ = Shape::kCircle;
};

}  // namespace game
