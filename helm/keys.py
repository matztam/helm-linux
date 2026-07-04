"""Helm key and touch model, transcribed exactly from the Garmin app.

Source: com.garmin.android.gmm.HelmClientManager (decompiled from classes.dex).
The ``HelmKey`` enum is ordinal-encoded: the wire value of each key is its
position in this list (HLM_KEY_INVALID == 0). Only a subset is meaningful on
any given plotter; the device advertises its layout via HelmDevice.KeyConfig
(HLM_KEY_CFG_NONE..HLM_KEY_CFG_4). Touch-only units report HLM_KEY_CFG_NONE.
"""

from __future__ import annotations

import enum


class HelmKey(enum.IntEnum):
    """Physical/soft keys, in the exact ordinal order used by the native code."""

    HLM_KEY_INVALID = 0
    HLM_KEY_ZOOM_IN = 1
    HLM_KEY_ZOOM_OUT = 2
    HLM_KEY_DIR_UP = 3
    HLM_KEY_DIR_DOWN = 4
    HLM_KEY_DIR_LEFT = 5
    HLM_KEY_DIR_RIGHT = 6
    HLM_KEY_SELECT = 7
    HLM_KEY_BACK = 8
    HLM_KEY_MENU = 9
    HLM_KEY_HOME = 10
    HLM_KEY_MARK = 11
    HLM_KEY_SOFT_1 = 12
    HLM_KEY_SOFT_2 = 13
    HLM_KEY_SOFT_3 = 14
    HLM_KEY_SOFT_4 = 15
    HLM_KEY_SOFT_5 = 16
    HLM_KEY_SOFT_6 = 17
    HLM_KEY_SOFT_7 = 18
    HLM_KEY_SOFT_8 = 19
    HLM_KEY_PAD_1 = 20
    HLM_KEY_PAD_2 = 21
    HLM_KEY_PAD_3 = 22
    HLM_KEY_PAD_4 = 23
    HLM_KEY_PAD_5 = 24
    HLM_KEY_PAD_6 = 25
    HLM_KEY_PAD_7 = 26
    HLM_KEY_PAD_8 = 27
    HLM_KEY_PAD_9 = 28
    HLM_KEY_PAD_BS = 29
    HLM_KEY_PAD_0 = 30
    HLM_KEY_PAD_PUNC = 31
    HLM_KEY_NAV_INFO = 32
    HLM_KEY_FOCUS = 33
    HLM_KEY_KNOB_LEFT = 34
    HLM_KEY_KNOB_RIGHT = 35
    HLM_KEY_KNOB_PUSH = 36
    HLM_KEY_PRESET_1 = 37
    HLM_KEY_PRESET_2 = 38
    HLM_KEY_PRESET_3 = 39
    HLM_KEY_PRESET_4 = 40
    HLM_KEY_COUNT = 41


class KeyConfig(enum.IntEnum):
    """Physical key layout a device reports (HelmDevice.KeyConfig)."""

    HLM_KEY_CFG_NONE = 0  # touchscreen only, no hardware keys
    HLM_KEY_CFG_1 = 1
    HLM_KEY_CFG_2 = 2
    HLM_KEY_CFG_3 = 3
    HLM_KEY_CFG_4 = 4
    HLM_KEY_CONFIGURATION_COUNT = 5


# TOUCH_UNITY from HelmClientManager.HelmTouch: normalized [0,1] screen
# coordinates are multiplied by this to produce 16.16 fixed-point integers.
TOUCH_UNITY = 65536


class HelmTouch:
    """A single touch point, matching HelmClientManager.HelmTouch.

    x/y are normalized floats in [0.0, 1.0] measured from the top-left of the
    plotter screen. ``track_id`` groups points of a multi-touch gesture; ``down``
    is True for press/move and False for release.
    """

    __slots__ = ("track_id", "x", "y", "down")

    def __init__(self, track_id: int, x: float, y: float, down: bool):
        self.track_id = int(track_id)
        self.x = float(x)
        self.y = float(y)
        self.down = bool(down)

    @property
    def fixed_x(self) -> int:
        return int(self.x * TOUCH_UNITY)

    @property
    def fixed_y(self) -> int:
        return int(self.y * TOUCH_UNITY)

    def as_dict(self) -> dict:
        return {
            "trackId": self.track_id,
            "x": self.fixed_x,
            "y": self.fixed_y,
            "down": self.down,
        }

    def __repr__(self) -> str:
        state = "down" if self.down else "up"
        return f"HelmTouch(id={self.track_id}, {self.x:.3f},{self.y:.3f} {state})"


# Convenience: map common keyboard keys to Helm keys for the GUI/CLI.
KEYBOARD_MAP = {
    "plus": HelmKey.HLM_KEY_ZOOM_IN,
    "equal": HelmKey.HLM_KEY_ZOOM_IN,
    "minus": HelmKey.HLM_KEY_ZOOM_OUT,
    "Up": HelmKey.HLM_KEY_DIR_UP,
    "Down": HelmKey.HLM_KEY_DIR_DOWN,
    "Left": HelmKey.HLM_KEY_DIR_LEFT,
    "Right": HelmKey.HLM_KEY_DIR_RIGHT,
    "Return": HelmKey.HLM_KEY_SELECT,
    "space": HelmKey.HLM_KEY_SELECT,
    "BackSpace": HelmKey.HLM_KEY_BACK,
    "Escape": HelmKey.HLM_KEY_BACK,
    "m": HelmKey.HLM_KEY_MENU,
    "h": HelmKey.HLM_KEY_HOME,
    "k": HelmKey.HLM_KEY_MARK,
}
