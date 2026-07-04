"""Reverse-engineered Helm hardware-key reference.

NOTE: keys are not wired into the client yet — the captured session only
contained touch input, so the key *message* format is not yet known. This
module preserves the key enums (from the app's HelmClientManager) for whoever
adds key support after capturing a session with a few button presses. The
touch model that IS implemented lives in helm_client.py.
"""

from __future__ import annotations

import enum


class HelmKey(enum.IntEnum):
    """Physical/soft keys, in the ordinal order used by the app (wire value =
    position; only a subset exists on any given plotter)."""

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


class KeyConfig(enum.IntEnum):
    """Physical key layout a device reports (HelmDevice.KeyConfig)."""

    HLM_KEY_CFG_NONE = 0  # touchscreen only, no hardware keys
    HLM_KEY_CFG_1 = 1
    HLM_KEY_CFG_2 = 2
    HLM_KEY_CFG_3 = 3
    HLM_KEY_CFG_4 = 4
