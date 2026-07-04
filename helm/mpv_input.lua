-- mpv input bridge for garmin-helm-linux.
-- Emits the mouse position over the video as script-messages that the GUI reads
-- via the JSON IPC socket:  "helm_touch <down|move|up> <nx> <ny>"
-- nx,ny are normalized [0,1] within the actual video rectangle (letterbox aware).

local dragging = false

local function norm()
    local pos = mp.get_property_native("mouse-pos")
    local d = mp.get_property_native("osd-dimensions")
    if not pos or not d then return nil end
    local vw = d.w - d.ml - d.mr
    local vh = d.h - d.mt - d.mb
    if vw <= 0 or vh <= 0 then return nil end
    local nx = (pos.x - d.ml) / vw
    local ny = (pos.y - d.mt) / vh
    if nx < 0 then nx = 0 elseif nx > 1 then nx = 1 end
    if ny < 0 then ny = 0 elseif ny > 1 then ny = 1 end
    return nx, ny
end

local function emit(state)
    local nx, ny = norm()
    if not nx then return end
    mp.commandv("script-message", "helm_touch", state,
                string.format("%.5f", nx), string.format("%.5f", ny))
end

-- Always-on poller (~33 Hz); only forwards while a drag is active. Reads a
-- fresh mouse-pos each tick, so a press-and-drag streams moving coordinates.
mp.add_periodic_timer(0.03, function()
    if dragging then emit("move") end
end)

mp.add_key_binding("MBTN_LEFT", "helm_mbtn_left", function(e)
    if e.event == "down" then
        dragging = true
        emit("down")
    elseif e.event == "up" then
        dragging = false
        emit("up")
    end
end, { complex = true })
