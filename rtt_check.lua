 
-- Lua script for Wireshark that compares measured TCP or ICMP RTT
-- with the average RTT of the source IP's country, based on MaxMind data

--##################################################

-- Continent mapping based on latitude and longitude (approximate)
local continents = {

    ["Oceania"] = {
        {-11.88, 110}, {33.13, 140}, {-5, 165}, {-5, 180},
        {-52.5, 180}, {-52.5, 142.5}, {-31.88, 110}
    },
    ["Antarctica"] = {
        {-60, -180}, {-60, 180}, {-90, 180}, {-90, -180}
    },
    ["Africa"] = {
        {15, -30}, {28.25, -13}, {35.42, -10}, {38, 10},
        {33, 27.5}, {31.74, 34.58}, {29.54, 34.92},
        {27.78, 34.46}, {11.3, 44.3}, {12.5, 52},
        {-60, 75}, {-60, -30}
    },
    ["Europe"] = {
        {90, -10}, {90, 77.5}, {42.5, 48.8}, {42.5, 30},
        {40.79, 28.81}, {41, 29}, {40.55, 27.31}, {40.4, 26.75},
        {40.05, 26.36}, {39.17, 25.19}, {35.46, 27.91}, {33, 27.5},
        {38, 10}, {35.42, -10}, {28.25, -13}, {15, -30},
        {57.5, -37.5}, {78.13, -10}
    },
    ["North-America"] = {
        {90, -168.75}, {90, -10}, {78.13, -10}, {57.5, -37.5},
        {15, -30}, {15, -75}, {1.25, -82.5}, {1.25, -105},
        {51, -180}, {60, -180}, {60, -168.75}
    },
    ["South-America"] = {
        {1.25, -105}, {1.25, -82.5}, {15, -75}, {15, -30},
        {-60, -30}, {-60, -105}
    },
    ["Asia"] = {
        {90, 77.5}, {42.5, 48.8}, {42.5, 30}, {40.79, 28.81},
        {41, 29}, {40.55, 27.31}, {40.4, 26.75}, {40.05, 26.36},
        {39.17, 25.19}, {35.46, 27.91}, {33, 27.5}, {31.74, 34.58},
        {29.54, 34.92}, {27.78, 34.46}, {11.3, 44.3}, {12.5, 52},
        {-60, 75}, {-60, 110}, {-31.88, 110}, {-11.88, 110},
        {33.13, 140}, {51, 166.6}, {60, 180},
        {90, 180}
    }
}

-- Function that checks if a point (lat, lon) is inside a polygon defined by its vertices -> Ray-Casting algorithm
-- The basic idea is to cast a horizontal ray from the point and count
-- how many times it intersects the polygon edges. If the number of
-- intersections is odd, the point is inside; if even, it's outside.
function is_point_in_polygon(point, polygon)

    local x, y = point[1], point[2]  -- Extract latitude (x) and longitude (y) from the point
    local n = #polygon               -- Number of polygon vertices
    local inside = false             -- Tracks whether the point is inside the polygon

    -- Itera su ogni lato del poligono
    for i = 1, n do

        local x1, y1 = polygon[i][1], polygon[i][2]                      -- Start vertex of the edge
        local x2, y2 = polygon[(i % n) + 1][1], polygon[(i % n) + 1][2]  -- End vertex of the edge

        -- Check if the point's latitude (y) is between the two vertices
        if (y1 > y) ~= (y2 > y) then
            -- Compute the longitude of the intersection between the edge and the horizontal line at `y`
            local x_intersection = (y - y1) * (x2 - x1) / (y2 - y1) + x1

            -- If the point is to the left of the intersection (x < x_intersection),
            -- flip the `inside` flag to determine containment
            if x < x_intersection then
                inside = not inside
            end
        end
    end

    -- Returns true if the point is inside the polygon, false otherwise
    return inside
end

-- Function that returns the name of the continent containing the point
function get_continent(point, continents)
    -- Iterate over each continent polygon
    for continent, polygon in pairs(continents) do
        if is_point_in_polygon(point, polygon) then
            return continent
        end
    end

    return "Unknown"  -- If no polygon contains the point
end

--##################################################

-- Function to read a txt file and create the rtt_reference structure
function create_rtt_reference(file_path)

    local rtt_reference = {}
    local file = io.open(file_path, "r")
    -- Error handling in Wireshark
    if not file then
        error("File not found: " .. file_path)
    end

    -- Read each line of the file
    for line in file:lines() do
        -- Split the line into comma-separated fields
        local country_code, mean, stddev = line:match("([^,]+),([^,]+),([^,]+)")
        -- For valid data
        if country_code and mean and stddev then

            rtt_reference[country_code] = {
                mean = tonumber(mean),     -- Convert mean to number
                stddev = tonumber(stddev)  -- Convert stddev to number
            }

        end
    end

    file:close()
    return rtt_reference

end

-- Determine path separator based on the operating system
local separator = package.config:sub(1,1)  -- '/' on Unix-like, '\\' on Windows
local file_path = Dir.personal_plugins_path() .. separator .. "ntp_rtt_stats.txt"
local rtt_reference = create_rtt_reference(file_path)

-- Function to determine the country with the closest mean RTT
local function estimate_response_country(rtt)

    local best_match = "Unknown"
    local min_difference = math.huge
    
    for country, stats in pairs(rtt_reference) do

        local diff = math.abs(rtt - stats.mean)

        --print("country, mean, diff: ",country, stats.mean, diff)

        if diff < min_difference then
            min_difference = diff
            best_match = country
        end

    end
    
    return best_match

end

--##################################################

-- Creation of the protocol Proto(short_name, long_name)
local rtt_checker = Proto("RTTCheck", "RTT Anomaly Detector")

-- Wireshark fields for protocol operations
local o_rtt_tcp = Field.new("tcp.analysis.ack_rtt")         -- field for RTT in TCP/TLS packets
local o_icmp_resptime = Field.new("icmp.resptime")          -- field for RTT in ICMP packets

-- Use source fields because source/destination may contain multiple values
local o_geoip_src = Field.new("ip.geoip.src_country_iso")   -- ISO country code field
local o_geoip_lon = Field.new("ip.geoip.src_lon")           -- source country longitude
local o_geoip_lat = Field.new("ip.geoip.src_lat")           -- source country latitude

--##################################################

-- Post-Dissector that works for ICMP e TCP
function rtt_checker.dissector(buffer, pinfo, tree)

    local icmp_resptime = o_icmp_resptime() and o_icmp_resptime().value

    if icmp_resptime then
        -- Convert NSTime value to string then to number
        icmp_resptime = tostring(icmp_resptime)  -- Convert NSTime to string
        icmp_resptime = tonumber(icmp_resptime)  -- Convert string to number
        icmp_resptime = icmp_resptime            -- In milliseconds
    end

    local rtt_tcp = o_rtt_tcp() and o_rtt_tcp().value

    if rtt_tcp then
        rtt_tcp = tostring(rtt_tcp)
        rtt_tcp = tonumber(rtt_tcp)
        rtt_tcp = rtt_tcp * 1000
    end

    local rtt_value = rtt_tcp or icmp_resptime

    if rtt_value then

        --print("icmp_resptime:", icmp_resptime)
        --print("rtt_value:", rtt_value)
        local country = o_geoip_src() and tostring(o_geoip_src().value)
        local lat = o_geoip_lat() and tonumber(o_geoip_lat().value)
        local lon = o_geoip_lon() and tonumber(o_geoip_lon().value)
        
        if country and lat and lon then

            local mean = -1
            local stddev
            local threshold_upper = 0
            local threshold_lower = math.huge
            local continent = "Unknown"
            local estimated_country = estimate_response_country(rtt_value) 
            local used_country

            -- If the country entry is not present, we'll use the continent
            if not rtt_reference[country] then

                local point = {lat, lon}
                continent = get_continent(point, continents)

            end

            if rtt_reference[country] then used_country = country else used_country = continent end

            if rtt_reference[used_country] then

                mean = rtt_reference[used_country].mean
                stddev = rtt_reference[used_country].stddev

                -- Threshold values are 2 times the standard deviation (k value)
                threshold_upper = mean + (2 * stddev)  -- Upper threshold
                threshold_lower = mean - (2 * stddev)  -- Lower threshold

            end

            -- If RTT is outside thresholds and the estimated country differs from the used country, report anomaly
            if (rtt_value > threshold_upper or rtt_value < threshold_lower) and estimated_country ~= used_country then
 
                local subtree = tree:add(rtt_checker, "RTT Anomaly"):set_generated()
                subtree:add("Detected country: ", country):set_generated()
                subtree:add("Expected RTT: ", string.format("%f ms", mean)):set_generated()
                subtree:add("Measured RTT: ", string.format("%f ms", rtt_value)):set_generated()
                subtree:add("Estimated country: ", estimated_country):set_generated()
                subtree:add_expert_info(expert.group.PROTOCOL, expert.severity.ERROR, "RTT mismatch detected")

            end
        end
    end
end

--##################################################

-- Registrazione del protocollo come post-dissector
register_postdissector(rtt_checker)

-- Function that displays the RTT reference table
local function menu_view_reference_rtt()
    -- Text window with title
    local win = TextWindow.new("RTT Reference Table")
    -- Window header
    win:append("=== RTT Reference Values by Country & Continent ===\n\n")
    -- Column header
    win:append(string.format("  %-16s  %-15s  %-15s\n", "Country", "Mean RTT (ms)", "StdDev (ms)"))
    win:append(string.rep("-", 52) .. "\n")
    for country, stats in pairs(rtt_reference) do
        -- Show each country's mean and standard deviation
        win:append(string.format("  %-16s  %-15.2f  %-15.2f\n", country, stats.mean, stats.stddev))
    end

end

-- Register the menu item under "RTT" named "View RTT Reference Table"
-- Invokes the function 'menu_view_reference_rtt'
-- register_menu(string, function, where)
register_menu("RTT/View RTT Reference Table", menu_view_reference_rtt, MENU_TOOLS_UNSORTED)

--##################################################
