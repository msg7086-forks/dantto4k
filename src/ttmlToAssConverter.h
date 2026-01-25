#pragma once

#include <string>
#include <string_view>
#include <cstdint>

class TtmlToAssConverter {
public:
    TtmlToAssConverter();

    // Converts a TTML string view to an ASS subtitle string.
    // The ASS header is prepended to the first conversion output.
    std::string convert(const std::string_view& ttmlInput);

private:
    // Formats milliseconds to ASS time format (H:MM:SS.cs).
    std::string formatTime(uint64_t ms);

    bool header_written_;
};
