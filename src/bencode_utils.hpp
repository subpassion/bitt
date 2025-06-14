#pragma once

#include <string>
#include <tuple>

#include "lib/nlohmann/json.hpp"

// TODO: mb use variant or any instead of json
using json = nlohmann::json;
using bencode_dictionary = std::map<std::string, json>;
using bencode_list = std::vector<json>;

class BencodeUtils {
public:
    static json decode_bencode_value(const std::string& encoded_value);
    static std::string encode_bencode(const json& bencoded_value);
    static std::string calculate_sha1(const std::string& data);

private:
    static std::tuple<json, int> decode_bencoded_value(const std::string& encoded_value, int start);
};