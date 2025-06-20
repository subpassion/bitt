#pragma once

#include <string>
#include <tuple>
#include <vector>

#include "lib/nlohmann/json.hpp"

// TODO: mb use variant or any instead of json
using json = nlohmann::json;
using bencode_dictionary = std::map<std::string, json>;
using bencode_list = std::vector<json>;
using ip_and_port = std::tuple<std::string, uint16_t>;

class BencodeUtils
{
public:
    static constexpr uint8_t SHA1_HASH_SIZE = 20;

    static json decode_bencode_value(const std::string &encoded_value);
    static std::string encode_bencode(const json &bencoded_value);
    static std::string calculate_sha1(const std::string &data);
    static std::string sha1_to_hex(const std::string &hash);
    static std::string read_to_string(const std::string &file_path);
    static std::vector<ip_and_port> parse_peers_addresses(const std::string &peers);

private:
    static std::tuple<json, int> decode_bencoded_value(const std::string &encoded_value, int start);
};