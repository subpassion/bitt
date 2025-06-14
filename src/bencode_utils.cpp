#include "bencode_utils.hpp"

#include <format>
#include <iostream>
#include <openssl/sha.h>

json BencodeUtils::decode_bencode_value(const std::string& encoded_value)
{
    auto&& [decoded_value, _] = BencodeUtils::decode_bencoded_value(encoded_value, 0);
    return decoded_value;
}

std::tuple<json, int> BencodeUtils::decode_bencoded_value(const std::string& encoded_value, int start)
{
    if (std::isdigit(encoded_value[start])) 
    {
        // Example: "5:hello" -> "hello"
        size_t colon_index = encoded_value.find(':', start);
        if (colon_index != std::string::npos) 
        {
            auto string_length_str = encoded_value.substr(start, colon_index == 1 ? 1 : colon_index - 1);
            auto string_length = std::atoll(string_length_str.c_str());
            auto str = encoded_value.substr(colon_index + 1, string_length);
            return {json(str), colon_index + string_length + 1};
        }
        else 
        {
            throw std::runtime_error(std::format("Invalid encoded value: {}", encoded_value));
        }
    } 
    else if (encoded_value[start] == 'i' && encoded_value.size() > 1) 
    {
        // Example: i-32e
        auto end_of_number = encoded_value.find_first_of('e', start);
        if (end_of_number != std::string::npos) 
        {
            auto number_string = encoded_value.substr(start + 1, end_of_number - (start + 1));
            // numbers that start with 0 - are not valid (except 0)
            if (number_string.starts_with("-0") || (number_string.size() >=2 && number_string.starts_with("0"))) 
            {
                throw std::runtime_error("Invalid encoded number: " + encoded_value);
            }
            auto number = std::atoll(number_string.c_str());
            return {json(number), end_of_number + 1};
        } 
        else 
        {
            throw std::runtime_error(std::format("Invalid encoded number: {}", encoded_value));
        }
    } 
    else if (encoded_value[start] == 'l') 
    {
        auto bencoded_values = bencode_list{};
        auto ls_index = start + 1;
        while (encoded_value[ls_index] != 'e') 
        {
            auto&& [decoded_value, next] = decode_bencoded_value(encoded_value, ls_index);
            bencoded_values.push_back(decoded_value);
            ls_index = next;
        }
        return {bencoded_values, ls_index + 1};
    }
    else if (encoded_value[start] == 'd') 
    {
        auto dict = bencode_dictionary{};
        auto ls_index = start + 1;
        while (encoded_value[ls_index] != 'e') 
        {
            auto&& [key, value_start] = decode_bencoded_value(encoded_value, ls_index);
            if (key.is_string())
            {
                auto&& [value, next] = decode_bencoded_value(encoded_value, value_start);
                dict[key] = value;
                ls_index = next;
            }
            else 
            {
                throw std::runtime_error(std::format("Wrong key type in the dictionary. Key must be string, but got: {}", key.type_name()));
            }
        }
        return {dict, ls_index + 1};
    }
    else 
    {
        throw std::runtime_error(std::format("Unhandled encoded value: {}", encoded_value));
    }
    return {"", std::string::npos};
}

std::string BencodeUtils::calculate_sha1(const std::string& data)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);

    auto result = std::string{};
    result.reserve(SHA_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) 
    {
        result += std::format("{:02x}", static_cast<int>(hash[i]));
    }

    return result;
}

std::string BencodeUtils::encode_bencode(const json& bencoded_value)
{
    if (bencoded_value.is_number_integer())
    {
        return std::format("i{}e", bencoded_value.get<int>());
    }
    else if (bencoded_value.is_string())
    {
        auto bencoded_str = bencoded_value.get<std::string>();
        return std::format("{}:{}", bencoded_str.size(), bencoded_str);
    }
    else if (bencoded_value.is_array())
    {
        auto encoded_list = std::string{};
        for (auto& value : bencoded_value.get<bencode_list>()) 
        {
            encoded_list += encode_bencode(value);
        }
        return encoded_list;
    }
    else if (bencoded_value.is_object())
    {
        auto encoded_dictionary = std::string{"d"};
        for (auto&& [value, key] : bencoded_value.get<bencode_dictionary>()) 
        {
            encoded_dictionary += encode_bencode(value);
            encoded_dictionary += encode_bencode(key);
        }
        encoded_dictionary += "e";
        return encoded_dictionary;
    } 
    else 
    {
        throw std::runtime_error(std::format("Unkown bencoded object: {}", bencoded_value.dump()));
    }
    return "";
}
