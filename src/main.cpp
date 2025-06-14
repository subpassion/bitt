#include <cassert>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include "bencode_utils.hpp"
#include "lib/nlohmann/json.hpp"

int main(int argc, char* argv[])
{
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    if (argc < 2)
    {
        std::cerr << std::format("Usage: {} info|test|decode\n", argv[0]);
        return 1;
    }

    auto command = std::string{argv[1]};
    if (command == "decode")
    {
        if (argc < 3)
        {
            std::cerr << std::format("Usage: {} decode <bencoded_value>\n", argv[0]);
            return 1;
        }

        auto encoded_value = std::string(argv[2]);
        auto decoded_value = BencodeUtils::decode_bencode_value(encoded_value);
        std::cout << decoded_value.dump();
    }
    else if (command == "info")
    {
        if (argc < 3)
        {
            std::cerr << std::format("Usage: {} info <torrent file>\n", argv[0]);
            return 1;
        }

        auto torrent_file = std::string(argv[2]);
        std::ifstream ifs(torrent_file, std::fstream::binary);
        std::stringstream file_content;
        file_content << ifs.rdbuf();

        auto file_content_str = file_content.str();
        auto meta_info = BencodeUtils::decode_bencode_value(file_content_str);
        auto meta_info_dict = meta_info.get<bencode_dictionary>();
        auto info_dict = meta_info_dict["info"].get<bencode_dictionary>();
        auto encoded_info_dict = BencodeUtils::encode_bencode(info_dict);
        auto hash = BencodeUtils::calculate_sha1(encoded_info_dict);
        auto pieces = info_dict["pieces"].get<std::string>();

        std::cout << std::format("Tracker URL: {}\n", meta_info_dict["announce"].get<std::string>());
        std::cout << std::format("The length of the file is: {}\n", info_dict["length"].dump());
        std::cout << std::format("Info hash: {}\n", hash);
        std::cout << "Piece Hashes:\n";
        
        for (auto current_piece_index = 0; current_piece_index < pieces.size(); current_piece_index += BencodeUtils::SHA1_HASH_SIZE) 
        {
            auto current_piece = pieces.substr(current_piece_index, BencodeUtils::SHA1_HASH_SIZE);
            std::cout << BencodeUtils::sha1_to_hex(current_piece) << std::endl;
        }
    }
    // TODO: use google test
    else if (command == "test") 
    {
        // test numbers
        {
            try 
            {
                std::unordered_map<std::string, int> test_numbers {
                    {"i32e", 32 },
                    {"i-32e", -32},
                    {"i0e", 0}
                };
                for (auto&& [bencoded_value, expected_value] : test_numbers)
                {
                    auto decoded_number = BencodeUtils::decode_bencode_value(bencoded_value);
                    assert(decoded_number.get<int>() == expected_value);
                }
                std::cout << "[OK] Test numbers\n";
            }
            catch (std::exception e) 
            {
                std::cout << std::format("[ERROR] Test numbers {}\n", e.what());
            }
        }
        // test strings
        {
            try
            {
                std::unordered_map<std::string, std::string> test_strings {
                    {"5:hello", "hello" },
                    {"1:h", "h"},
                };
                for (auto&& [bencoded_value, expected_value] : test_strings)
                {
                    auto decoded_string = BencodeUtils::decode_bencode_value(bencoded_value);
                    assert(decoded_string.get<std::string>() == expected_value);
                }
                std::cout << "[OK] Test strings\n";
            }
            catch (std::exception e)
            {
                std::cout << std::format("[ERROR] Test strings {}\n", e.what());
            }
        }
        // test lists
        {
            try {
                auto list = BencodeUtils::decode_bencode_value("li32elleei42ee");
                assert(list.is_array());

                auto json_list = list.get<bencode_list>();
                assert(json_list[0].get<int>() == 32);
                assert(json_list[1].is_array());
                assert(json_list[1].get<bencode_list>().size() == 1);
                assert(json_list[1].get<bencode_list>()[0].get<bencode_list>().empty());
                assert(json_list[2].get<int>() == 42);
                std::cout << "[OK] Test lists\n";
            }
            catch (std::exception e)
            {
                std::cout << std::format("[ERROR] Test lists {}\n", e.what());
            }
        }
        // test dictionaries
        {
            try 
            {
                auto dict = BencodeUtils::decode_bencode_value("d9:publisher3:bob17:publisher-webpage15:www.example.com18:publisher.location4:homee");
                auto json_map = dict.get<std::map<std::string, json>>();
                assert(json_map["publisher"] == "bob");
                assert(json_map["publisher-webpage"] == "www.example.com");
                assert(json_map["publisher.location"] == "home");
                std::cout << "[OK] Test dictionaries\n";
            }
            catch (std::exception e)
            {
                std::cout << std::format("[ERROR] Test dictionaries {}\n", e.what());
            }
        }
    } 
    else
    {
        std::cerr << std::format("Unknown command: {}\n ", command);
        return 1;
    }

    return 0;
}