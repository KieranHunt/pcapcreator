from scapy.all import *
import sys
from random import shuffle
import string

max_payload_size = 1500

url_params = sys.argv

a = rdpcap(url_params[1])

rules = ["time", "person", "year", "way", "day", "thing", "man", "world", "life", "hand", "part", "child", "eye",
         "woman", "place", "work", "week", "case", "point", "government", "google", "facebook", "youtube", "baidu",
         "yahoo", "amazon", "wikipedia", "qq", "twitter", "taobao", "live", "sina", "linkedin", "weibo", "ebay",
         "yandex", "hao123", "vk", "bing", "msn"]

for packet in a:
    shuffle(rules)
    random_rule_string = ''.join(rules)
    length_of_payload = len(packet.payload.payload.payload.payload.payload)
    length_of_rule_string = len(random_rule_string)

    divisor = max_payload_size / length_of_rule_string

    random_rule_string = random_rule_string*(divisor + 1)

    if (length_of_payload != 0):
        random_value_less_than_length = random.randint(1, length_of_payload)

        packet.payload.payload.payload.payload.payload = ''.join(random.choice(string.lowercase) for x in range(random_value_less_than_length - 1)) + random_rule_string[random_value_less_than_length:length_of_payload]

wrpcap("sort_of_random.pcap", a)
