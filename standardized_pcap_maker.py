from scapy.all import *
import sys
from random import shuffle
import string

max_payload_size = 1500 - 39

url_params = sys.argv

rules = ["time", "person", "year", "way", "day", "thing", "man", "world", "life", "hand", "part", "child", "eye",
         "woman", "place", "work", "week", "case", "point", "government", "google", "facebook", "youtube", "baidu",
         "yahoo", "amazon", "wikipedia", "qq", "twitter", "taobao", "live", "sina", "linkedin", "weibo", "ebay",
         "yandex", "hao123", "vk", "bing", "msn"]

packets = []

for i in range(10000):

    start_non_random = random.randint(0, max_payload_size)
    random_rule_string = ''.join(rules)
    length_of_rule_string = len(random_rule_string)

    divisor = max_payload_size / length_of_rule_string

    random_rule_string = random_rule_string*(divisor + 1)

    payload = ''.join(random.choice(string.lowercase) for x in range(start_non_random - 1)) + random_rule_string[start_non_random:max_payload_size]

    packet = a = IP()/UDP()/DNS()
    packet.payload.payload.payload = payload

    packets.append(packet)

wrpcap("fixed_length_random_contents.pcap", packets)
