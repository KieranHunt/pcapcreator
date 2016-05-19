from scapy.all import *
import sys
from random import shuffle

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

    packet.payload.payload.payload.payload.payload = random_rule_string[:length_of_payload]

wrpcap("not_so_random.pcap", a)
