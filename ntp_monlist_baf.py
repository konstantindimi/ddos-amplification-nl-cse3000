import csv
import threading
from queue import Queue
from scapy.all import *

THREADS = 10

def valid_ntp_response(packet, ip):
    valid_ntp = (IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 123
                 and len(packet) >= 48 and packet[UDP].dport == 123)
    return valid_ntp

def send_ntp_request(ip, results_queue):
    try:
        ntp_packet = IP(dst=ip) / UDP(dport=123) / NTPPrivate(mode=7, implementation="XNTPD", request_code="REQ_MON_GETLIST_1")
        send(ntp_packet, verbose=0)
        responses = sniff(lfilter=lambda x: valid_ntp_response(x, ip), timeout=2)
        response_length = sum(len(resp[UDP].payload) for resp in responses)
        if responses:
            request_length = len(ntp_packet[UDP].payload)
            results_queue.put({"IP": ip, "Request Length": request_length, "Response Length": response_length})
    except Exception as e:
        pass

def worker():
    while True:
        item = ip_queue.get()
        if item is None:
            break
        ip = item["ip"]
        send_ntp_request(ip, results_queue)
        ip_queue.task_done()

def get_baf(input_file="", output_file=""): #Input and output file paths
    global ip_queue, results_queue
    ip_queue = Queue()
    results_queue = Queue()
    results = []

    with open(input_file, "r") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ip_queue.put(row)

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    ip_queue.join()

    for _ in range(THREADS):
        ip_queue.put(None)
    for t in threads:
        t.join()

    while not results_queue.empty():
        result = results_queue.get()
        request_length = result["Request Length"]
        response_length = result["Response Length"]
        ratio = response_length / request_length if request_length != 0 else 0
        result["BAF"] = ratio
        results.append(result)

    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["IP", "Request Length", "Response Length", "BAF"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

get_baf("")

