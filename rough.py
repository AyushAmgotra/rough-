import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, raw
from collections import defaultdict, deque
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import subprocess

# Global variables
ip_counter = defaultdict(int)
captured_packets = []
sniffing = False
protocol_filter = "ip"
packet_rate = deque(maxlen=50)
timestamps = deque(maxlen=50)
suspicious_ips = set()
iot_devices = {"192.168.1.10", "192.168.1.20"}  # Example IoT device IPs

# --- Future Feature 1: Automatic Protocol Identification ---
def detect_protocol(packet):
    """Simple demo function for automatic protocol identification"""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(IP):
        return "IP"
    else:
        return "Unknown"

# --- Future Feature 2: Automated Mitigation (Firewall Block) ---
def block_ip(ip):
    if ip not in suspicious_ips:
        suspicious_ips.add(ip)
        try:
            # Linux firewall block (change for Windows: netsh advfirewall)
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            messagebox.showwarning("Mitigation", f"🚨 Suspicious IP blocked: {ip}")
        except Exception as e:
            print("Error blocking IP:", e)

# --- Future Feature 3: IoT Anomaly Detection ---
def detect_iot_anomaly(ip, count):
    """Detect unusual traffic from IoT devices"""
    if ip in iot_devices and count > 50:  # Example rule
        messagebox.showwarning("IoT Alert", f"⚠️ IoT Device {ip} unusual traffic detected!")
        block_ip(ip)

# Update IP table
def update_table():
    for row in ip_tree.get_children():
        ip_tree.delete(row)
    for ip, count in ip_counter.items():
        ip_tree.insert("", "end", values=(ip, count))

# Update Packet List
def update_packet_list(packet):
    proto = detect_protocol(packet)
    packet_list.insert(tk.END, f"[{proto}] {packet.summary()}")
    packet_list.yview(tk.END)

# Process each packet
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        ip_counter[src_ip] += 1
        ip_counter[dst_ip] += 1
        captured_packets.append(packet)

        update_table()
        update_packet_list(packet)

        # IoT anomaly detection
        detect_iot_anomaly(src_ip, ip_counter[src_ip])

        # Example auto-mitigation rule: too many packets from one IP
        if ip_counter[src_ip] > 100:
            block_ip(src_ip)

        # Update packet rate
        now = time.time()
        if not timestamps or now - timestamps[-1] >= 1:
            timestamps.append(now)
            packet_rate.append(len(captured_packets))
            update_graph()

# Show packet details
def show_packet_details(event):
    selection = packet_list.curselection()
    if not selection:
        return
    index = selection[0]
    packet = captured_packets[index]

    details = []
    proto = detect_protocol(packet)
    details.append(f"Detected Protocol: {proto}")

    if packet.haslayer(IP):
        details.append(f"Source IP: {packet[IP].src}")
        details.append(f"Destination IP: {packet[IP].dst}")

    if packet.haslayer(TCP):
        details.append(f"Source Port: {packet[TCP].sport}")
        details.append(f"Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        details.append(f"Source Port: {packet[UDP].sport}")
        details.append(f"Destination Port: {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        details.append("ICMP Packet")

    try:
        payload = raw(packet).decode(errors="ignore")
        details.append(f"Payload (raw):\n{payload[:300]}")
    except:
        details.append("Payload: [Binary/Not Decodable]")

    detail_win = tk.Toplevel(root)
    detail_win.title("Packet Details")
    detail_win.geometry("500x400")

    text_box = tk.Text(detail_win, wrap="word")
    text_box.pack(fill="both", expand=True)
    text_box.insert("1.0", "\n".join(details))
    text_box.config(state="disabled")

# Start sniffing
def start_sniffing():
    global sniffing, protocol_filter
    sniffing = True
    selected = filter_var.get()

    if selected == "All":
        protocol_filter = "ip"
    elif selected == "TCP":
        protocol_filter = "tcp"
    elif selected == "UDP":
        protocol_filter = "udp"
    elif selected == "ICMP":
        protocol_filter = "icmp"

    threading.Thread(
        target=lambda: sniff(
            filter=protocol_filter,
            prn=process_packet,
            store=False,
            stop_filter=lambda p: not sniffing
        ),
        daemon=True
    ).start()
    status_label.config(text=f"🔴 Sniffing Running... ({selected})")

# Stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="🟢 Sniffing Stopped.")

# Save packets
def save_packets():
    if captured_packets:
        wrpcap("captured_packets.pcap", captured_packets)
        messagebox.showinfo("Saved", "✅ Packets saved in 'captured_packets.pcap'")
    else:
        messagebox.showwarning("No Packets", "⚠️ No packets captured yet.")

# Update Graph
def update_graph():
    ax.clear()
    ax.plot(range(len(packet_rate)), packet_rate, marker="o")
    ax.set_title("Live Packet Rate")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packets Captured")
    canvas.draw()

# GUI setup
root = tk.Tk()
root.title(" Network Packet Sniffer BLOCK AUTOMATION")
root.geometry("1000x650")

# Buttons & Filter
frame = tk.Frame(root)
frame.pack(pady=10)

start_btn = tk.Button(frame, text="▶ Start", command=start_sniffing, bg="green", fg="white", width=10)
start_btn.grid(row=0, column=0, padx=5)

stop_btn = tk.Button(frame, text="⏹ Stop", command=stop_sniffing, bg="red", fg="white", width=10)
stop_btn.grid(row=0, column=1, padx=5)

save_btn = tk.Button(frame, text="💾 Save Packets", command=save_packets, bg="blue", fg="white", width=15)
save_btn.grid(row=0, column=2, padx=5)

# Protocol Filter
filter_var = tk.StringVar(value="All")
filter_label = tk.Label(frame, text="Filter:")
filter_label.grid(row=0, column=3, padx=5)
filter_menu = ttk.Combobox(frame, textvariable=filter_var, values=["All", "TCP", "UDP", "ICMP"], width=10, state="readonly")
filter_menu.grid(row=0, column=4, padx=5)

# Status label
status_label = tk.Label(root, text="🟢 Ready.", font=("Arial", 12))
status_label.pack(pady=5)

# Split frame for IPs + Packets
split_frame = tk.Frame(root)
split_frame.pack(fill="both", expand=True, padx=10, pady=10)

# IP Table
ip_frame = tk.LabelFrame(split_frame, text="Active IPs")
ip_frame.pack(side="left", fill="both", expand=True, padx=5)

ip_columns = ("IP Address", "Packets")
ip_tree = ttk.Treeview(ip_frame, columns=ip_columns, show="headings", height=15)
ip_tree.heading("IP Address", text="IP Address")
ip_tree.heading("Packets", text="Packets")
ip_tree.pack(fill="both", expand=True)

# Packet List
packet_frame = tk.LabelFrame(split_frame, text="Captured Packets")
packet_frame.pack(side="left", fill="both", expand=True, padx=5)

packet_list = tk.Listbox(packet_frame, width=60, height=20)
packet_list.pack(fill="both", expand=True)
packet_list.bind("<Double-1>", show_packet_details)

# Graph
graph_frame = tk.LabelFrame(root, text="Traffic Graph")
graph_frame.pack(fill="both", expand=True, padx=10, pady=10)

fig, ax = plt.subplots(figsize=(6,3))
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack(fill="both", expand=True)

root.mainloop()

