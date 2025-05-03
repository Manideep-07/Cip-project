import os
import pandas as pd
import joblib
import scapy.all as scapy
import numpy as np
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report

# =================== Step 1: Load and Process Dataset ===================
def train_model():
    file_path = "network_traffic.csv"
    df = pd.read_csv(file_path)
    df = df.drop(columns=[col for col in df.columns if 'Unnamed' in col], errors='ignore')
    X = df.drop(columns=["label"])
    y = df["label"]

    imputer = SimpleImputer(strategy='mean')
    X = imputer.fit_transform(X)

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100),
        "Decision Tree": DecisionTreeClassifier(),
        "KNN": KNeighborsClassifier(n_neighbors=5)
    }

    best_model = None
    best_accuracy = 0

    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Accuracy of {name}: {accuracy:.4f}")
        print(classification_report(y_test, y_pred))
        if accuracy > best_accuracy:
            best_model = model
            best_accuracy = accuracy

    joblib.dump(best_model, "best_firewall_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(imputer, "imputer.pkl")

train_model()

model = joblib.load("best_firewall_model.pkl")
scaler = joblib.load("scaler.pkl")
imputer = joblib.load("imputer.pkl")

blocked_packets = []
sniffing = False
sniff_thread = None

# =================== Feature Extraction ===================
def extract_features(packet):
    protocol_number = -1
    source_port = 0
    destination_port = 0
    flags = 0

    if packet.haslayer(scapy.IP):
        protocol_number = packet[scapy.IP].proto
    if packet.haslayer(scapy.TCP):
        source_port = packet[scapy.TCP].sport
        destination_port = packet[scapy.TCP].dport
        flags = int(packet[scapy.TCP].flags)
    elif packet.haslayer(scapy.UDP):
        source_port = packet[scapy.UDP].sport
        destination_port = packet[scapy.UDP].dport

    packet_length = len(packet)
    return [protocol_number, packet_length, source_port, destination_port, flags]

# =================== GUI Code ===================
app = tk.Tk()
app.title("Real-Time ML Firewall")
app.geometry("900x500")

log_text = tk.Text(app, height=15)
log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

packet_list = ttk.Treeview(app, columns=("Protocol", "Length", "Src Port", "Dst Port", "Flags", "IP", "Status"), show="headings")
for col in packet_list["columns"]:
    packet_list.heading(col, text=col)
packet_list.pack(fill=tk.BOTH, padx=10, expand=True)

# Add tag colors
packet_list.tag_configure("Blocked", background="lightcoral")
packet_list.tag_configure("Allowed", background="lightgreen")

# Manual allow function (Updated with status update)
def allow_packet():
    selected = packet_list.selection()
    for item in selected:
        values = packet_list.item(item, "values")
        protocol, length, src_port, dst_port, flags, ip, _ = values
        log_text.insert(tk.END, f"✅ Packet manually allowed: Protocol={protocol}, Length={length}, Src Port={src_port}, Dst Port={dst_port}, Flags={flags}, From IP={ip}\n")

        # Update status to Allowed
        new_values = (protocol, length, src_port, dst_port, flags, ip, "Allowed")
        packet_list.item(item, values=new_values, tags=("Allowed",))

        # Remove from blocked_packets if present
        try:
            features = [int(protocol), int(length), int(src_port), int(dst_port), int(flags)]
            blocked_packets.remove((features, ip))
        except ValueError:
            pass

# Clear log and blocked packet list
def clear_logs():
    log_text.delete("1.0", tk.END)
    for item in packet_list.get_children():
        packet_list.delete(item)
    blocked_packets.clear()
    log_text.insert(tk.END, "🧹 Logs and blocked packet list cleared.\n")

# Packet processing function
def process_packet(packet):
    global blocked_packets
    features = extract_features(packet)
    try:
        feature_vector = pd.DataFrame([features], columns=["protocol", "packet_length", "source_port", "destination_port", "flags"])
        imputed = imputer.transform(feature_vector)
        scaled = scaler.transform(imputed)
        prediction = model.predict(scaled)[0]

        if prediction == 0:
            log_text.insert(tk.END, f"✅ Packet Allowed: {features}\n")
        else:
            if packet.haslayer(scapy.IP):
                source_ip = packet[scapy.IP].src
                log_text.insert(tk.END, f"🚨 Packet Blocked: {features} From {source_ip}\n")
                blocked_packets.append((features, source_ip))
                packet_list.insert("", tk.END, values=features + [source_ip, "Blocked"], tags=("Blocked",))
    except Exception as e:
        log_text.insert(tk.END, f"⚠ Error: {e}\n")

# Start and Stop Functions
def start_sniffing():
    global sniffing, sniff_thread
    sniffing = True
    sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing))
    sniff_thread.start()
    log_text.insert(tk.END, "🔍 Started monitoring traffic...\n")

def stop_sniffing():
    global sniffing
    sniffing = False
    log_text.insert(tk.END, "⛔ Stopped monitoring.\n")

# Buttons
button_frame = tk.Frame(app)
button_frame.pack(pady=10)

start_btn = tk.Button(button_frame, text="Start Monitoring", command=start_sniffing)
start_btn.grid(row=0, column=0, padx=5)

stop_btn = tk.Button(button_frame, text="Stop Monitoring", command=stop_sniffing)
stop_btn.grid(row=0, column=1, padx=5)

allow_btn = tk.Button(button_frame, text="Allow Selected Packet", command=allow_packet)
allow_btn.grid(row=0, column=2, padx=5)

clear_btn = tk.Button(button_frame, text="Clear Logs", command=clear_logs)
clear_btn.grid(row=0, column=3, padx=5)

app.mainloop()
