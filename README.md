# Cip-project
# Real-Time Machine Learning Firewall with GUI

This project is a real-time firewall monitoring system that uses machine learning to classify and block suspicious network packets. It features a Tkinter-based GUI that displays allowed and blocked packets, and allows manual packet control.

------------------
FEATURES
------------------
- Trains a machine learning model (Random Forest, Decision Tree, or KNN).
- Classifies packets in real-time.
- Interactive GUI with logs and manual control.
- Color-coded packet table (Blocked = Red, Allowed = Green).
- Allows packet manually and clears logs.

------------------
PROJECT STRUCTURE
------------------
project/
├── network_traffic.csv
├── best_firewall_model.pkl
├── scaler.pkl
├── imputer.pkl
├── firewall_gui.py
└── README.txt

------------------
REQUIREMENTS
------------------
- Python 3.7+
- Required packages:
    pip install pandas scikit-learn joblib scapy numpy

------------------
DATASET FORMAT
------------------
CSV columns required:
protocol, packet_length, source_port, destination_port, flags, label

Example:
protocol,packet_length,source_port,destination_port,flags,label
6,60,443,52344,24,0
17,74,53,49622,0,0
6,60,135,49157,2,1

Label: 0 = allowed, 1 = blocked

------------------
HOW TO RUN
------------------
1. Place 'network_traffic.csv' in the project directory.
2. Run the app:
   python firewall_gui.py
3. Use the GUI:
   - Start Monitoring
   - Stop Monitoring
   - Allow Selected Packet
   - Clear Logs

------------------
HOW IT WORKS
------------------
- Trains 3 models, selects best one based on accuracy.
- Uses scapy to sniff packets.
- Features extracted and classified as allowed/blocked.
- Blocked packets shown in GUI table.
- Manual allow updates packet status.

------------------
GUI PREVIEW
------------------
Columns: Protocol, Length, Src Port, Dst Port, Flags, IP, Status
[Allowed] = Green row
[Blocked] = Red row

------------------
NOTES
------------------
- Run with admin/root permissions:
  sudo python firewall_gui.py
- Intended for educational/research use only.

------------------
FUTURE IMPROVEMENTS
------------------
- Export logs to CSV
- Auto-learn from manual overrides
- Protocol-specific rules

------------------
LICENSE
------------------
MIT License
