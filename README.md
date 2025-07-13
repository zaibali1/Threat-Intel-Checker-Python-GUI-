🛡️ Threat Intel Feed Checker
A Python GUI application that analyzes IP addresses and URLs using VirusTotal and AbuseIPDB threat intelligence APIs. It flags malicious inputs, displays the results in a real-time dashboard, and generates a local CSV report. The app includes an interactive chart to monitor API request patterns.

- 🦠 [VirusTotal API](https://www.virustotal.com/)
- 🚨 [AbuseIPDB API](https://www.abuseipdb.com/)


📌 Features
🔍 Analyze IP addresses and URLs manually or via file upload.
- ✅ Check IPs and URLs via VirusTotal
- ✅ Check IPs via AbuseIPDB
- 📂 File upload (.txt/.csv)
- 🖼️ Tkinter-based GUI — no CLI needed
- 💾 Save results to CSV
- 🔔 Alert if any indicator is flagged as malicious


💻 Installation
🔧 Requirements
Python 3.8+

⚙️ Install Required Package:
pip install requests pandas matplotlib
pip install requests
pip install requests pandas

Note: tkinter comes pre-installed with standard Python on Windows/Mac/Linux.

## 🧠 Libraries Used

| Library       | Purpose                                                                 |
|---------------|-------------------------------------------------------------------------|
| **requests**  | To send HTTP requests to APIs (VirusTotal & AbuseIPDB)                  |
| **pandas**    | To handle and structure results in table format and export to CSV       |
| **tkinter**   | To build the graphical user interface (buttons, text areas, tables)     |
| **ttk**       | `tkinter.ttk` provides improved widgets like `Treeview` for tables      |
| **messagebox**| For showing alerts like "Analysis complete" or error messages           |
| **filedialog**| For file upload UI functionality (CSV or TXT)  


🧠 Integrates:
VirusTotal API
AbuseIPDB API

🔐 API Keys Setup
🧪 VirusTotal
Sign up: https://www.virustotal.com/gui/join-us
Get your API key from your profile
Replace in threat_checker.py:
VT_API_KEY = 'your_virustotal_api_key'


🚨 AbuseIPDB
Sign up: https://www.abuseipdb.com/register
Get your API key from: https://www.abuseipdb.com/account/api
Replace in threat_checker.py:
ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key'


⚠️ Flags malicious IPs/URLs based on:
VirusTotal: if VT_Malicious > 0
AbuseIPDB: if Abuse_Confidence ≥ 50



📂 Saves results to a CSV at C:\Users\Zaib Ali\Desktop\project\threat_report.csv
📊 Displays an API usage graph (mocked for UI enhancement)
⚠️ Shows alert popups if malicious indicators are detected
🖥️ Built with Tkinter and Matplotlib



🚀 Usage
✅ Option 1: Manual Entry
Type one IP or URL per line

Click Analyze Input

✅ Option 2: Upload File
Supported formats: .txt, .csv

First column of CSV is used


💾 Output Format
The tool will save a CSV file named threat_report.csv with columns like:

Input	VT_Malicious	VT_Suspicious	Abuse_Confidence	Country
8.8.8.8	0	0	15	US
evil.com	4	2	Not an IP

Also generates a full report (threat_report.csv) and summary text inside the GUI.


📜 License
This project is for educational and research purposes. API usage must follow the terms of service of each provider.


📬 Contact
Maintained by Zaib Un Nissa Qureshi
https://github.com/zaibali1
For support or suggestions, open an issue or reach out via GitHub.





