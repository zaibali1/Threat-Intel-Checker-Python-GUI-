import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import pandas as pd
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import random
import os

# === API Keys ===
VT_API_KEY = 'virustotal_api_key'
ABUSEIPDB_API_KEY = 'abuseipdb_api_key'

# === VirusTotal Checker ===
def check_virustotal(ip_or_url):
    headers = {"x-apikey": VT_API_KEY}
    try:
        if ip_or_url.replace('.', '').isdigit():
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_or_url}"
        else:
            url_id_resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": ip_or_url})
            if url_id_resp.status_code != 200:
                return {"VT Error": url_id_resp.text}
            url_id = url_id_resp.json()["data"]["id"]
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return {"VT Error": response.text}

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "VT_Harmless": stats.get("harmless", 0),
            "VT_Malicious": stats.get("malicious", 0),
            "VT_Suspicious": stats.get("suspicious", 0),
            "VT_Undetected": stats.get("undetected", 0)
        }
    except Exception as e:
        return {"VT Error": str(e)}

# === AbuseIPDB Checker ===
def check_abuseipdb(ip):
    if not ip.replace('.', '').isdigit():
        return {"AbuseIPDB Error": "Not an IP"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        if response.status_code != 200:
            return {"AbuseIPDB Error": response.text}
        data = response.json()["data"]
        return {
            "Abuse_Confidence": data["abuseConfidenceScore"],
            "Total_Reports": data["totalReports"],
            "Country": data.get("countryCode", "N/A")
        }
    except Exception as e:
        return {"AbuseIPDB Error": str(e)}

# === Analyze Inputs ===
def analyze(inputs):
    results = []
    for item in inputs:
        vt_result = check_virustotal(item)
        abuse_result = check_abuseipdb(item)
        result = {"Input": item}
        result.update(vt_result)
        result.update(abuse_result)
        results.append(result)
    return pd.DataFrame(results)

# === Run Analysis and Update UI ===
def run_analysis(inputs):
    df = analyze(inputs)
    for row in tree.get_children():
        tree.delete(row)
    for _, row in df.iterrows():
        tree.insert("", tk.END, values=list(row.values))

    # Save report to specific path
    output_path = r"C:\\Users\\Zaib Ali\\Desktop\\project\\threat_report.csv"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)

    messagebox.showinfo("Done", f"Analysis complete. Results saved to:\n{output_path}")
    report_text.delete("1.0", tk.END)
    report_text.insert(tk.END, df.to_string(index=False))
    show_consumption_graph()

# === File Upload Handler ===
def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text or CSV files", "*.txt *.csv")])
    if not file_path:
        return
    try:
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
            inputs = df.iloc[:, 0].dropna().astype(str).tolist()
        else:
            with open(file_path, 'r') as f:
                inputs = [line.strip() for line in f.readlines() if line.strip()]
        run_analysis(inputs)
    except Exception as e:
        messagebox.showerror("File Error", str(e))

# === Manual Input Handler ===
def run_manual_input():
    input_text = entry_input.get("1.0", tk.END).strip().splitlines()
    if input_text:
        run_analysis(input_text)

# === Generate and Show Graph ===
def show_consumption_graph():
    # Dummy data simulating API usage stats
    days = [f"Day {i}" for i in range(1, 31)]
    consumption = [random.randint(50, 150) for _ in range(30)]

    fig = plt.Figure(figsize=(10, 3), dpi=100)
    ax = fig.add_subplot(111)
    ax.plot(days, consumption, marker='o', color='#2563eb')
    ax.set_title("API Consumption Last 30 Days", fontsize=11)
    ax.set_xlabel("Day")
    ax.set_ylabel("Requests")
    ax.tick_params(axis='x', labelrotation=45)
    fig.tight_layout()

    for widget in chart_frame.winfo_children():
        widget.destroy()

    chart_canvas = FigureCanvasTkAgg(fig, master=chart_frame)
    chart_canvas.draw()
    chart_canvas.get_tk_widget().pack(fill='both', expand=True)

# === GUI Setup ===
app = tk.Tk()
app.title("Threat Intel Feed Checker")
app.geometry("1200x900")
app.configure(bg="#0f1117")

# === Custom Styles ===
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#1c1e26", foreground="white", rowheight=28, fieldbackground="#1c1e26", font=("Segoe UI", 10))
style.map('Treeview', background=[('selected', '#2563eb')])
style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#2d313a", foreground="white")

frame = tk.Frame(app, bg="#0f1117")
frame.pack(pady=20)

label = tk.Label(frame, text="Enter IPs/URLs (one per line):", bg="#0f1117", fg="white", font=("Segoe UI", 11, "bold"))
label.pack(anchor='w', padx=10, pady=(0,5))

entry_input = tk.Text(frame, height=5, width=110, bg="#1c1e26", fg="white", insertbackground="white", font=("Segoe UI", 10))
entry_input.pack(padx=10)

btn_frame = tk.Frame(frame, bg="#0f1117")
btn_frame.pack(pady=10)

btn_analyze = tk.Button(btn_frame, text="Analyze Input", command=run_manual_input, bg="#2563eb", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5)
btn_analyze.grid(row=0, column=0, padx=10)

btn_upload = tk.Button(btn_frame, text="Upload File", command=browse_file, bg="#2563eb", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5)
btn_upload.grid(row=0, column=1, padx=10)

columns = ["Input", "VT_Harmless", "VT_Malicious", "VT_Suspicious", "VT_Undetected", "Abuse_Confidence", "Total_Reports", "Country"]
tree = ttk.Treeview(app, columns=columns, show='headings', style="Treeview")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=140, anchor='center')

tree.pack(expand=True, fill='both', padx=20, pady=10)

# === Report Display Box ===
report_label = tk.Label(app, text="Text Report Summary:", bg="#0f1117", fg="white", font=("Segoe UI", 11, "bold"))
report_label.pack(anchor='w', padx=20)

report_text = tk.Text(app, height=10, width=140, bg="#1c1e26", fg="white", font=("Segoe UI", 10), wrap="none")
report_text.pack(expand=False, fill='both', padx=20, pady=(0, 20))

# === Chart Frame ===
chart_label = tk.Label(app, text="Consumption Last 30 Days:", bg="#0f1117", fg="white", font=("Segoe UI", 11, "bold"))
chart_label.pack(anchor='w', padx=20)

chart_frame = tk.Frame(app, bg="#0f1117", height=200)
chart_frame.pack(fill='both', expand=False, padx=20, pady=(0, 20))

# === Start the App ===
app.mainloop()
