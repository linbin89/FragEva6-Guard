from bcc import BPF
import time

b = BPF(src_file="FragEva6-Guard.c")

alert_count = b.get_table("alert_count")

b.attach_xdp("ens33, b.load_func("xdp_ipv6_prog", BPF.XDP))

print("Monitoring alerts. Press Ctrl+C to stop.")

try:
    while True:
        total_count = sum(alert_count.values())
        print(f"Total alerts: {total_count}", end="\r", flush=True)
        time.sleep(1)
except KeyboardInterrupt:
    print("\nMonitoring stopped.")
finally:
    b.remove_xdp("ens33")
