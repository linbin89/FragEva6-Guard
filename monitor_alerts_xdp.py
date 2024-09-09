import time
import re
import select

def monitor_alerts(trace_pipe, timeout=5):
    pattern = r'(\d+\.\d+).*Alert count: (\d+)'
    first_time = None
    last_time = None
    first_count = None
    last_count = None
    start_time = time.time()

    print("Starting to monitor alerts...")

    with open(trace_pipe, 'r') as file:
        poller = select.poll()
        poller.register(file, select.POLLIN)

        while True:
            if poller.poll(100):  
                line = file.readline().strip()
                if line:
                    match = re.search(pattern, line)
                    if match:
                        timestamp = float(match.group(1))
                        alert_count = int(match.group(2))
                        
                        if first_time is None:
                            first_time = timestamp
                            first_count = alert_count
                            print(f"First alert detected: timestamp={first_time}, count={first_count}")
                        
                        last_time = timestamp
                        last_count = alert_count
                        
                        start_time = time.time()  # Reset the timer
            
            if time.time() - start_time > timeout:
                print(f"No new alerts for {timeout} seconds. Stopping.")
                break

    if first_time is None or last_time is None:
        print("No alerts detected.")
        return 0, 0, 0, 0

    print(f"Last alert detected: timestamp={last_time}, count={last_count}")
    
    total_alerts = last_count - first_count
    total_time = last_time - first_time
    avg_delay = total_time / total_alerts if total_alerts > 0 else 0
    detection_rate = (total_alerts / 4999) * 100

    print("\nConfirming timestamps:")
    print(f"First alert timestamp: {first_time}")
    print(f"Last alert timestamp: {last_time}")
    print(f"\nFirst alert count: {first_count}")
    print(f"Last alert count: {last_count}")
    print(f"Total alerts: {total_alerts+1}")
    print(f"Total time: {total_time:.6f} seconds")
    print(f"Detection rate: {detection_rate:.2f}%")
    print(f"Average processing delay: {avg_delay * 1000:.6f} ms")

    return total_alerts, total_time, avg_delay, detection_rate

trace_pipe_path = '/sys/kernel/debug/tracing/trace_pipe'
total_alerts, total_time, avg_delay, detection_rate = monitor_alerts(trace_pipe_path)
