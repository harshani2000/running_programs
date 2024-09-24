import psutil
import tkinter as tk
from tkinter import ttk
from datetime import datetime

#track processes and their stop times
process_info = {}

#filter only OS-related processes
def is_os_program(proc):
    try:
        # Get the command or executable path
        cmd = proc.info['exe'] or proc.info['name']  
        if (".py" in cmd or "python" in cmd or       # Python
                ".sh" in cmd or "bash" in cmd or         # Bash/Shell
                "java" in cmd or "javac" in cmd or       # Java
                "node" in cmd or ".js" in cmd or         # JavaScript 
                "clang" in cmd or ".c" in cmd or ".cpp" in cmd or # C/C++
                "dotnet" in cmd or "mono" in cmd or      # C#/.NET
                ".cs" in cmd): 
            return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return False

#format the start time from a timestamp
def format_start_time(start_time):
    return datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')

#update process status and track stop times
def update_process_status():
    #track of running PIDs
    current_pids = set()

    #Iterate all running processes and filter them
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time', 'status']):
        try:
            if is_os_program(proc):
                pid = proc.info['pid']
                name = proc.info['name']
                file_path = proc.info['exe']
                start_time = format_start_time(proc.info['create_time'])
                status = proc.info['status']

                #Mark this process as currently running
                current_pids.add(pid)

                #Check if the process is already tracked
                if pid not in process_info:
                    #Add new process to the process_info dictionary
                    process_info[pid] = {
                        'pid': pid,
                        'name': name,
                        'file_path': file_path,
                        'start_time': start_time,
                        'stop_time': 'running', 
                        'status': status
                    }
                else:
                    # Update the process's current status
                    process_info[pid]['status'] = status
                    process_info[pid]['stop_time'] = 'Running'  # Reset stop time if still running
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    #Check for processes that have stopped
    for pid in list(process_info):
        if pid not in current_pids and process_info[pid]['status'] != 'Stopped':
            #Update the stop time and set status to 'Stopped'
            process_info[pid]['stop_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            process_info[pid]['status'] = 'Stopped'

#update the process list in the TreeView
def update_process_list():
    #Clear the existing process list in the TreeView
    for proc in tree.get_children():
        tree.delete(proc)

    #Populate the treeview with process information
    for proc in process_info.values():
        tree.insert("", "end", values=(proc['pid'], proc['name'], proc['file_path'], proc['start_time'], proc['stop_time'], proc['status']))

    #Update every 2 seconds
    tree.after(2000, refresh_process_list)

#refresh process list and status
def refresh_process_list():
    update_process_status()
    update_process_list()

#Create the main window
root = tk.Tk()
root.title("OS Program Viewer")
root.geometry("1000x500")

#Create a frame for the TreeView and scrollbar
frame = ttk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

#Create a treeview widget
columns = ("PID", "Name", "File Path", "Start Time", "Stop Time", "Status")
tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)

#Define column headers
tree.heading("PID", text="Process ID")
tree.heading("Name", text="Process Name")
tree.heading("File Path", text="File Path")
tree.heading("Start Time", text="Start Time")
tree.heading("Stop Time", text="Stop Time")
tree.heading("Status", text="Status")

#Define column width and alignment
tree.column("PID", width=80, anchor=tk.CENTER)
tree.column("Name", width=200, anchor=tk.W)
tree.column("File Path", width=400, anchor=tk.W)
tree.column("Start Time", width=150, anchor=tk.W)
tree.column("Stop Time", width=150, anchor=tk.W)
tree.column("Status", width=100, anchor=tk.W)

#Pack the TreeView into the frame
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

#Add a vertical scrollbar
scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
tree.configure(yscrollcommand=scrollbar.set)

#Start the process monitoring and updating
refresh_process_list()

#Run the main event loop
root.mainloop()
