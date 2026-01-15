import tkinter as tk
from tkinter import ttk
import packet_sniffer_fixed as sniffer
import threading

from time import sleep


# GLOBAL VARIABLES
# List of packet objects currently being displayed on screen
_displayed_packets = []
# The direction of the filter dir button
_filter_dir = "to"
# Tracks if the packet sniffer thread is currently sniffing
_listening = False


def main():

    buildUI()

    window.after(10, Update)
    window.mainloop()


# Check for messages, update UI as needed
def Update():
    global _listening
    global _displayed_packets

    # Check if sniffer is finished or has sent a packet for display
    mes = sniffer.GetMessage("ui")
    if mes is not None:
        if mes == -1:
            print("Finished message received")
            _listening = False
        else:
            displayPacket(mes)

    window.after(10, Update)


# Builds the UI
def buildUI():
    # The main window of the app- contains all UI elements
    global window
    window = tk.Tk()
    window.title("Packet Sniffer")
    window.geometry("850x850")

    # A frame widget containing everything within the window
    frame = tk.Frame(window)
    # Show the widget on screen (pack place or grid- geometry managers)
    frame.pack()


    # TOOLBAR
    # The row for basic user command tools
    # Run(button)   Stop(button)   ip1 (text box)   dir(->, <-, <->)(button)   ip2 (text box)   Filter(button)   Clear Packets(button)
    toolbar_row = tk.Frame(frame)
    toolbar_row.grid(row=0, column=0)

    # Runs the sniffer
    run_button = tk.Button(toolbar_row, text="Run", command=Listen)
    run_button.grid(row=0, column=0)

    # Send a message to packet sniffer thread to stop sniffing
    stop_button = tk.Button(toolbar_row, text="Stop", command=StopListening)
    stop_button.grid(row=0, column=1)

    # A text box of one of two ips to filter received packets by
    global filter_text_box_ip1
    filter_text_box_ip1 = tk.Text(toolbar_row, height=1, width=20)
    filter_text_box_ip1.grid(row=0, column=2)

    # Button that specifies direction of packets sent in filter (can be changed by click)
    global filter_dir_button
    filter_dir_button = tk.Button(toolbar_row, text="->", command=changeFilterDir)
    filter_dir_button.grid(row=0, column=3)

    # A text box of one of two ips to filter received packets by
    global filter_text_box_ip2
    filter_text_box_ip2 = tk.Text(toolbar_row, height=1, width=20)
    filter_text_box_ip2.grid(row=0, column=4)

    # Button to search packets using criteria from filter options
    filter_button = tk.Button(toolbar_row, text="Filter", command=filterPacketDisplay)
    filter_button.grid(row=0, column=5)

    # Clears all packets from ui (but not from data)
    clear_button = tk.Button(toolbar_row, text="Clear List", command=clearPacketDisplay)
    clear_button.grid(row=0, column=6)

    # Generates a summary of all packets addressed to/from host (Moved to right click packet menu)
    #stats_button = tk.Button(toolbar_row, text="Host Stats", command=lambda: displayStats(sniffer._settings["current interface"][1]))
    #stats_button.grid(row=0, column=7)

    # Creates a popup window for run settings
    settings_button = tk.Button(toolbar_row, text = "Settings", command=openSettings)
    settings_button.grid(row=0, column=9)

    # The master frame, containing all content related to sniffed packets
    packets_master = tk.LabelFrame(frame, text="Packets", width=90)
    packets_master.grid(row=1, column=0)


    # PACKET LIST TREEVIEW WITH SCROLL
    # Treeview Scrollbar for packet list
    tree_scroll = tk.Scrollbar(packets_master)

    # Create Treeview
    global packet_list
    # Selectmode: "extended": can ctrl click multiple items, "browse": can only select one item
    packet_list = ttk.Treeview(packets_master, yscrollcommand=tree_scroll.set, selectmode="browse", show="headings")
    packet_list.grid(row=0, column=0)

    # Configure Scrollbar
    tree_scroll.config(command=packet_list.yview)

    # Define Columns
    packet_list['columns'] = ("No.", "Time", "Src", "Dest", "Proto", "Len", "Info")

    # Format Columns
    packet_list.column("No.", anchor=tk.CENTER, width=50)
    packet_list.column("Time", anchor=tk.CENTER, width=80)
    packet_list.column("Src", anchor=tk.CENTER, width=120)
    packet_list.column("Dest", anchor=tk.CENTER, width=120)
    packet_list.column("Proto", anchor=tk.CENTER, width=120)
    packet_list.column("Len", anchor=tk.CENTER, width=80)
    packet_list.column("Info", anchor=tk.CENTER, width=150)

    # Create Headings
    packet_list.heading("No.", text="No.", anchor=tk.CENTER)
    packet_list.heading("Time", text="Time", anchor=tk.CENTER)
    packet_list.heading("Src", text="Src", anchor=tk.CENTER)
    packet_list.heading("Dest", text="Dest", anchor=tk.CENTER)
    packet_list.heading("Proto", text="Proto", anchor=tk.CENTER)
    packet_list.heading("Len", text="Len", anchor=tk.CENTER)
    packet_list.heading("Info", text="Info",anchor=tk.CENTER)

    # Bind popup packet menu to right click on packet list
    packet_list.bind("<Button-3>", PacketMenuPopup)

    # Grid the scrollbar to the packet list
    tree_scroll.grid(row=0, column=1, sticky='nsw')


    # RIGHT CLICK MENU FOR PACKETS
    global packet_menu
    packet_menu = tk.Menu(packets_master, tearoff=0)
    packet_menu.add_command(label="Packet Details", command=ShowpacketDetails)
    packet_menu.add_command(label="Filter Src/Dst", command=setFilterInput)
    packet_menu.add_command(label="Src IP Stats", command= lambda: displayStats(GrabPacketIPs()[0]))
    packet_menu.add_command(label="Dst IP Stats", command= lambda: displayStats(GrabPacketIPs()[1]))


    # PACKET DETAILS BOX
    details_master = tk.LabelFrame(frame, text="Packet Details", width=50)
    details_master.grid(row=2, column=0)

    # Scrollbar for details
    details_scroll = tk.Scrollbar(details_master)

    global packet_details
    #packet_details = tk.Text(details_master, wrap='word', height=10, width=90, yscrollcommand=details_scroll.set)
    packet_details = tk.Text(details_master, wrap='word', height=15, width=90, yscrollcommand=details_scroll.set)
    packet_details.grid(row=0, column=0)
    packet_details.config(state="disabled")

    # Configure scrollbar
    details_scroll.config(command=packet_details.yview)
    details_scroll.grid(row=0, column=1, sticky='nsw')


    # RUNTIME STATS BOX
    stats_master = tk.LabelFrame(frame, text="Runtime Stats")
    stats_master.grid(row=3, column=0)

    # Scrollbar for stats
    stats_scroll = tk.Scrollbar(stats_master)

    global runtime_stats
    #runtime_stats = tk.Text(stats_master, wrap='word', height=10, width=90, yscrollcommand=stats_scroll.set)
    runtime_stats = tk.Text(stats_master, wrap='word', height=15, width=90, yscrollcommand=stats_scroll.set)
    runtime_stats.grid(row=0, column=0)
    runtime_stats.config(state="disabled")

    # Configure scrollbar
    stats_scroll.config(command=runtime_stats.yview)
    stats_scroll.grid(row=0, column=1, sticky='nsw')



# START/STOP
# Starts up the listening function in sniffer in a separate thread
def Listen():
    global _listening
    if _listening == False:
        listenThread = threading.Thread(None, sniffer.main)
        _listening = True
        listenThread.start()
        #listenThread.run()
        

# Sends a message to packet sniffer thread to stop sniffing
def StopListening():
    global _listening
    if _listening == True:
        sniffer.SendMessageLocal("sniffer", -1)


# PACKET DISPLAY FUNCTIONS

# Displays a packet dictionary at a specified row within packet_list frame
def displayPacket(packetEntry):
    global _displayed_packets
    global packet_list

    # Network Layer protocol- only IPv4 packets are supported and will be processed

    # Transport Layer protocol (though ICMP is tecnically network) - if not ICMP, TCP, or UDP, it is unsupported by sniffer and payload will contain "not unpacked"
    proto_num = packetEntry["proto"]
    proto = "unknown"
    if proto_num == 1:
        proto = "ICMP"
    elif proto_num == 6:
        proto = "TCP"
    elif proto_num == 17:
        proto = "UDP"

    # Application Layer Protocol
    # Ports: 23=TELNET, 20=FTP(data) 21=FTP(control) (file transfer proto), 69=TFTP(trivial file transfer proto- simplified ftp), 2049=NFS (network file system), 25=SMTP(simple mail transfer proto), 515=LPD(line printer daemon- for printer sharing), 161=SNMP(TCP) 162=SNMP(UDP) (simple network management proto- gathers data about network),
    # 53=DNS(domain name system- site name to ip), 67,68=DHCP(dynamic host config proto- gives ip addresses to hosts), 80=HTTP/HTTPS(duh), 443=HTTPS, 110=POP(post office proto), 6667=IRC(internet relay chat- text-based- Discord?), 
    
    # Details section of packet display, grab app layer proto, dest port number, or some other detail, if port not contained in TL proto header
    # The details will be unknown if the packet uses an unsupported TL proto
    #TODO: Add support for other TL protos
    if proto == "TCP" or proto == "UDP":
        # Check to see if the port is a number (scapy gives app layer names if it knows them)
        try:
            # If app proto is a number, list the proto name based on common ports
            int(packetEntry["payload"]["dest_port"])
            if packetEntry["payload"]["dest_port"] == 80:
                app_proto = "HTTP/HTTPS"
            elif packetEntry["payload"]["dest_port"] == 443:
                app_proto = "HTTPS"
            elif packetEntry["payload"]["dest_port"] == 53:
                app_proto = "DNS"
            elif packetEntry["payload"]["dest_port"] == 6667:
                app_proto = "IRC"
            else:
                app_proto = "AL proto using port " + str(packetEntry["payload"]["dest_port"])
        except:
            # If app proto is a name (given by scapy), port # is not known - just list the name
            print("App proto given by scapy")
            app_proto = packetEntry["payload"]["dest_port"]

    # ICMP is a network layer proto contained in an ip packet (also network layer). It contains no transport or app layer proto
    elif proto == "ICMP":
        app_proto = "ICMP packet over IP"
    # Unsupported Transport Layer proto, can't analyze payload ("not unpacked")
    else:
        app_proto = "unknown"

    packet_list.insert(parent='', index='end', text='', values=(packetEntry["no"], packetEntry["time"], packetEntry["src"], packetEntry["target"], proto, packetEntry["total_length"], app_proto))
    _displayed_packets.append(packetEntry)

# Recreates packet list ui widget using a list of packets
def remakeDisplay(packetList):
    print("remaking display")
    global _displayed_packets
    # Empty all packets from ui
    clearPacketDisplay()

    # Create widget for each packet in packetList
    for packet in packetList:
        displayPacket(packet)


# Removes all packets from ui (but not from data)
def clearPacketDisplay():
    global _displayed_packets

    _displayed_packets.clear()

    global packet_list
    for item in packet_list.get_children():
        packet_list.delete(item)

    _displayed_packets = []




# RIGHT CLICK PACKET OPTIONS
# Displays the right click popup menu for the packet list
def PacketMenuPopup(event):
    global packet_menu
    global packet_list

    # Check if item selected before displaying pop up menu
    selected_item = packet_list.focus()
    if selected_item != '':
        try:
            packet_menu.tk_popup(event.x_root, event.y_root)
        finally:
            packet_menu.grab_release()


# Displays selected packet details in the "Packet Details" box
def ShowpacketDetails():
    global packet_list
    global _displayed_packets
    global packet_details

    # Check if item selected before displaying pop up menu
    selected_item = packet_list.focus()
    if selected_item != '':
        index = packet_list.index(selected_item)

        packet_dict = _displayed_packets[index]

        packet_details.config(state="normal")
        # Clear text box
        packet_details.delete('1.0', tk.END)
        # Display new packet details
        packet_details.insert(tk.END, "NETWORK PACKET: \n")
        for key in packet_dict:
            if key != "data" and key != "payload":
                packet_details.insert(tk.END, "{k}: {v}\n".format(k=key, v=packet_dict[key]))

        packet_details.insert(tk.END, "\nTRANSPORT PACKET: \n")
        for key in packet_dict["payload"]:
            packet_details.insert(tk.END, "{k}: {v}\n".format(k=key, v=packet_dict["payload"][key]))
        packet_details.config(state="disabled")


# When not sniffing, filters packets displayed based on filter provided by user
def filterPacketDisplay():
    global _listening
    if _listening == False:
        inp = getFilterInput()
        #print("LIST RECEIVED")
        #print(sniffer.getFilteredList(inp[0], inp[1], inp[2]))
        remakeDisplay(sniffer.getFilteredList(inp[0], inp[1], inp[2]))


# Grabs the two ips (sender/receiver) from the currently selected packet
def GrabPacketIPs():
    global filter_text_box_ip1
    global filter_text_box_ip2
    global filter_dir_button
    global _filter_dir

    selected_item = packet_list.focus()
    details = packet_list.item(selected_item)
    
    ips = (details["values"][2], details["values"][3])
    #print(ips)
    return ips


# Inserts IPs from a selected packet into the filter box For quicker filtering
def setFilterInput():
    global filter_text_box_ip1
    global filter_text_box_ip2
    global filter_dir_button
    global _filter_dir
    ips = GrabPacketIPs()

    # Clear the filter text boxes
    filter_text_box_ip1.delete('1.0', tk.END)
    filter_text_box_ip2.delete('1.0', tk.END)
    # Insert the two ips into the boxes
    filter_text_box_ip1.insert(tk.END, ips[0])
    filter_text_box_ip2.insert(tk.END, ips[1])
    # Change the filter direction and button to "to" (->)
    _filter_dir = "to"
    filter_dir_button.config(text="->")


# Returns an array representing the desired filter: [ip1, dir, ip2]
def getFilterInput():
    global _listening
    global _filter_dir
    # If not currently sniffing, pull from the filter input boxes
    if _listening == False:
        inp = []
        inp.append(filter_text_box_ip1.get(1.0, "end-1c"))
        inp.append(_filter_dir)
        inp.append(filter_text_box_ip2.get(1.0, "end-1c"))
        return inp
    

# Iterates between three directions for filter ("to", "from", "both") and changes button accordingly
def changeFilterDir():
    global _filter_dir
    if _filter_dir == "to":
        _filter_dir = "from"
        filter_dir_button.config(text="<-")
    elif _filter_dir == "from":
        _filter_dir = "both"
        filter_dir_button.config(text="<->")
    else:
        _filter_dir = "to"
        filter_dir_button.config(text="->")


# Generates a summary of all packets gathered, displays to the stats box
def displayStats(ip):
    global runtime_stats
    if _listening == False:
        stats = sniffer.generateStats(ip)

        # Allow text box to be edited
        runtime_stats.config(state="normal")
        # Clear text box
        runtime_stats.delete('1.0', tk.END)

        # Other ips -> host
        runtime_stats.insert(tk.END, "Packets sent to host {host}: \n".format(host=ip))
        for addr in stats[1]:
            total = stats[1][addr]["total"]
            ipv4 = stats[1][addr]["ipv4"]
            other = total - ipv4
            runtime_stats.insert(tk.END, "\n{ip} sent {num} packets \n".format(ip=addr, num=total))
            runtime_stats.insert(tk.END, "Network Layer \n")
            runtime_stats.insert(tk.END, "IPv4 packets: {num} ({percent}%)\n".format(num=ipv4, percent=ipv4 / total * 100))
            runtime_stats.insert(tk.END, "Other: {num} ({percent}%)\n".format(num=other, percent=other / total * 100))

            runtime_stats.insert(tk.END, "Transport Layer \n")
            # Number of packets utilizing tcp, udp and icmp
            tcp = stats[1][addr]["tcp"]
            udp = stats[1][addr]["udp"]
            icmp = stats[1][addr]["icmp"]
            other = total - tcp - udp - icmp
            runtime_stats.insert(tk.END, "TCP: {num} ({percent}%)\n".format(num=tcp, percent=tcp / total * 100))
            runtime_stats.insert(tk.END, "UDP: {num} ({percent}%)\n".format(num=udp, percent=udp / total * 100))
            runtime_stats.insert(tk.END, "ICMP: {num} ({percent}%)\n".format(num=icmp, percent=icmp / total * 100))
            runtime_stats.insert(tk.END, "Other: {num} ({percent}%)\n".format(num=other, percent=other / total * 100))

        runtime_stats.insert(tk.END, "-------------------------------------------\n")

        # Host -> other ips
        runtime_stats.insert(tk.END, "Packets sent from host {host}: \n".format(host=ip))
        for addr in stats[0]:
            runtime_stats.insert(tk.END, "\nSent {num} packets to {ip} \n".format(ip=addr, num=stats[0][addr]["total"]))
            total = stats[0][addr]["total"]
            ipv4 = stats[0][addr]["ipv4"]
            other = total - ipv4
            runtime_stats.insert(tk.END, "Network Layer \n")
            runtime_stats.insert(tk.END, "IPv4 packets: {num} ({percent}%)\n".format(num=ipv4, percent=ipv4 / total * 100))
            runtime_stats.insert(tk.END, "Other: {num} ({percent}%)\n".format(num=other, percent=other / total * 100))

            runtime_stats.insert(tk.END, "Transport Layer \n")
            # Number of packets utilizing tcp, udp and icmp
            tcp = stats[0][addr]["tcp"]
            udp = stats[0][addr]["udp"]
            icmp = stats[0][addr]["icmp"]
            other = total - tcp - udp - icmp
            runtime_stats.insert(tk.END, "TCP: {num} ({percent}%)\n".format(num=tcp, percent=tcp / total * 100))
            runtime_stats.insert(tk.END, "UDP: {num} ({percent}%)\n".format(num=udp, percent=udp / total * 100))
            runtime_stats.insert(tk.END, "ICMP: {num} ({percent}%)\n".format(num=icmp, percent=icmp / total * 100))
            runtime_stats.insert(tk.END, "Other: {num} ({percent}%)\n".format(num=other, percent=other / total * 100))


        # Disable text box editing
        runtime_stats.config(state="disabled")


# SETTINGS FUNCTIONS

# Creates a new window for settings (freezes main window until it is closed)
def openSettings():
    global _listening
    global window

    if _listening == False:
        # Disable the main window while settings are open
        window.attributes("-disabled", True)

        # Open a new window for settings
        global settings_window
        global run_time_text_box
        global packet_limit_text_box

        settings_window = tk.Toplevel(window)
        settings_window.title("Settings")
        settings_window.geometry("800x800")

        settings_frame = tk.Frame(settings_window)
        settings_frame.pack()

        # Interface settings
        interface_settings_frame = tk.LabelFrame(settings_frame, text="Interface Settings")
        interface_settings_frame.grid(row=0, column=0, sticky=tk.NSEW)
        
        interface_label = tk.Label(interface_settings_frame, text="Interface: ")
        interface_label.grid(row=0, column=0, sticky=tk.NSEW)

        global selected_interface_name
        selected_interface_name = tk.StringVar()
        selected_interface_name.set(sniffer._settings["current interface"][0])
        options = []
        for interface in sniffer._settings["interfaces"]:
            options.append(interface)
        interface_drop = tk.OptionMenu(interface_settings_frame, selected_interface_name, *options)
        interface_drop.grid(row=0, column=1, sticky=tk.NSEW)

        # The settings for setting limits on run time
        run_settings_frame = tk.LabelFrame(settings_frame, text="Run Settings")
        run_settings_frame.grid(row=1, column=0, sticky=tk.NSEW)

        run_time_label = tk.Label(run_settings_frame, text="Run for (seconds): ")
        run_time_text_box = tk.Text(run_settings_frame, height=1, width=20)

        # Place the settings text fields on screen and fill them with current settings
        run_time_label.grid(row=0, column=0)
        run_time_text_box.grid(row=0, column=1)
        if sniffer._settings["time limit"] == None:
            run_time_text_box.insert(tk.END, "")
        else:
            run_time_text_box.insert(tk.END, sniffer._settings["time limit"])

        packet_limit_label = tk.Label(run_settings_frame, text= "Sample size (# packets): ")
        packet_limit_text_box = tk.Text(run_settings_frame, height=1, width=20)

        packet_limit_label.grid(row=1, column=0)
        packet_limit_text_box.grid(row=1, column=1)
        if sniffer._settings["packet limit"] == None:
            packet_limit_text_box.insert(tk.END, "")
        else:
            packet_limit_text_box.insert(tk.END, sniffer._settings["packet limit"])

        # The settings for handling data
        data_settings_frame = tk.LabelFrame(settings_frame, text="Data Settings")
        data_settings_frame.grid(row=2, column=0, sticky=tk.NSEW)

        # Reset button
        # Deletes all packets from memory and clears ui (for a new run)
        reset_button = tk.Button(data_settings_frame, text="Reset Data", command=confirmReset)
        reset_button.grid(row=0, column=1, padx=100)

        # The button for applying the settings
        run_settings_apply_button = tk.Button(settings_frame, text="Apply", command=applySettings)
        run_settings_apply_button.grid(row=3, column=0, sticky=tk.NSEW)

        # When X button clicked
        settings_window.protocol("WM_DELETE_WINDOW", settingsOnClose)


# Re-enables the main window and closes settings window
def settingsOnClose():
    global window
    # Re-enable the main window
    window.attributes("-disabled", False)
    # Destroy settings window
    settings_window.destroy()


# Gets inputs from settings text fields, validates, and applies them to sniffer
def applySettings():
    global run_time_text_box
    global packet_limit_text_box
    global settings_window

    # Set the sniffer interface to current selection
    selectInterface()

    time_limit = run_time_text_box.get(1.0, "end-1c")
    # Handle empty input
    if time_limit == "":
        time_limit = None
    else:
        try:
            time_limit = float(time_limit)
            # Don't accept negative time
            if time_limit < 0:
                createMessageBox(settings_window, "Time must not be negative")
                return
        # Don't accept non-number input
        except ValueError:
            createMessageBox(settings_window, "Time must be a number")
            return

    packet_limit = packet_limit_text_box.get(1.0, "end-1c")
    # Handle empty input
    if packet_limit == "":
        packet_limit = None
    else:
        try:
            packet_limit = int(packet_limit)
            # Don't accept negative packet number
            if packet_limit < 0:
                createMessageBox(settings_window, "Sample size must not be negative")
                return
        # Don't accept non-int input
        except ValueError:
            createMessageBox(settings_window, "Sample size must be a number")
            return

    new_settings = {}
    new_settings["time limit"] = time_limit
    new_settings["packet limit"] = packet_limit
    sniffer.updateSettings(new_settings)

    return


# Grabs the interface from the drop down menu and calls sniffer to change to this interface
def selectInterface():
    global selected_interface_name
    new_settings = {}
    name = selected_interface_name.get()
    ip = sniffer._settings["interfaces"][name]
    # The tuple containing interface name and ip address associated with it
    interface = (name, ip)
    print(interface)
    new_settings["current interface"] = (interface)
    sniffer.updateSettings(new_settings)


# Deletes all packets from memory and clears ui (for a new run)
def resetData():
    global _listening
    global packet_details
    global runtime_stats
    if _listening == False:
        # Call the sniffer to reset all packets
        sniffer.resetData()
        # Clear the UI
        clearPacketDisplay()
        packet_details.config(state="normal")
        packet_details.delete('1.0', tk.END)
        packet_details.config(state="disabled")
        runtime_stats.config(state="normal")
        runtime_stats.delete('1.0', tk.END)
        runtime_stats.config(state="disabled")


# MESSAGE POPUPS

# Creates a notification message window (to notify users of incorrect inputs or significant changes in program)
# Takes a windows to freeze (until notification is exited), and text to display to the window
from tkinter import messagebox
def createMessageBox(window, text):
    messagebox.showerror(parent=window, title="Error", message=text, default="ok")

# Creates an ask yes/no window confirming if the user wants to reset all data
def confirmReset():
    global settings_window
    answer = messagebox.askyesno(parent=settings_window, title="Confirm", message="Reset all capture data? This cannot be undone.")
    if answer:
        print("Resetting data")
        resetData()
    else:
        print("Reset canceled")



main()