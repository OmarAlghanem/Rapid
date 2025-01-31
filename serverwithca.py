import ssl
import socket

def create_ssl_server():
    host = '0.0.0.0'  # Listen on all available interfaces
    port = 8443        # SSL port

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="C:\\Users\\abdul\\ssl_try2\\cert.crt", keyfile="C:\\Users\\abdul\\ssl_try2\\key.pem")
    context.load_verify_locations("C:\\Users\\abdul\\ssl_try2\\ca.crt")  # Load the CA certificate for client verification
    context.verify_mode = ssl.CERT_REQUIRED  # Enforce client cert verification

    # Create the base server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")

    try:
        while True:
            print("Waiting for a connection...")
            conn, addr = server_socket.accept()  # Accept a new connection
            print(f"Connection established with {addr}")

            # Wrap the connection to secure it
            secure_conn = context.wrap_socket(conn, server_side=True)
            
            # Get client certificate
            client_cert = secure_conn.getpeercert()
            if client_cert:
                print("Client certificate received:")
                print(client_cert)
            else:
                print("No client certificate received.")

            try:
                # Handle the connection (example: send a message)
                secure_conn.sendall(b"Hello, secure world!")

                # Receive data from the client
                data = secure_conn.recv(1024)  # Adjust the buffer size if necessary
                if data:
                    print(f"Received from client: {data.decode('utf-8')}")  # Assuming the data is text

            except ssl.SSLError as e:
                print(f"SSL error: {e}")
            except Exception as e:
                print(f"Error: {e}")
            finally:
                secure_conn.close()  # Make sure to close the secure connection after handling

    except KeyboardInterrupt:
        print("Server stopped manually.")
    finally:
        server_socket.close()  # Ensure server socket is closed when exiting

if __name__ == "__main__":
    create_ssl_server()
