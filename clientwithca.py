import socket
import ssl

def create_ssl_client():
    host = '192.168.68.63'  # Your server IP
    port = 8443  # Port you're connecting to
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Load the server's CA certificate for verifying the client's certificate
    context.load_verify_locations("ca.crt")

    # **Disable** certificate verification on the client side
    context.check_hostname = False  # Disable hostname checking
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification

    # Load the client's certificate and private key for authentication
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")

    # Create the raw socket
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   
    # Wrap the socket with SSL
    secure_socket = context.wrap_socket(raw_socket, server_hostname=host)

    try:
        print("Connecting to server...")
        secure_socket.connect((host, port))
        print("Connection established!")

        # Verify certificate has been sent (this is part of the handshake process)
        cert = secure_socket.getpeercert()
        if cert:
            print("Certificate has been sent and received by the server!")
        else:
            print("No certificate received!")

        # Send a simple request if needed
        secure_socket.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
       
        # Receive response from server
        response = secure_socket.recv(4096)
        print("Received:", response.decode())
   
    except Exception as e:
        print(f"Error during SSL connection: {e}")
   
    finally:
        secure_socket.close()

# Run the client
create_ssl_client()