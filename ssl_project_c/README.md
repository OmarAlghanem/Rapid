# SSL Robot Control Server

This project is a C-based SSL server that allows you to control a robot remotely. It uses OpenSSL for secure communication and provides a set of commands to control the robot's movements.

## Project Structure

The project has the following structure:

-   `.vscode`: Contains VS Code configuration files.
-   `certs`: Contains the SSL certificates required for secure communication.
-   `include`: Contains header files.
-   `src`: Contains the source code files.

## Building the Project

To build the project, you will need a C compiler and the OpenSSL library. You can use the following command to build the project:

```
gcc src/*.c -o server -lssl -lcrypto -lws2_32
```

## Running the Project

To run the project, you will need to generate SSL certificates. You can use the following command to generate the certificates:

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

Once you have generated the certificates, you can run the server using the following command:

```
./server
```

## Robot Control Commands

The following commands can be sent to the server to control the robot:

-   `spin ninety`: Spin the robot 90 degrees.
-   `spin oneeighty`: Spin the robot 180 degrees.
-   `rest`: Put the robot in the rest position.

## Hash Verification

The server expects the client to send a hash of the current state. The hash is used to verify the integrity of the client. The server supports two types of hashes:

-   `INIT`: The initial hash.
-   `PERIODIC`: The periodic hash.

The expected hashes are hardcoded in the `src/server_robo.c` file. You will need to update these hashes to match the actual hashes of the client.
