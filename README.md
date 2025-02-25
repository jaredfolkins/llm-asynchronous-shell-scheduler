# LLMASS 

**LLM Asynchronous Shell Scheduler**

tldr; Enables an **LLM** to remotely & securely control a jumphost using asynchronous `GET` requests.

## Overview

**LLMASS** is a simple HTTP server written in Go that executes shell commands based on incoming HTTP `GET` requests. The server maintains a directory-based session system, issuing tickets per command, which allows quick chronological viewing of command output.

## Features

- **Secure Hash Check**: Requires >= 32-character `HASH` for request authentication.
- **Sessions**: Commands are organized into `sessions` where each command gets a ticket number with its output saved to file.
- **Dynamic Group Names**: Automatically generate a random session name if not specified.
- **Terminal**: Retrieve all outputs for a session.
- **Ticket**: Retrieve a specific ticket from a session.
- **Documentation**: Serves a dynamically rendered markdown `README.md`.

## Requirements

- [Go 1.21+](https://golang.org/dl/) (earlier versions may work, but this was tested with 1.18+).
- A `.env` file containing environment variables.
- (Optional) [Caddy](https://caddyserver.com) as a reverse proxy.

## Installation and Setup

#### Clone the Repository

```bash
git clone https://github.com/jaredfolkins/llm-asynchronous-shell-scheduler.git
cd llm-asynchronous-shell-scheduler
```

#### Create a file named `.env` in the project root:

```bash
touch .env
```

  And populate it with the required environment variables.

#### Install Dependencies

 ```bash
 go mod tidy
 ```

#### Build and Run

 ```bash
 go build -o llmass
 ./llmass
 ```
By default, the server will start listening on the port specified in your `.env`.

## Configuration


LLMASS relies on several environment variables that you need to place in a `.env` file.

**Important**: 

The `HASH` must be >= 32 characters long.

**Example**:
```dotenv
HASH=g5U8N2kL0f4R7zV3m1T6bJ9aQ8W0xC2e
FQDN=http://localhost:8083
PORT=8083
SESSIONS_DIR=sessions
```


## Parameter Map

| GET Parameter | Description                                        | /shell   | /history | /status  | /context   | /       |
|---------------|----------------------------------------------------|----------|----------|----------|------------|---------|
| `hash`        | >= 32-character password for authentication.       | required | required | required | required   | n/a     |
| `cmd`         | Url encoded cli command to execute                 | required | n/a      | n/a      | n/a        | n/a     |
| `ticket`      | Ticket number of the request                       | n/a      | n/a      | required | n/a        | n/a     |
| `session`     | Session in order that the llm can maintain context | no       | required | required | n/a        | n/a     |

## Shell

- **Description**: Execute a shell command.
- **Path**: [{FQDN}/shell]({FQDN}/shell)
- **Method**: `GET`
- **Query Parameters**:
    - `hash`: Must match the `HASH` from your `.env`.
    - `cmd`: is a url encoded shell command to execute, e.g., `ls -lah`.
    - `sessions` (optional): A directory/session name. If not provided, a random session name is generated using Docker's names generator.

**Example**: 
```bash
curl -G "{FQDN}/shell" --data-urlencode "cmd=ls -lah" --data-urlencode "hash=g5U8N2kL0f4R7zV3m1T6bJ9aQ8W0xC2e"
```

A **successful** response returns:
```
{
  "ticket":1,
  "session":"mystifying_gould"
}
```

The **output** of the command is:

- saved in a new named `<int>.ticket` 
- the file is inside `SESSIONS_DIR/<sessionname>/`

## Ticket 

- **Description**: Returns the output of a specific ticket.
- **Path**: [{FQDN}/status]({FQDN}/status)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.
  - `session`: The session name to fetch the ticket from.
  - `ticket`: The specific ticket number to retrieve.

**Example**: 
```bash
curl -G "{FQDN}/status?session=mystifying_gould&ticket=1&hash=g5U8N2kL0f4R7zV3m1T6bJ9aQ8W0xC2e"
```

## History

- **Description**: Returns all command history for a session.
- **Path**: [{FQDN}/history]({FQDN}/history)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.
  - `session`: The session name to fetch the ticket from.

**Example**:
```bash
curl -G "{FQDN}/history?session=mystifying_gould&hash=g5U8N2kL0f4R7zV3m1T6bJ9aQ8W0xC2e"
```

## Context

- **Description**: Returns the inital context for the LLM.
- **Path**: [{FQDN}/context]({FQDN}/context)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.

**Example**:
```bash
curl -G "{FQDN}/context?hash=g5U8N2kL0f4R7zV3m1T6bJ9aQ8W0xC2e"
```

## Index 

- **Description**: : Displays the README.md file in the root directory as HTML
- **Path**: [{FQDN}/]({FQDN}/)
- **Method**: `GET`

**Example**
```bash
curl -G "{FQDN}/"
```

## Session Directory Structure

After running commands, you’ll see a structure like:
```
.
├── sessions
│   └── mystifying_gould
│       ├── 1.ticket
│       ├── 2.ticket
│       └── ...
├── main.go
├── README.md
└── .env
```
- **sessions**: The default `SESSIONS_DIR` unless overridden in `.env`.
- **session-name**: Each session is a subdirectory.
- **1.ticket, 2.ticket**: Text files containing the command outputs (or errors).

## LLM Example procedure

- As the LLM where the user has provided you with an objective and a unique `hash` to use for authentication.
- You go to the index page at `{FQDN}/context` to gather your context.
- Given the objective you issue a command to the server using the `{FQDN}/shell` endpoint providing the `hash` and `cmd` parameters.
- Returned is a json object with a `ticket` and `session`
- YOU MUST REMEMBER these values to continue the process.
- Use the `session` value in all future requests to maintain context.
- You check the status of the `ticket` using the `{FQDN}/status` endpoint by supplying the `ticket`, `session`, and `hash` parameters.
- You continue to check the status of the ticket until the command is complete.
- Once you have the result you use the `session` and `hash` parameters to issue a new `cmd` to the `{FQDN}/shell` endpoint.
- You continue to loop through the process until the objective is complete.

## Security 

- Ensure that `HASH` is random and never checked into source control.
- Secure your server and be responsible.
- Happy hacking!

## License

This project is released by [Jared Folkins](https://x.com/jf0lkins) under the [MIT License](https://opensource.org/licenses/MIT). See the [GITHUB](https://github.com/jaredfolkins/llm-asynchronous-shell-scheduler) for more details.