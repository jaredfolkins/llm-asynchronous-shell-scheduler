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
HASH=REPLACE_ME_WITH_THE_HASH
FQDN=http://localhost:8083
PORT=8083
SESSIONS_DIR=sessions
```


## Parameter Map

| GET Parameter | Description                                        | /shell   | /history | /context   | /       |
|---------------|----------------------------------------------------|----------|----------|------------|---------|
| `hash`        | >= 32-character password for authentication.       | required | required | required   | n/a     |
| `cmd`         | Url encoded cli command to execute                 | required | n/a      | n/a        | n/a     |
| `session`     | Session in order that the llm can maintain context | required | required | n/a        | n/a     |

## Shell

- **Description**: Execute a shell command.
- **Path**: [{FQDN}/shell]({FQDN}/shell)
- **Method**: `GET`
- **Query Parameters**:
    - `hash`: Must match the `HASH` from your `.env`.
    - `cmd`: is a url encoded shell command to execute, e.g., `ls -lah`.
    - `session` A directory/session name 

**Example**: 
```bash
curl -G "{FQDN}/shell" --data-urlencode "cmd=ls -lah" --data-urlencode "hash=REPLACE_ME_WITH_THE_HASH"
```

A **successful** response returns:
```
{
  "ticket":REMEMBER_THIS_ID,
  "session":"USE_SESSION_TO_MAINTAIN_CONTEXT",
  "cmd_intput": "THE_COMMAND_YOU_SENT_AS_EXECUTED",
  "cmd_output": "THE_RESULT_OF_THE_COMMAND",
}
```

The **output** of the command is:

- saved in a new named `<int>.ticket` 
- the file is inside `SESSIONS_DIR/<sessionname>/`

## History

- **Description**: Returns all command history for a session.
- **Path**: [{FQDN}/history]({FQDN}/history)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.
  - `session`: The session name to fetch the ticket from.

**Example**:
```bash
curl -G "{FQDN}/history?session=REPLACE_WITH_YOUR_SESSION&hash=REPLACE_ME_WITH_THE_HASH"
```

## Context

- **Description**: Returns the inital context for the LLM.
- **Path**: [{FQDN}/context]({FQDN}/context)
- **Method**: `GET`
- **Query Parameters**:
  - `hash`: Must match the `HASH`.

**Example**:
```bash
curl -G "{FQDN}/context?hash=REPLACE_ME_WITH_THE_HASH"
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
│   └── YOUR_SESSION_NAME
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
- Remember what you've tried by using the `{FQDN}/history` endpoint by supplying the `session` and `hash` parameters.
- You go to the context page at `{FQDN}/context` to gather your context.
- Given the objective you issue a command to the server using the `{FQDN}/shell` endpoint providing the `hash` and `cmd` and `session` parameters.
- Returned is a json object with a `ticket` and `session`
- YOU MUST REMEMBER these values to continue the process.
- Use the `session` value in all future requests to maintain context.
- You check the status of your commands using the `{FQDN}/history` endpoint by supplying the `session` and `hash` parameters.
- Once you have the result you use the `session` and `hash` parameters to issue a new `cmd` to the `{FQDN}/shell` endpoint.
- You continue to loop through the process until the objective is complete.
- If at any point you forget what you've done try using the `{FQDN}/history` endpoint again by supplying the `session` and `hash` parameters.

## Security 

- Ensure that `HASH` is random and never checked into source control.
- Secure your server and be responsible.
- Happy hacking!

## License

This project is released by [Jared Folkins](https://x.com/jf0lkins) under the [MIT License](https://opensource.org/licenses/MIT). See the [GITHUB](https://github.com/jaredfolkins/llm-asynchronous-shell-scheduler) for more details.