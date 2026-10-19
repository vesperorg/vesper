# Running a Vesper seed node

A seed node is an always-on node with a fixed internet address. New nodes are told that
address (the `peers` list in `config.json`) so they can find the network; after that they
find each other. It also mines on one core, so the test network keeps making blocks when
nobody else is mining.

**Never run a public seed node from your home internet connection.** Its address is public and
tied to Vesper. Use a small rented server, paid for in a way that does not carry your name.

## What to rent

- Any provider of small Linux servers ("VPS"). Choose one that accepts payment without an
  identity check (some take cryptocurrency) and lets you sign up with a fresh email address.
- Ubuntu 24.04, 2 CPU cores, 2 GB of memory, 20 GB of disk. About 5 dollars a month.
- Open port: 8880 (the setup script opens it in the server's own firewall; some providers
  also have a firewall in their web panel: allow TCP 8880 there too).

## Setting it up

The repository must be public first (`publish_github.bat`), because the server downloads the
code from it. Then, on the server:

```bash
curl -fsSLO https://raw.githubusercontent.com/vesperorg/vesper/master/deploy/setup-seed.sh
sudo bash setup-seed.sh https://github.com/vesperorg/vesper
```

The script installs Python, copies Vesper to `/opt/vesper`, runs the full self-test (nothing
starts unless every check passes), makes a wallet for the node's mining rewards (test coins, no
value; its recovery code is printed once), installs the node as a service that starts at every
boot and restarts itself, and opens only SSH and 8880. It ends by printing the seed's address,
`http://<server address>:8880`.

Then the seed's address goes into the `peers` list of `config.json` in the repository, so
every node that starts finds it.

## Looking after it

| What | Command (on the server) |
|---|---|
| Is it running, what is it doing | `journalctl -u vesper-node -f` |
| Its view of the network | `curl -s http://127.0.0.1:8880/api/info` |
| Update to the newest code | `sudo bash /opt/vesper/deploy/setup-seed.sh https://github.com/vesperorg/vesper` |
| Stop, start | `sudo systemctl stop vesper-node`, `sudo systemctl start vesper-node` |

The service runs as its own user with no rights outside its data folder (`/var/lib/vesper`),
and is limited to 2 GB of memory. The node's own limits apply as everywhere: requests per
address, a ban for rule-breakers, 64 connections at once and 8 per address, 20 s for a silent
connection, blocks at most 4 MB.

## Not yet tried

The reference platform is Windows. The self-test also runs on Linux in the repository's
GitHub checks, and the setup script refuses to start a node that fails it. A first run of
this script on a real server is part of the launch.
