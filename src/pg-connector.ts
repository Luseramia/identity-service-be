import { SQL } from "bun";
import { postgresConfig } from "./runtime-config";

const pool = new SQL({
  ...postgresConfig(),

  // Connection pool settings
  max: 20, // Maximum connections in pool
  idleTimeout: 30, // Close idle connections after 30s
  maxLifetime: 0, // Connection lifetime in seconds (0 = forever)
  connectionTimeout: 30, // Timeout when establishing new connections

  // SSL/TLS options
//   tls: true,
  // tls: {
  //   rejectUnauthorized: true,
  //   requestCert: true,
  //   ca: "path/to/ca.pem",
  //   key: "path/to/key.pem",
  //   cert: "path/to/cert.pem",
  //   checkServerIdentity(hostname, cert) {
  //     ...
  //   },
  // },

  // Callbacks
  // onconnect: client => {
  //   console.log("Connected to PostgreSQL");
  // },
  // onclose: client => {
  //   console.log("PostgreSQL connection closed");
  // },
});


// console.log(await pool`SELECT*FROM users`);
 
export default pool
