// Types mirroring internal/launcher: the launcher passes Go structs to the
// browser unchanged, so these must stay in sync with their JSON tags.

export interface Issue {
  field: string;
  severity: "error" | "warning";
  message: string;
}

/** The server's startup parameters, matching `underflow serve`. */
export interface Spec {
  listen: string;
  local: boolean;
  dbDriver: "sqlite" | "postgres" | string;
  dbDsn: string;
  pepper: "file" | "generated" | string;
  overwrite: boolean;
  pepperFilePath: string;
  registration: "open" | "closed" | "invite" | string;
  inviteCode: string;
  argon2Profile: "interactive" | "moderate" | "paranoid" | string;
  sessionTtl: string;
  logLevel: string;
  trustedProxies: string;
  tlsCert: string;
  tlsKey: string;
  insecure: boolean;
  binary: string;
}

/** The resolved runtime configuration derived from a Spec. */
export interface Result {
  env: Record<string, string>;
  args: string[];
  url: string;
  probeUrl: string;
  command: string;
  pepperPath: string;
  pepperExists: boolean;
  ready: boolean;
  issues: Issue[] | null;
}

export interface PepperStatus {
  path: string;
  exists: boolean;
  size: number;
  fingerprint: string;
  readError: string;
}

export type Status =
  | "stopped"
  | "starting"
  | "running"
  | "stopping"
  | "exited"
  | "failed";

export interface State {
  status: Status;
  pid: number;
  startedAt: string;
  exitedAt: string;
  exitCode: number;
  error: string;
  url: string;
  probeUrl: string;
  config: string;
  args: string[] | null;
  pepperPath: string;
  logLines: number;
  started: boolean;
}

export interface Bootstrap {
  spec: Spec;
  result: Result;
  state: State;
  pepper: PepperStatus;
  workDir: string;
  stateDir: string;
  binary: string;
  choices: {
    profiles: string[];
    registrations: string[];
    drivers: string[];
    logLevels: string[];
    pepperSources: string[];
  };
}

export interface SpecResponse {
  spec: Spec;
  result: Result;
  saved: boolean;
  pepper: PepperStatus;
}

export interface StateResponse {
  state: State;
  result: Result;
  pepper: PepperStatus;
}

export interface LogLine {
  seq: number;
  text: string;
}
