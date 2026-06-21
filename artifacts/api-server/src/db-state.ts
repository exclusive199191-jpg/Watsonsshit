let dbTableReady = false;

export function isDbTableReady(): boolean {
  return dbTableReady;
}

export function setDbTableReady(ready: boolean): void {
  dbTableReady = ready;
}
