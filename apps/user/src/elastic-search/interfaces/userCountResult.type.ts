export interface UserCountResult {
  count: number;
  _shards: {
    total: number;
    successfull: number;
    skipped: number;
    failed: number;
  };
}
